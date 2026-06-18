"""
Engine registry — singleton that owns ML and DL engine instances.

Responsibilities
----------------
* Lazy directory scan: on first access, check which engines have their
  files on disk (``MLEngine.is_available()`` / DL when added).
* Cache loaded engine instances so we don't reload models per request.
* Read the active engine from the ``EngineConfig`` DB singleton through
  a 5-second time-based cache to keep hot paths (the live sniffer's
  per-packet predict) cheap — at 10k packets/s a per-packet DB hit
  would saturate Postgres.
* Allow admins to switch the active engine; switching invalidates the
  cache immediately so the next prediction sees the new value.

The DL engine is loaded by name only — its module
(``dl_engine.py``) lands in Phase 2b. Until then, ``"dl"`` simply
fails the availability check and the registry falls back to ``"ml"``.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.conf import settings

from .base_engine import BaseEngine
from .ml_engine import MLEngine

logger = logging.getLogger("pids.detection.registry")

# Master switch for the GNN engine. Disabled until a properly trained GNN
# model is available. When True, the registry registers the GNN engine and
# the frontend/API expose it again. Flip to True to re-enable.
GNN_ENABLED = False


# Time-based cache for the DB-stored active engine name. Tunable.
_ACTIVE_ENGINE_CACHE_TTL_SECONDS: float = 5.0


class EngineRegistry:
    """
    Singleton registry of detection engines. Use :func:`get_registry`
    rather than constructing this directly.
    """

    def __init__(self) -> None:
        # All engines we KNOW ABOUT, keyed by short name. Available or not.
        self._engines: Dict[str, BaseEngine] = {}
        # Active-engine cache (DB-backed, 5-second TTL).
        self._active_cache_value: Optional[str] = None
        self._active_cache_expires: float = 0.0
        # Guards initialisation and cache reads in the multi-threaded
        # Django/ASGI context.
        self._lock = threading.RLock()
        self._initialised = False

    # ------------------------------------------------------------------
    # Initialisation (lazy)
    # ------------------------------------------------------------------
    def _ensure_initialised(self) -> None:
        if self._initialised:
            return
        with self._lock:
            if self._initialised:
                return
            self._engines["ml"] = MLEngine(Path(settings.ML_MODELS_DIR))

            # DL engine is added in Phase 2b. Try to import it; if the
            # module isn't there yet just skip — the registry stays
            # functional with ML only.
            try:
                from .dl_engine import DLEngine  # type: ignore  # noqa: WPS433
                self._engines["dl"] = DLEngine(Path(settings.DL_MODELS_DIR))
            except ImportError:
                logger.info(
                    "DL engine module not present yet; registry running with ML only"
                )

            # GNN engine — DISABLED until a proper model is trained.
            # Flip GNN_ENABLED back to True (and re-enable the frontend
            # references) once the trained GNN artifacts are dropped into
            # ``dl_models/gnn/``. Code is intentionally left in place.
            if GNN_ENABLED:
                try:
                    from .gnn_engine import GNNEngine  # type: ignore  # noqa: WPS433
                    self._engines["gnn"] = GNNEngine(
                        Path(settings.DL_MODELS_DIR) / "gnn"
                    )
                except ImportError:
                    logger.info("GNN engine module not present; skipping")

            self._initialised = True
            logger.info(
                "EngineRegistry initialised with engines: %s",
                list(self._engines.keys()),
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_available_engines(self) -> List[str]:
        """
        Return the list of engine names whose model files are on disk.

        Cheap — only checks file existence, never loads models.
        """
        self._ensure_initialised()
        return [name for name, eng in self._engines.items() if eng.is_available()]

    def get_engine(self, name: str) -> Optional[BaseEngine]:
        """
        Return the engine instance for ``name``, or ``None`` if unknown.

        Returned even when the engine isn't available on disk — callers
        that want a usable engine should check ``is_available()`` first
        or use :meth:`get_active_engine`.
        """
        self._ensure_initialised()
        return self._engines.get(name)

    def get_active_engine(self) -> BaseEngine:
        """
        Return the currently active engine instance, falling back to
        whatever is available if the configured choice is missing.

        Resolution order:

        1. Whatever ``EngineConfig.active_engine`` says (5-second cache).
        2. If that engine is unavailable, the first available engine.
        3. As a last resort, the ML engine instance — even if its files
           are missing, so callers always get a non-None object whose
           ``ensure_loaded()`` will return False and the public
           ``predict()`` will degrade to ``("Normal", 0.5, "Normal")``.
        """
        self._ensure_initialised()
        name = self._read_active_cached()
        engine = self._engines.get(name)
        if engine is not None and engine.is_available():
            return engine

        # Fallback: first available engine.
        for fallback_name, fallback in self._engines.items():
            if fallback.is_available():
                if name and fallback_name != name:
                    logger.warning(
                        "Active engine %r unavailable; falling back to %r",
                        name, fallback_name,
                    )
                return fallback

        # Nothing on disk — return the ML stub so callers don't crash.
        logger.warning("No engines available on disk; returning ML stub")
        return self._engines["ml"]

    def set_active_engine(self, name: str, user: Any = None) -> BaseEngine:
        """
        Persist the active-engine choice to the DB and invalidate the
        local cache so the next read picks it up immediately.

        Parameters
        ----------
        name
            Either ``"ml"`` or ``"dl"``. Validated.
        user
            ``CustomUser`` instance recording who made the change
            (optional — system-initiated changes pass ``None``).

        Returns
        -------
        BaseEngine
            The newly active engine instance.

        Raises
        ------
        ValueError
            If ``name`` isn't a known engine.
        """
        self._ensure_initialised()
        if name not in self._engines:
            raise ValueError(
                f"Unknown engine {name!r}; known: {list(self._engines)}"
            )

        # Local import to avoid Django app-loading order issues at module
        # import time.
        from api.models import EngineConfig
        cfg = EngineConfig.get_active()
        cfg.active_engine = name
        if user is not None:
            cfg.updated_by = user
        cfg.save()

        with self._lock:
            self._active_cache_value = name
            self._active_cache_expires = time.time() + _ACTIVE_ENGINE_CACHE_TTL_SECONDS

        logger.info(
            "Active engine set to %r by %s",
            name,
            getattr(user, 'username', None) or 'system',
        )
        return self._engines[name]

    def reload_engines(self) -> None:
        """
        Drop loaded model state so the next ``predict()`` reloads from
        disk. Call after retraining writes new model files.
        """
        self._ensure_initialised()
        from . import _shared
        with self._lock:
            for engine in self._engines.values():
                engine._loaded = False  # noqa: SLF001 — registry-level reset
                engine._load_error = None  # noqa: SLF001
            _shared.reset_caches()
        logger.info("Engine registry: model caches reset")

    # ------------------------------------------------------------------
    # Internal: cached active-engine reader (5s TTL)
    # ------------------------------------------------------------------
    def _read_active_cached(self) -> str:
        """
        Return the active engine name from the cache, refreshing from
        the DB once per ``_ACTIVE_ENGINE_CACHE_TTL_SECONDS``. Per the
        spec — at 10k packets/s a per-packet DB hit would be untenable.
        """
        now = time.time()
        if self._active_cache_value is not None and now < self._active_cache_expires:
            return self._active_cache_value

        with self._lock:
            # Double-check inside the lock.
            now = time.time()
            if self._active_cache_value is not None and now < self._active_cache_expires:
                return self._active_cache_value
            try:
                from api.models import EngineConfig
                self._active_cache_value = EngineConfig.get_active().active_engine
            except Exception as exc:  # noqa: BLE001
                # DB unreachable / migrations not run yet — fall back to
                # the configured default rather than crashing.
                logger.warning(
                    "EngineConfig read failed (%s); using DETECTION_ENGINE_DEFAULT",
                    exc,
                )
                self._active_cache_value = getattr(
                    settings, "DETECTION_ENGINE_DEFAULT", "dl"
                )
            self._active_cache_expires = now + _ACTIVE_ENGINE_CACHE_TTL_SECONDS
            return self._active_cache_value


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_REGISTRY: Optional[EngineRegistry] = None
_REGISTRY_LOCK = threading.Lock()


def get_registry() -> EngineRegistry:
    """
    Return the process-wide :class:`EngineRegistry` singleton, creating
    it on first call. Thread-safe.
    """
    global _REGISTRY
    if _REGISTRY is None:
        with _REGISTRY_LOCK:
            if _REGISTRY is None:
                _REGISTRY = EngineRegistry()
    return _REGISTRY


def get_active_engine_cached() -> BaseEngine:
    """
    Convenience wrapper used by the live sniffer hot path.

    Equivalent to ``get_registry().get_active_engine()`` — the 5-second
    cache lives inside the registry, so this call is cheap.
    """
    return get_registry().get_active_engine()

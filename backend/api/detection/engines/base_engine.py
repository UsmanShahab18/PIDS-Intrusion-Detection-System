"""
Abstract base class for PIDS detection engines (ML / DL).

Design notes
------------
* Models are loaded lazily on the first call to :meth:`predict` or
  :meth:`predict_batch` so that ``manage.py`` startup remains fast and a
  missing-model error never crashes Django.
* :meth:`predict` returns a structured dict (the new contract). The legacy
  3-tuple ``(label, confidence, status)`` consumed by
  ``pids_core/traffic_capture.py`` is exposed via :meth:`predict_legacy`
  so the existing call site can switch over without changing its unpacking.
* :meth:`is_available` only checks that the model files exist on disk; it
  does not load them. Use it from the registry's directory scan.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("pids.detection")


# Canonical statuses returned by every engine. Matches the strings the
# existing pipeline already writes to TrafficLog.status, so frontend logic
# (which keys on these strings) remains untouched.
STATUS_NORMAL = "Normal"
STATUS_SUSPICIOUS = "Suspicious"
STATUS_ATTACK = "Attack"
STATUS_UNKNOWN = "Unknown"


class BaseEngine(ABC):
    """
    Abstract base class for a two-stage detection engine.

    Subclasses must implement :meth:`is_available`, :meth:`load`, and
    :meth:`_predict_one`. The base class provides the public
    :meth:`predict` / :meth:`predict_legacy` / :meth:`predict_batch`
    surface plus the lazy-load wiring.

    Attributes
    ----------
    name : str
        Short identifier (``"ml"``, ``"dl"``). Used in API responses,
        logs, and persistence.
    models_dir : pathlib.Path
        Directory the engine reads its model files from.
    feature_list : list[str] | None
        Ordered list of 31 feature names this engine expects, populated
        on :meth:`load`. Both ML and DL engines load this from
        ``dl_models/selected_features.pkl`` so they share the same input
        schema.
    """

    #: Subclasses override.
    name: str = "base"

    def __init__(self, models_dir: Path) -> None:
        """
        Parameters
        ----------
        models_dir
            Directory containing the engine's model artifacts.
        """
        self.models_dir: Path = Path(models_dir)
        self.feature_list: Optional[List[str]] = None
        self._loaded: bool = False
        self._load_error: Optional[str] = None

    # ------------------------------------------------------------------
    # Abstract surface
    # ------------------------------------------------------------------
    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if all required model files exist on disk.

        Must NOT load the models. Cheap directory check only.
        """

    @abstractmethod
    def load(self) -> bool:
        """
        Load every model and artifact this engine needs.

        Implementations must catch their own exceptions, log them, and
        return ``False`` on failure rather than raising — a missing or
        corrupt model file should never crash Django startup.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure. Failure also sets
            :attr:`_load_error` for diagnostic surfacing.
        """

    @abstractmethod
    def _predict_one(
        self, features: Dict[str, Any], protocol: str
    ) -> Tuple[str, float, str]:
        """
        Engine-specific prediction for a single feature dictionary.

        Returns
        -------
        tuple
            ``(attack_type_or_label, confidence, status)`` where ``status``
            is one of ``"Normal"``, ``"Suspicious"``, ``"Attack"``,
            ``"Unknown"``.
        """

    # ------------------------------------------------------------------
    # Public surface — implemented here, do not override
    # ------------------------------------------------------------------
    def ensure_loaded(self) -> bool:
        """
        Lazy-load the engine on first use.

        Returns
        -------
        bool
            ``True`` once the engine is loaded, ``False`` if loading
            failed (call :attr:`_load_error` for the reason).
        """
        if self._loaded:
            return True
        if self._load_error is not None:
            # Already tried and failed. Don't keep retrying on hot path.
            return False
        try:
            ok = self.load()
        except Exception as exc:  # noqa: BLE001 - we deliberately swallow
            self._load_error = f"{type(exc).__name__}: {exc}"
            logger.exception(
                "Engine %s failed to load from %s", self.name, self.models_dir
            )
            return False
        self._loaded = bool(ok)
        if not self._loaded and self._load_error is None:
            self._load_error = "load() returned False without raising"
        return self._loaded

    def predict(
        self, features: Dict[str, Any], protocol: str = "TCP"
    ) -> Dict[str, Any]:
        """
        Run inference on a single feature dictionary.

        Returns
        -------
        dict
            Keys:
              * ``is_attack`` (bool)
              * ``attack_type`` (str) — e.g. ``"Normal"`` or ``"DDOS attack-HOIC"``
              * ``confidence`` (float, 0..1)
              * ``status`` (str) — ``"Normal"`` / ``"Suspicious"`` / ``"Attack"`` / ``"Unknown"``
              * ``engine`` (str) — engine identifier
        """
        label, confidence, status = self.predict_legacy(features, protocol)
        return {
            "is_attack": status == STATUS_ATTACK,
            "attack_type": label,
            "confidence": float(confidence),
            "status": status,
            "engine": self.name,
        }

    def predict_legacy(
        self, features: Dict[str, Any], protocol: str = "TCP"
    ) -> Tuple[str, float, str]:
        """
        Return the legacy 3-tuple ``(label, confidence, status)``.

        Used by ``pids_core/traffic_capture.py`` whose existing unpacking
        is ``pred, conf, status = ml.predict(features, proto)``. New
        callers should prefer :meth:`predict` (dict) instead.
        """
        if not self.ensure_loaded():
            return STATUS_NORMAL, 0.5, STATUS_NORMAL
        return self._predict_one(features, protocol)

    def predict_batch(
        self, features_list: List[Dict[str, Any]], protocol: str = "TCP"
    ) -> List[Dict[str, Any]]:
        """
        Run inference on a list of feature dictionaries.

        Default implementation calls :meth:`predict` per item. Subclasses
        with vectorised inference paths (notably the DL engine) may
        override for throughput.
        """
        return [self.predict(f, protocol) for f in features_list]

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        """
        Return a JSON-serialisable description of this engine.

        Used by ``GET /api/engine/info``. Subclasses may extend to add
        engine-specific fields (model file paths, n_classes, etc.).
        """
        return {
            "name": self.name,
            "available": self.is_available(),
            "loaded": self._loaded,
            "load_error": self._load_error,
            "models_dir": str(self.models_dir),
            "feature_count": len(self.feature_list) if self.feature_list else None,
        }

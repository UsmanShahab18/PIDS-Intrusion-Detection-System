"""
Engine selector API.

Three endpoints, mounted under ``/api/engine/``:

* ``GET  status`` — list available engines and identify the active one.
* ``POST select`` — admin-only; switch the active engine (persisted to
  ``EngineConfig`` singleton).
* ``GET  info``   — diagnostic details (file paths, class counts,
  load errors).

All three views catch per-engine exceptions so a single broken engine
cannot 500 the whole endpoint — instead the offending engine's entry
carries an ``error`` field and the others render normally.

Frontend ``EngineSelector.jsx`` consumes these.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from rest_framework.decorators import api_view
from rest_framework.response import Response

from api.auth_utils import admin_required, jwt_required
from api.detection.engines.engine_registry import get_registry

logger = logging.getLogger("pids.api.engine")


def _safe_engine_status(eng) -> Dict[str, Any]:
    """Per-engine block for ``/status`` — never raises."""
    try:
        avail = bool(eng.is_available())
    except Exception as exc:  # noqa: BLE001
        logger.exception("is_available() failed for engine %r", getattr(eng, "name", "?"))
        return {"available": False, "loaded": False,
                "load_error": f"is_available() raised: {exc}"}
    return {
        "available": avail,
        "loaded": getattr(eng, "_loaded", False),
        "load_error": getattr(eng, "_load_error", None),
    }


@api_view(["GET"])
@jwt_required
def engine_status(request) -> Response:
    """
    GET /api/engine/status — degrades gracefully if anything throws.
    """
    try:
        reg = get_registry()
        # Force lazy init so reg._engines is populated. get_available_engines()
        # internally calls _ensure_initialised() — also gives us the live
        # availability list as a free side-product.
        reg.get_available_engines()
    except Exception as exc:
        logger.exception("get_registry() failed")
        return Response({
            "available": [], "active": None, "engines": {},
            "error": f"Registry init failed: {exc}",
        })

    engines: Dict[str, Dict[str, Any]] = {}
    available = []
    for name, eng in reg._engines.items():  # noqa: SLF001
        st = _safe_engine_status(eng)
        engines[name] = st
        if st["available"]:
            available.append(name)

    try:
        active = reg.get_active_engine().name
    except Exception as exc:  # noqa: BLE001
        logger.exception("get_active_engine() failed")
        active = None

    return Response({
        "available": available,
        "active": active,
        "engines": engines,
    })


@api_view(["POST"])
@admin_required
def engine_select(request) -> Response:
    """
    POST /api/engine/select

    Body
    ----
    ``{"engine": "ml"}`` or ``{"engine": "dl"}``.

    Persists the choice to ``EngineConfig``, writes an ``AuditLog``
    entry, and returns the new state. Admin role required.

    NOTE: ``"gnn"`` is intentionally disabled until a trained GNN model
    is available (see GNN_ENABLED in engine_registry). Add it back to
    ``valid_engines`` to re-enable.
    """
    valid_engines = ("ml", "dl")
    name = (request.data or {}).get("engine")
    if name not in valid_engines:
        return Response(
            {"error": f"Field 'engine' must be one of {valid_engines}"},
            status=400,
        )
    reg = get_registry()
    if name not in reg._engines:  # noqa: SLF001
        return Response({"error": f"Engine {name!r} is not registered"}, status=404)
    if not reg.get_engine(name).is_available():
        return Response(
            {"error": f"Engine {name!r} has no model files on disk"},
            status=409,
        )

    # Capture the previous engine for the audit trail before switching.
    try:
        previous = reg.get_active_engine().name
    except Exception:  # noqa: BLE001
        previous = None

    user = getattr(request, "user", None)
    new_engine = reg.set_active_engine(name, user=user)

    # Audit log: a detection-engine switch is an admin action worth
    # recording — it changes how all subsequent live traffic is
    # classified.
    try:
        from api.models import AuditLog
        AuditLog.objects.create(
            user=user if getattr(user, "is_authenticated", False) else None,
            action="detection_engine_changed",
            affected_entity="EngineConfig",
            entity_id="1",
            details={"from": previous, "to": name},
            ip_address=request.META.get("REMOTE_ADDR"),
        )
    except Exception:  # noqa: BLE001
        logger.exception("Failed to write audit log for engine switch")

    return Response({
        "active": new_engine.name,
        "info": new_engine.info(),
    })


@api_view(["GET"])
@jwt_required
def engine_info(request) -> Response:
    """
    GET /api/engine/info — degrades gracefully per-engine.
    """
    try:
        reg = get_registry()
        reg.get_available_engines()  # force lazy init
    except Exception as exc:
        logger.exception("get_registry() failed in engine_info")
        return Response({"error": f"Registry init failed: {exc}",
                         "engines": {}}, status=500)

    try:
        active = reg.get_active_engine().name
    except Exception:
        active = None

    payload: Dict[str, Any] = {
        "active": active,
        "feature_count_expected": 31,
        "ml_classes": 14,
        "dl_classes": 14,
        "dl_routing_enabled": _bool_setting("DL_INFIL_ROUTING_ENABLED", True),
        "dl_raw_mode": _bool_setting("DL_RAW_MODE", False),
        "engines": {},
    }
    for name, eng in reg._engines.items():  # noqa: SLF001
        try:
            payload["engines"][name] = eng.info()
        except Exception as exc:  # noqa: BLE001
            logger.exception("info() failed for engine %r", name)
            payload["engines"][name] = {"name": name, "error": str(exc)}
    return Response(payload)


def _bool_setting(name: str, default: bool) -> bool:
    """Read a boolean Django setting safely."""
    from django.conf import settings
    return bool(getattr(settings, name, default))

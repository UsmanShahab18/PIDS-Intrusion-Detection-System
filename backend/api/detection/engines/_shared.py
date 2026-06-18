"""
Shared helpers for ML / DL engines.

Centralises the loading of artifacts that **both** engines depend on:

* ``selected_features.pkl`` — ordered list of 31 feature names; the canonical
  ML and DL models were both trained on this exact column order.
* ``scaler.pkl`` — StandardScaler fit on the same training data; both engines
  must apply it before inference (the saved XGBoost / LightGBM / Keras
  models all consume scaled values).
* ``label_encoder.pkl`` — sklearn ``LabelEncoder`` whose ``classes_``
  decode old-space attack indices.

All loaders are cached at module level so loading is paid once per Python
process. Failures are surfaced via exceptions; callers (engines) translate
them into ``BaseEngine._load_error`` for graceful degradation.
"""
from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from django.conf import settings


# ---------------------------------------------------------------------------
# Module-level caches. Engines are singletons so this is effectively a
# per-process cache. Cleared on Django reload (test isolation OK).
# ---------------------------------------------------------------------------
_FEATURE_NAMES_CACHE: Optional[List[str]] = None
_SCALER_CACHE: Any = None
_LABEL_ENCODER_CACHE: Any = None


def _dl_path(filename: str) -> Path:
    """
    Resolve a filename under ``settings.DL_MODELS_DIR``.

    The shared artifacts (selected_features, scaler, label_encoder) all
    live in the DL models directory because they were produced by the DL
    training pipeline and adopted as the canonical schema for both engines.
    """
    return Path(settings.DL_MODELS_DIR) / filename


def load_feature_names() -> List[str]:
    """
    Return the ordered list of 31 feature names used by both engines.

    Cached on first call. Raises :class:`FileNotFoundError` /
    :class:`pickle.UnpicklingError` if the file is missing or corrupt.
    """
    global _FEATURE_NAMES_CACHE
    if _FEATURE_NAMES_CACHE is None:
        with open(_dl_path("selected_features.pkl"), "rb") as fh:
            names = pickle.load(fh)
        if not isinstance(names, (list, tuple)):
            raise TypeError(
                f"selected_features.pkl must contain a list, got {type(names).__name__}"
            )
        _FEATURE_NAMES_CACHE = list(names)
    return _FEATURE_NAMES_CACHE


def load_scaler() -> Any:
    """
    Return the cached StandardScaler shared by ML and DL engines.

    The scaler was fit on the same training matrix the canonical models
    were trained on, so applying it before inference is mandatory.
    """
    global _SCALER_CACHE
    if _SCALER_CACHE is None:
        with open(_dl_path("scaler.pkl"), "rb") as fh:
            _SCALER_CACHE = pickle.load(fh)
    return _SCALER_CACHE


def load_label_encoder() -> Any:
    """
    Return the cached sklearn ``LabelEncoder``. Use ``classes_[old_idx]``
    to decode an attack name from an old-space integer.
    """
    global _LABEL_ENCODER_CACHE
    if _LABEL_ENCODER_CACHE is None:
        with open(_dl_path("label_encoder.pkl"), "rb") as fh:
            _LABEL_ENCODER_CACHE = pickle.load(fh)
    return _LABEL_ENCODER_CACHE


def vectorise_features(
    features: Dict[str, Any], feature_names: List[str]
) -> np.ndarray:
    """
    Convert a sparse-ish feature dict into the dense, ordered array the
    models expect.

    Missing keys default to ``0.0``. Non-finite values (``inf`` / ``-inf``
    / ``nan``) are clamped to ``0.0`` for parity with the existing
    pipeline (`pids_core/ml_engine.py` does the same via
    ``df.replace([np.inf, -np.inf], 0).fillna(0)``).

    Parameters
    ----------
    features
        Dict produced by :class:`FeatureExtractor`.
    feature_names
        Ordered list (length 31) returned by :func:`load_feature_names`.

    Returns
    -------
    numpy.ndarray
        Float32 array of shape ``(1, len(feature_names))`` ready for the
        scaler and downstream models.
    """
    row = np.zeros((1, len(feature_names)), dtype=np.float32)
    for i, name in enumerate(feature_names):
        try:
            v = float(features.get(name, 0.0))
            if not np.isfinite(v):
                v = 0.0
            row[0, i] = v
        except (TypeError, ValueError):
            row[0, i] = 0.0
    return row


def scale_features(
    features: Dict[str, Any],
    feature_names: List[str],
    scaler: Any,
) -> np.ndarray:
    """
    One-shot helper that combines :func:`vectorise_features` and the
    scaler ``transform`` step. Returns a ``(1, 31)`` scaled float32 array.
    """
    row = vectorise_features(features, feature_names)
    return scaler.transform(row).astype(np.float32)


def reset_caches() -> None:
    """
    Clear all module-level caches. Used by the registry's
    ``reload_engines()`` so retrained artifacts are picked up without a
    process restart.
    """
    global _FEATURE_NAMES_CACHE, _SCALER_CACHE, _LABEL_ENCODER_CACHE
    _FEATURE_NAMES_CACHE = None
    _SCALER_CACHE = None
    _LABEL_ENCODER_CACHE = None

"""
ML detection engine — XGBoost (stage 1) + LightGBM (stage 2).

This is the new, registry-aware replacement for the legacy
``api.management.commands.pids_core.ml_engine.MLEngine`` whose
``load_models()`` silently failed because it tried to load ``.pkl``
files that never existed in the canonical ``ml_models/`` directory.

Pipeline (must match how the canonical models were trained):

1. Vectorise the feature dict in the order given by
   ``dl_models/selected_features.pkl`` (31 features, shared with DL).
2. Apply the StandardScaler from ``dl_models/scaler.pkl``.
3. Stage 1 — ``stage1_xgboost.json`` ``Booster.predict`` returns
   ``P(Attack)``; compare to a UDP-aware threshold.
4. Stage 2 — ``stage2_lightgbm.txt`` ``Booster.predict`` returns a
   14-class softmax over the original CIC-IDS-2018 attack labels
   (Infilteration included, unlike the DL engine).
5. Post-process via :mod:`._heuristics` to suppress known false
   positives on benign UDP traffic.

The engine has 14 attack classes (vs DL's 13 — see project notes on
intentional Infiltration exclusion in the DL pipeline).
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

from . import _heuristics as H
from ._shared import load_feature_names, load_label_encoder, load_scaler
from .base_engine import (
    STATUS_ATTACK,
    STATUS_NORMAL,
    BaseEngine,
)

logger = logging.getLogger("pids.detection.ml")


class MLEngine(BaseEngine):
    """
    Two-stage classical-ML engine: XGBoost binary + LightGBM multiclass.

    Notes
    -----
    * Loads canonical filenames (``.json`` / ``.txt``) from
      ``settings.ML_MODELS_DIR``, NOT the legacy ``.pkl`` filenames.
    * Number of stage-2 classes: **14** (full attack set including
      ``Infilteration``).
    * Expects scaled inputs — the same StandardScaler the DL engine uses.
    """

    name: str = "ml"

    # Canonical filenames inside ``settings.ML_MODELS_DIR``.
    # Two artifact formats supported: the new sklearn-pickle format
    # (.pkl, produced by the user's latest 31-feature retrain) and the
    # legacy booster-export format (.json / .txt). Loader probes .pkl
    # first because that's the current production format.
    STAGE1_FILE_PKL  = "stage1_xgboost.pkl"
    STAGE2_FILE_PKL  = "stage2_lightgbm.pkl"
    LABEL_ENC_FILE   = "label_encoder.pkl"            # new — sklearn LabelEncoder pickle
    STAGE1_FILE_JSON = "stage1_xgboost.json"          # legacy fallback
    STAGE2_FILE_TXT  = "stage2_lightgbm.txt"          # legacy fallback
    LABEL_MAP_FILE   = "stage2_label_mapping.pkl"     # legacy fallback

    def __init__(self, models_dir: Path) -> None:
        super().__init__(models_dir)
        self._stage1: Any = None  # xgb.Booster (lazy import in load())
        self._stage2: Any = None  # lgb.Booster
        self._label_mapping: Dict[str, Any] = {}
        self._label_encoder: Any = None
        self._scaler: Any = None

    # ------------------------------------------------------------------
    # File-presence check (called by the registry)
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """
        Cheap directory check.

        Engine is considered available if EITHER the new .pkl pair
        (with label_encoder.pkl) OR the legacy .json / .txt pair
        (with stage2_label_mapping.pkl) is present on disk.
        """
        new_set = all((self.models_dir / f).exists() for f in
                      (self.STAGE1_FILE_PKL, self.STAGE2_FILE_PKL, self.LABEL_ENC_FILE))
        legacy_set = all((self.models_dir / f).exists() for f in
                         (self.STAGE1_FILE_JSON, self.STAGE2_FILE_TXT, self.LABEL_MAP_FILE))
        return new_set or legacy_set

    # ------------------------------------------------------------------
    # Lazy load on first predict
    # ------------------------------------------------------------------
    def load(self) -> bool:
        """
        Load XGBoost stage 1, LightGBM stage 2, label mapping/encoder,
        scaler, and feature list.

        Probes the new ``.pkl`` artifact set first (current production
        format produced by the latest 31-feature retrain) and falls
        back to the legacy ``.json`` / ``.txt`` set if the pickle
        files are absent.
        """
        try:
            # Heavy imports only when the engine is actually used.
            import xgboost as xgb
            import lightgbm as lgb
            import joblib   # handles NumPy/sklearn cross-version pickles vanilla pickle chokes on

            stage1_pkl = self.models_dir / self.STAGE1_FILE_PKL
            stage2_pkl = self.models_dir / self.STAGE2_FILE_PKL
            enc_pkl    = self.models_dir / self.LABEL_ENC_FILE

            stage1_json = self.models_dir / self.STAGE1_FILE_JSON
            stage2_txt  = self.models_dir / self.STAGE2_FILE_TXT
            label_map   = self.models_dir / self.LABEL_MAP_FILE

            artifact_format = None
            # ----- New pickle format (joblib-loadable) -----
            if stage1_pkl.exists() and stage2_pkl.exists() and enc_pkl.exists():
                self._stage1 = joblib.load(stage1_pkl)   # XGBClassifier
                self._stage2 = joblib.load(stage2_pkl)   # LGBMClassifier
                self._label_encoder = joblib.load(enc_pkl)
                # The new label_encoder.pkl contains ATTACK-ONLY classes
                # (14 names, no 'Benign'); stage 1 is the binary head
                # that decides Normal vs Attack. Synthesise an identity
                # mapping over the encoder's class space so _decode_stage2
                # can translate stage-2 outputs back to attack names.
                classes = list(self._label_encoder.classes_)
                self._label_mapping = {
                    "old_to_new": {i: i for i in range(len(classes))},
                    "new_to_old": {i: i for i in range(len(classes))},
                    "attack_class_indices": list(range(len(classes))),
                    "attack_class_names":   classes,
                    "benign_label_idx":     None,   # binary head handles benign
                }
                artifact_format = "pkl(joblib)"

            # ----- Legacy booster format -----
            elif stage1_json.exists() and stage2_txt.exists() and label_map.exists():
                booster1 = xgb.Booster()
                booster1.load_model(str(stage1_json))
                self._stage1 = booster1
                self._stage2 = lgb.Booster(model_file=str(stage2_txt))
                with open(label_map, "rb") as fh:
                    self._label_mapping = pickle.load(fh)
                # Shared label encoder with DL engine (legacy path).
                self._label_encoder = load_label_encoder()
                artifact_format = "legacy"

            else:
                raise FileNotFoundError(
                    f"No ML artifacts found in {self.models_dir}. "
                    f"Expected either ({self.STAGE1_FILE_PKL}, {self.STAGE2_FILE_PKL}, "
                    f"{self.LABEL_ENC_FILE}) or ({self.STAGE1_FILE_JSON}, "
                    f"{self.STAGE2_FILE_TXT}, {self.LABEL_MAP_FILE})."
                )

            # Shared artifacts with DL engine.
            self.feature_list = load_feature_names()
            self._scaler = load_scaler()

            logger.info(
                "MLEngine loaded (%s): features=%d classes=%d",
                artifact_format,
                len(self.feature_list),
                len(self._label_mapping.get("attack_class_indices", [])),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("MLEngine.load() failed")
            return False

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def _vectorise(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Vectorise + scale a feature dict into the ``(1, 53)`` array the
        XGBoost / LightGBM boosters expect.
        """
        from ._shared import scale_features  # local to avoid circular at import time
        assert self.feature_list is not None  # set in load()
        return scale_features(features, self.feature_list, self._scaler)

    def _decode_stage2(self, new_idx: int) -> str:
        """
        Map a stage-2 output index (0..13) back to an attack name via
        the saved ``new_to_old`` table and the LabelEncoder.
        """
        new_to_old = self._label_mapping.get("new_to_old", {})
        old_idx = new_to_old.get(int(new_idx))
        if old_idx is None:
            return "Unknown"
        try:
            return str(self._label_encoder.classes_[int(old_idx)])
        except (IndexError, AttributeError):
            return "Unknown"

    def _predict_one(
        self, features: Dict[str, Any], protocol: str
    ) -> Tuple[str, float, str]:
        """
        Two-stage inference for one feature dict. See module docstring
        for the full pipeline.
        """
        try:
            import xgboost as xgb  # local import — Booster.predict needs DMatrix

            x_scaled = self._vectorise(features)
            dst_port = H.get_dst_port(features)

            # ----------- Stage 1: P(Attack) -----------
            # Two API shapes possible:
            #   * sklearn wrapper (XGBClassifier) — has predict_proba(X)
            #   * raw Booster (legacy .json path) — needs DMatrix + predict(dmat)
            if hasattr(self._stage1, 'predict_proba'):
                proba = self._stage1.predict_proba(x_scaled)
                anomaly_p = float(np.asarray(proba).reshape(-1)[-1])  # P(class 1)
            else:
                dmat = xgb.DMatrix(x_scaled)
                anomaly_p = float(self._stage1.predict(dmat)[0])

            threshold = H.stage1_threshold(protocol, dst_port)
            if anomaly_p <= threshold:
                # Benign — confidence is the complement.
                return "Normal", 1.0 - anomaly_p, STATUS_NORMAL

            # ----------- Stage 2: multiclass -----------
            # LGBMClassifier returns shape (1, n_classes); raw Booster
            # returns the same shape from predict(). Both safe to pass
            # the scaled (1, F) array to.
            if hasattr(self._stage2, 'predict_proba'):
                stage2_proba = self._stage2.predict_proba(x_scaled)
            else:
                stage2_proba = self._stage2.predict(x_scaled)
            probs = np.asarray(stage2_proba).reshape(-1)
            new_idx = int(np.argmax(probs))
            confidence = float(probs[new_idx])
            attack_type = self._decode_stage2(new_idx)

            # ----------- Post-process -----------
            return H.post_process_attack_label(
                attack_type=attack_type,
                confidence=confidence,
                protocol=protocol,
                dst_port=dst_port,
                anomaly_probability=anomaly_p,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("MLEngine._predict_one failed")
            return "Unknown", 0.0, STATUS_NORMAL

    # ------------------------------------------------------------------
    # Diagnostics (extends BaseEngine.info)
    # ------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        """
        Engine-specific extras for ``GET /api/engine/info``.

        Reports whichever artifact set is present on disk (.pkl or
        legacy .json/.txt) so the admin UI shows the correct file paths.
        """
        info = super().info()

        stage1_pkl = self.models_dir / self.STAGE1_FILE_PKL
        if stage1_pkl.exists():
            stage1_path = stage1_pkl
            stage2_path = self.models_dir / self.STAGE2_FILE_PKL
            label_path  = self.models_dir / self.LABEL_ENC_FILE
            fmt = "pkl"
        else:
            stage1_path = self.models_dir / self.STAGE1_FILE_JSON
            stage2_path = self.models_dir / self.STAGE2_FILE_TXT
            label_path  = self.models_dir / self.LABEL_MAP_FILE
            fmt = "legacy"

        # Pull live class count from the loaded label encoder if we
        # have one; fall back to the canonical 14 for the default
        # CIC-IDS-2018 schema.
        n_classes = 14
        if self._label_encoder is not None and hasattr(self._label_encoder, 'classes_'):
            try:
                n_classes = len(self._label_encoder.classes_)
            except Exception:
                pass

        info.update({
            "artifact_format": fmt,
            "stage1_file": str(stage1_path),
            "stage2_file": str(stage2_path),
            "label_map_file": str(label_path),
            "n_attack_classes": n_classes,
            "supports_infiltration": True,
        })
        return info

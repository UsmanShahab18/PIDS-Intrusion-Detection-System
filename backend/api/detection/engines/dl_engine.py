"""
DL detection engine — Two-Stage Deep Neural Network (Keras).

Pipeline
--------
1. Vectorise + scale a feature dict using the shared 31-feature
   schema (``selected_features.pkl``) and StandardScaler
   (``scaler.pkl``) — same preprocessing as :class:`MLEngine`.
2. **Stage 1** — ``stage1_final.keras`` produces a single sigmoid
   output ``P(Attack)``. If below the (UDP-aware) threshold the flow
   is reported as ``Normal`` and stage 2 is skipped.
3. **Stage 2** — ``stage2_final.keras`` is a 13-class softmax. The
   stage-2 head was trained on 13 attack classes; ``Infilteration``
   was deliberately excluded by the upstream training pipeline.
4. The output index is decoded via
   ``label_mapping.pkl["new_to_old"]`` → ``label_encoder.classes_``.
5. **Low-confidence routing** — when softmax max is below
   ``settings.DL_LOW_CONFIDENCE_THRESHOLD`` and
   ``settings.DL_INFIL_ROUTING_ENABLED`` is True, we hand the flow to
   the LLM behavioural engine. The LLM may return a known class name,
   ``"Infilteration"``, or ``"Unknown"``. This is the explicit
   compensation for the missing stage-2 class.
6. **Heuristics** — by default the same UDP / normal-port
   false-positive suppression rules :class:`MLEngine` uses are
   applied, so the two engines produce comparable user-visible labels.
   Set ``settings.DL_RAW_MODE = True`` to bypass them and run the
   raw classifier output (useful for fair side-by-side comparison).

Stage-2 class asymmetry vs ML
-----------------------------
DL stage 2 has **13 output neurons** (skipping label-space index 12,
``Infilteration``); ML stage 2 has **14**. The DL training pipeline
saved an explicit ``infil_label_idx: 12`` marker in
``label_mapping.pkl`` to signal the exclusion is intentional. See
project documentation for context. Verified during Phase 2b kickoff.
"""
from __future__ import annotations

import logging
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from django.conf import settings

from . import _heuristics as H
from ._shared import load_feature_names, load_label_encoder, load_scaler
from .base_engine import (
    STATUS_ATTACK,
    STATUS_NORMAL,
    STATUS_SUSPICIOUS,
    STATUS_UNKNOWN,
    BaseEngine,
)

logger = logging.getLogger("pids.detection.dl")


# Stage-1 P(Attack) cutoff before any UDP boosts. The DL stage-1 head
# is sigmoid so 0.5 is the natural decision boundary. We default to 0.5
# but inherit the legacy 0.7 ML threshold when heuristics mode is on
# (the heuristics module already bumps thresholds for UDP).
DL_STAGE1_BASE_THRESHOLD: float = 0.5


class DLEngine(BaseEngine):
    """
    Keras-based two-stage detection engine.

    Notes
    -----
    * Stage-2 output dimensionality: **13** (no Infilteration neuron).
    * Loaded lazily on first :meth:`predict` so Django startup stays fast.
    * Loads ``.keras`` files via standalone Keras 3 (``import keras``)
      because the artifacts were saved with Keras 3.13.2 — TF 2.15's
      built-in ``tf.keras`` (Keras 2.15) cannot deserialise them.
    """

    name: str = "dl"

    STAGE1_FILE = "stage1_final.keras"
    STAGE2_FILE = "stage2_final.keras"
    LABEL_MAP_FILE = "label_mapping.pkl"

    def __init__(self, models_dir: Path) -> None:
        super().__init__(models_dir)
        self._stage1: Any = None  # keras.Model
        self._stage2: Any = None  # keras.Model
        self._label_mapping: Dict[str, Any] = {}
        self._label_encoder: Any = None
        self._scaler: Any = None
        # Lazy LLM service handle — only fetched when low-confidence
        # routing actually fires.
        self._llm_service: Any = None
        self._llm_init_attempted: bool = False

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """All four required files must exist on disk."""
        required = [
            self.models_dir / self.STAGE1_FILE,
            self.models_dir / self.STAGE2_FILE,
            self.models_dir / self.LABEL_MAP_FILE,
            Path(settings.DL_MODELS_DIR) / "selected_features.pkl",
        ]
        return all(p.exists() for p in required)

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------
    def load(self) -> bool:
        """
        Load the two Keras models, label mapping, scaler, encoder, and
        feature names. All errors are caught and logged so a corrupt or
        version-mismatched artifact cannot crash Django.
        """
        try:
            # Suppress TF's verbose info-level logs before importing.
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
            # Standalone Keras 3 — required because the artifacts are
            # Keras 3 saved-model format (see module docstring).
            import keras  # noqa: F401  (kept for early failure if missing)
            from ._keras_compat import load_keras_compat

            stage1_path = self.models_dir / self.STAGE1_FILE
            stage2_path = self.models_dir / self.STAGE2_FILE
            label_map_path = self.models_dir / self.LABEL_MAP_FILE

            # compile=False — we never train through these models, so
            # there's no need to rebuild the optimiser or loss state.
            # The compat loader strips forward-only config keys (e.g.
            # `quantization_config`, `optional`) when the artifact was
            # saved by a newer Keras minor version than the runtime
            # supports. See _keras_compat.py.
            self._stage1 = load_keras_compat(stage1_path, compile=False)
            self._stage2 = load_keras_compat(stage2_path, compile=False)

            with open(label_map_path, "rb") as fh:
                self._label_mapping = pickle.load(fh)

            self.feature_list = load_feature_names()
            self._scaler = load_scaler()
            self._label_encoder = load_label_encoder()

            n_classes = self._stage2.output_shape[-1]
            logger.info(
                "DLEngine loaded: stage1=%s stage2=%s features=%d stage2_classes=%d "
                "(infil_label_idx=%s)",
                self.STAGE1_FILE,
                self.STAGE2_FILE,
                len(self.feature_list),
                n_classes,
                self._label_mapping.get("infil_label_idx"),
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("DLEngine.load() failed")
            return False

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def _vectorise(self, features: Dict[str, Any]) -> np.ndarray:
        """Vectorise + scale a feature dict to the ``(1, 53)`` model input."""
        from ._shared import scale_features
        assert self.feature_list is not None
        return scale_features(features, self.feature_list, self._scaler)

    def _decode_stage2(self, new_idx: int) -> str:
        """
        Map a stage-2 output index (0..12) back to an attack name via
        ``new_to_old`` and ``label_encoder.classes_``.

        Note: index 12 in this NEW space decodes to ``SSH-Bruteforce``,
        NOT ``Infilteration`` — the latter is unreachable via stage 2
        in this engine by design.
        """
        new_to_old = self._label_mapping.get("new_to_old", {})
        old_idx = new_to_old.get(int(new_idx))
        if old_idx is None:
            return "Unknown"
        try:
            return str(self._label_encoder.classes_[int(old_idx)])
        except (IndexError, AttributeError):
            return "Unknown"

    def _get_llm_service(self) -> Any:
        """
        Lazy-load the LLM behavioural service. We don't import at
        module-import time because ``llm_service`` pulls in heavy deps
        and pings Ollama on construction.
        """
        if self._llm_service is not None or self._llm_init_attempted:
            return self._llm_service
        self._llm_init_attempted = True
        try:
            from api.management.commands.pids_core.llm_service import get_llm_service
            self._llm_service = get_llm_service()
        except Exception as exc:  # noqa: BLE001
            logger.warning("DL engine could not load LLM service: %s", exc)
            self._llm_service = None
        return self._llm_service

    def _route_to_llm(
        self,
        features: Dict[str, Any],
        protocol: str,
        dst_port: int,
        ml_prediction: str,
        ml_confidence: float,
    ) -> Optional[Tuple[str, float, str]]:
        """
        Hand a low-confidence DL prediction to the LLM behavioural
        engine for deeper analysis.

        Returns ``None`` if the LLM is unavailable or returns nothing
        actionable (caller falls back to the heuristic-post-processed
        DL prediction). Otherwise returns a 3-tuple ready to surface.
        """
        llm = self._get_llm_service()
        if not llm or not getattr(llm, "is_available", False):
            return None

        traffic_data: Dict[str, Any] = {
            "src_ip": "",
            "dst_ip": "",
            "protocol": protocol,
            "dst_port": dst_port,
            "ml_prediction": ml_prediction,
            "ml_confidence": ml_confidence,
            "engine": "dl",
            "skip_cache": False,
        }
        try:
            result = llm.analyze_zero_day(traffic_data, features)
        except Exception:  # noqa: BLE001
            logger.exception("DL -> LLM routing failed")
            return None
        if not isinstance(result, dict) or not result.get("success"):
            return None

        attack_category = (
            result.get("attack_category") or result.get("label") or "Unknown"
        )
        llm_conf = float(result.get("confidence") or ml_confidence or 0.0)

        # LLM verdict — three branches:
        #   * is_zero_day with high conf → upgrade to Attack
        #   * benign with high conf      → override to Normal
        #   * everything else            → keep as Suspicious
        if result.get("is_zero_day") and llm_conf >= 0.7:
            return f"LLM-Detected: {attack_category}", llm_conf, STATUS_ATTACK
        if not result.get("is_suspicious") and llm_conf >= 0.8:
            return "Normal", llm_conf, STATUS_NORMAL
        # Honor explicit Infilteration verdict from LLM (the asymmetry
        # compensation that motivated this whole routing path).
        if attack_category and "infil" in attack_category.lower():
            return "Infilteration", llm_conf, STATUS_ATTACK
        return attack_category, llm_conf, STATUS_SUSPICIOUS

    def _predict_one(
        self, features: Dict[str, Any], protocol: str
    ) -> Tuple[str, float, str]:
        """Two-stage Keras inference; see module docstring."""
        try:
            x_scaled = self._vectorise(features)
            dst_port = H.get_dst_port(features)

            # ----------- Stage 1: P(Attack) -----------
            stage1_out = self._stage1.predict(x_scaled, verbose=0)
            anomaly_p = float(np.asarray(stage1_out).ravel()[0])

            raw_mode = bool(getattr(settings, "DL_RAW_MODE", False))
            if raw_mode:
                threshold = DL_STAGE1_BASE_THRESHOLD
            else:
                threshold = H.stage1_threshold(
                    protocol, dst_port, base=DL_STAGE1_BASE_THRESHOLD
                )

            if anomaly_p <= threshold:
                return "Normal", 1.0 - anomaly_p, STATUS_NORMAL

            # ----------- Stage 2: 13-class softmax -----------
            stage2_out = self._stage2.predict(x_scaled, verbose=0)
            probs = np.asarray(stage2_out).reshape(-1)
            new_idx = int(np.argmax(probs))
            confidence = float(probs[new_idx])
            attack_type = self._decode_stage2(new_idx)

            # ----------- Low-confidence routing -----------
            low_conf_threshold = float(
                getattr(settings, "DL_LOW_CONFIDENCE_THRESHOLD", 0.7)
            )
            routing_enabled = bool(
                getattr(settings, "DL_INFIL_ROUTING_ENABLED", True)
            )
            if routing_enabled and confidence < low_conf_threshold and not raw_mode:
                routed = self._route_to_llm(
                    features=features,
                    protocol=protocol,
                    dst_port=dst_port,
                    ml_prediction=attack_type,
                    ml_confidence=confidence,
                )
                if routed is not None:
                    return routed
                # LLM unavailable/unhelpful — fall through to heuristics.

            # ----------- Heuristic post-processing -----------
            if raw_mode:
                # Spec: DL_RAW_MODE returns the raw classifier label.
                # We label it Attack since stage 1 fired.
                return attack_type, confidence, STATUS_ATTACK

            return H.post_process_attack_label(
                attack_type=attack_type,
                confidence=confidence,
                protocol=protocol,
                dst_port=dst_port,
                anomaly_probability=anomaly_p,
            )
        except Exception:  # noqa: BLE001
            logger.exception("DLEngine._predict_one failed")
            return "Unknown", 0.0, STATUS_UNKNOWN

    # ------------------------------------------------------------------
    # Optional: vectorised batch path for higher throughput
    # ------------------------------------------------------------------
    def predict_batch(
        self, features_list: List[Dict[str, Any]], protocol: str = "TCP"
    ) -> List[Dict[str, Any]]:
        """
        Vectorised inference over a list of feature dicts.

        For now we delegate per-item to keep the heuristic / LLM-
        routing paths simple. A future optimisation can scale + run
        Keras in one shot then apply the per-row decisions.
        """
        return super().predict_batch(features_list, protocol)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        """
        Engine-specific extras for ``GET /api/engine/info``.

        Class count + Infiltration support are read DYNAMICALLY from
        the loaded stage-2 model and label_mapping so the UI reflects
        whichever DNN variant is currently on disk (the 31-feature
        retrain produced a 14-class head with Infiltration; the older
        53-feature artifact had 13 with Infiltration excluded).
        """
        info = super().info()
        n_classes = None
        if self._stage2 is not None and hasattr(self._stage2, 'output_shape'):
            try:
                n_classes = int(self._stage2.output_shape[-1])
            except Exception:
                n_classes = None
        infil_idx = self._label_mapping.get("infil_label_idx") if self._loaded else None
        # Heuristic: if the saved label_mapping carries an explicit
        # `infil_label_idx` marker, the model was trained WITHOUT
        # Infiltration in stage 2. Absence of the marker means it
        # was trained WITH Infiltration (current 14-class retrain).
        supports_infil = infil_idx is None
        info.update({
            "stage1_file": str(self.models_dir / self.STAGE1_FILE),
            "stage2_file": str(self.models_dir / self.STAGE2_FILE),
            "label_map_file": str(self.models_dir / self.LABEL_MAP_FILE),
            "n_attack_classes": n_classes,
            "supports_infiltration": supports_infil,
            "infil_label_idx": infil_idx,
            "low_confidence_threshold": float(
                getattr(settings, "DL_LOW_CONFIDENCE_THRESHOLD", 0.7)
            ),
            "infil_routing_enabled": bool(
                getattr(settings, "DL_INFIL_ROUTING_ENABLED", True)
            ),
            "raw_mode": bool(getattr(settings, "DL_RAW_MODE", False)),
        })
        return info

"""
GNN detection engine — Two-Stage Graph Neural Network.

Pipeline
--------
1. **Stage 1** — ``EGraphSAGE_GAT`` (SAGEConv x2 + GATv2): binary
   Benign vs Attack. Decision threshold 0.35 (calibrated low for
   Infiltration recall — see ``gnn_inference.STAGE1_ATTACK_THRESHOLD``).
2. **Stage 2** — ``GIN_GAT`` (GINConv x2 + GATv2): 13-class attack type,
   run only on flows stage 1 flagged as Attack.

Unlike the ML/DL engines this is *relational* — flows are nodes in a
graph (same-Dst-Port + KNN + self-loop edges). A clustered set of
stealthy Infiltration flows can reinforce one another, which is why the
GNN reaches end-to-end Infiltration F1 0.6321 vs the DNN baseline 0.27
(2.34x improvement). The trade-off: overall accuracy 0.8785, below the
ML/DL engines — so the GNN is an *opt-in* choice for deployments where
Infiltration detection matters more than headline accuracy.

Integration notes
------------------
* ``torch`` / ``torch_geometric`` are heavy. They are imported lazily
  inside ``gnn_inference`` — this module never imports them at load
  time, so registering the GNN engine does not slow Django startup or
  the ML/DL hot paths. The import only happens on the first GNN
  ``predict()``.
* Uses the GNN's OWN ``scaler.pkl`` (``dl_models/gnn/scaler.pkl``), not
  the shared one — it was fit on the GNN's training split.
* If the model files are missing, ``is_available()`` returns False and
  the registry transparently falls back to another available engine
  (ML / XGBoost), per the registry's resolution order.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .base_engine import (
    STATUS_ATTACK,
    STATUS_NORMAL,
    STATUS_UNKNOWN,
    BaseEngine,
)

logger = logging.getLogger("pids.detection.gnn")


class GNNEngine(BaseEngine):
    """
    Two-stage Graph Neural Network detection engine.

    Notes
    -----
    * Stage-2 head has **13** attack classes (Infiltration *included* —
      ``"Infilteration"`` is index 11 of ``GNN_CLASS_NAMES``).
    * Loaded lazily on first :meth:`predict`.
    * :meth:`predict_batch` builds one graph over the whole batch so
      flows can exchange context — this is the preferred call path for
      the live sniffer; per-flow :meth:`_predict_one` builds a trivial
      single-node graph and loses the relational signal.
    """

    name: str = "gnn"

    def __init__(self, models_dir: Path) -> None:
        super().__init__(models_dir)
        self._bundle: Any = None  # dict from load_gnn_models()

    # ------------------------------------------------------------------
    # Availability — cheap file check, no torch import
    # ------------------------------------------------------------------
    def is_available(self) -> bool:
        """True if both .pt checkpoints and scaler.pkl are on disk."""
        try:
            from dl_models.gnn.gnn_inference import gnn_files_present
            return bool(gnn_files_present())
        except Exception as exc:  # noqa: BLE001
            logger.warning("GNN availability check failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Load — lazy, catches everything
    # ------------------------------------------------------------------
    def load(self) -> bool:
        """
        Load both stage models + scaler via ``gnn_inference``.

        All errors are caught and recorded in ``_load_error`` so a
        missing torch_geometric install or a corrupt checkpoint cannot
        crash Django — the registry just falls back to another engine.
        """
        try:
            from dl_models.gnn.gnn_inference import (
                GNN_CLASS_NAMES,
                STAGE1_ATTACK_THRESHOLD,
                load_gnn_models,
            )

            self._bundle = load_gnn_models()
            self.feature_list = list(self._bundle["feature_order"])
            logger.info(
                "GNNEngine loaded: features=%d classes=%d stage1_threshold=%.2f",
                len(self.feature_list),
                len(GNN_CLASS_NAMES),
                STAGE1_ATTACK_THRESHOLD,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"{type(exc).__name__}: {exc}"
            logger.exception(
                "GNNEngine.load() failed — is torch_geometric installed? "
                "Registry will fall back to another engine."
            )
            return False

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    @staticmethod
    def _to_tuple(result: Dict[str, Any]) -> Tuple[str, float, str]:
        """Map one ``predict_gnn`` result dict to the legacy 3-tuple."""
        label = result.get("final_label", "Unknown")
        confidence = float(result.get("confidence", 0.0))
        if label == "Benign":
            # Engine contract uses "Normal" for the benign status string.
            return "Normal", confidence, STATUS_NORMAL
        if label == "Unknown":
            return "Unknown", confidence, STATUS_UNKNOWN
        return label, confidence, STATUS_ATTACK

    def _predict_one(
        self, features: Dict[str, Any], protocol: str
    ) -> Tuple[str, float, str]:
        """
        Single-flow inference. Builds a one-node graph (self-loop only),
        so the relational signal is lost — prefer :meth:`predict_batch`
        on the hot path. Kept for the BaseEngine single-predict contract.
        """
        try:
            from dl_models.gnn.gnn_inference import predict_gnn

            results = predict_gnn([features])
            if not results:
                return "Unknown", 0.0, STATUS_UNKNOWN
            return self._to_tuple(results[0])
        except Exception:  # noqa: BLE001
            logger.exception("GNNEngine._predict_one failed")
            return "Unknown", 0.0, STATUS_UNKNOWN

    def predict_batch(
        self, features_list: List[Dict[str, Any]], protocol: str = "TCP"
    ) -> List[Dict[str, Any]]:
        """
        Graph-aware batch inference — builds ONE graph over the whole
        batch so flows exchange context (the relational signal that
        makes the GNN worth selecting). Falls back to the per-item base
        implementation if loading or inference fails.
        """
        if not features_list:
            return []
        if not self.ensure_loaded():
            # Mirror BaseEngine.predict_legacy degradation per item.
            return [
                {
                    "is_attack": False, "attack_type": "Normal",
                    "confidence": 0.5, "status": STATUS_NORMAL, "engine": self.name,
                }
                for _ in features_list
            ]
        try:
            from dl_models.gnn.gnn_inference import predict_gnn

            raw = predict_gnn(features_list)
            out: List[Dict[str, Any]] = []
            for result in raw:
                label, confidence, status = self._to_tuple(result)
                out.append({
                    "is_attack": status == STATUS_ATTACK,
                    "attack_type": label,
                    "confidence": confidence,
                    "status": status,
                    "engine": self.name,
                })
            return out
        except Exception:  # noqa: BLE001
            logger.exception("GNNEngine.predict_batch failed; degrading to per-item")
            return super().predict_batch(features_list, protocol)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    def info(self) -> Dict[str, Any]:
        """Engine-specific extras for ``GET /api/engine/info``."""
        info = super().info()
        try:
            from dl_models.gnn.gnn_inference import (
                GNN_CLASS_NAMES,
                STAGE1_ATTACK_THRESHOLD,
            )
            n_classes = len(GNN_CLASS_NAMES)
            threshold = STAGE1_ATTACK_THRESHOLD
        except Exception:  # noqa: BLE001
            n_classes = 13
            threshold = 0.35
        info.update({
            "architecture": "Two-Stage GNN (E-GraphSAGE+GATv2 / GIN+GATv2)",
            "stage1_file": str(self.models_dir / "stage1_egraphsage_best.pt"),
            "stage2_file": str(self.models_dir / "stage2_gin_gat_best.pt"),
            "n_attack_classes": n_classes,
            "supports_infiltration": True,
            "stage1_threshold": threshold,
            "graph_topology": "same-Dst-Port + KNN(k=8) + self-loops",
            # End-to-end metrics (see dl_models/gnn/README.md).
            "overall_accuracy": 0.8785,
            "infiltration_f1": 0.6321,
        })
        return info

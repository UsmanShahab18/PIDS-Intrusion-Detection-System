"""
Inference module for the two-stage GNN intrusion detector.

Public surface
--------------
* ``load_gnn_models()``      — load both stage models + scaler + feature
                               order from this directory. Cached per process.
* ``build_graph_from_flows`` — turn a batch of flow feature dicts into a
                               PyG ``Data`` object (nodes = flows).
* ``predict_gnn(flow_batch)``— run the full two-stage pipeline and return
                               a list of per-flow result dicts.

Graph topology
--------------
Each network flow is one node. A GNN needs edges, and the choice of edge
construction is what lets the model exploit *relational* structure that
a per-flow classifier (XGBoost / DNN) cannot see. Three edge types are
combined (see ``build_graph_from_flows`` for the rationale of each):

  1. Same-Dst-Port edges  — flows hitting the same destination port
     within the batch window are likely part of one campaign (port
     scans, brute-force, DDoS all fan out to a fixed service port).
  2. KNN(k=8) feature-space edges — flows that are statistically similar
     get connected, so a confidently-benign neighbourhood can "vouch"
     for an ambiguous flow and vice-versa. This is the main driver of
     the Infiltration recall gain — stealthy Infiltration flows look
     near-benign alone but cluster together in feature space.
  3. Self-loops — every node keeps its own signal through message passing.

Edge features are the element-wise mean of the two endpoint node
vectors. The current checkpoints use plain SAGE / GIN / GATv2 layers
that do not consume ``edge_attr``, but it is attached to the ``Data``
object anyway so an edge-aware retrain needs no pipeline change.

Two-stage routing
------------------
Stage 1 (binary) decides Benign vs Attack. Its decision threshold is
**0.35**, not 0.5 — deliberately calibrated low to raise Attack recall
on stealthy Infiltration flows (the whole reason this model exists).
Flows stage 1 calls Attack are routed through Stage 2 for the 13-class
attack-type label. Benign flows skip stage 2 entirely.

Lazy by design: ``torch`` / ``torch_geometric`` are heavy. Nothing here
imports them at module load — the imports live inside ``load_gnn_models``
so Django startup and the ML/DL engines are never slowed down.
"""
from __future__ import annotations

import json
import logging
import pickle
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("pids.detection.gnn")

# This file's directory — all GNN artifacts live alongside it.
_GNN_DIR = Path(__file__).resolve().parent

# Stage-1 binary decision threshold. Tuned DOWN from the natural 0.5 to
# 0.35 to maximise Attack recall on Infiltration (standalone Infiltration
# F1 0.9995; end-to-end 0.6321 vs DNN baseline 0.27).
STAGE1_ATTACK_THRESHOLD: float = 0.35

# KNN neighbours per node when building feature-space edges.
KNN_K: int = 8

# Stage-2 class names — order MUST match the training label order and
# the 13-way head in stage2_gin_gat_best.pt. Mirrors
# dl_models/gnn/stage2_metrics.json["classes"].
GNN_CLASS_NAMES: List[str] = [
    "Bot",
    "Brute Force -Web",
    "Brute Force -XSS",
    "DDOS attack-HOIC",
    "DDOS attack-LOIC-UDP",
    "DDoS attacks-LOIC-HTTP",
    "DoS attacks-GoldenEye",
    "DoS attacks-Hulk",
    "DoS attacks-SlowHTTPTest",
    "DoS attacks-Slowloris",
    "FTP-BruteForce",
    "Infilteration",
    "SSH-Bruteforce",
]

# Artifact filenames in this directory.
_STAGE1_FILE = "stage1_egraphsage_best.pt"
_STAGE2_FILE = "stage2_gin_gat_best.pt"
_SCALER_FILE = "scaler.pkl"
_STAGE1_METRICS_FILE = "stage1_metrics.json"

# Process-wide cache of the loaded bundle. Loading is paid once.
_GNN_BUNDLE: Optional[Dict[str, Any]] = None
_LOAD_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Availability check (cheap — no torch import)
# ---------------------------------------------------------------------------
def gnn_files_present() -> bool:
    """Return True if every required GNN artifact exists on disk."""
    return all(
        (_GNN_DIR / f).exists()
        for f in (_STAGE1_FILE, _STAGE2_FILE, _SCALER_FILE)
    )


# ---------------------------------------------------------------------------
# Model / artifact loading
# ---------------------------------------------------------------------------
def load_gnn_models() -> Dict[str, Any]:
    """
    Load both stage models, the StandardScaler, and the 31-feature order.

    Returns a bundle dict::

        {
            "stage1": EGraphSAGE_GAT (eval mode),
            "stage2": GIN_GAT (eval mode),
            "scaler": StandardScaler,
            "feature_order": list[str]  (length 31),
            "device": torch.device,
        }

    Cached per process — repeat calls return the same bundle. Raises on
    failure; the caller (``GNNEngine.load``) catches and degrades.
    """
    global _GNN_BUNDLE
    if _GNN_BUNDLE is not None:
        return _GNN_BUNDLE

    with _LOAD_LOCK:
        if _GNN_BUNDLE is not None:
            return _GNN_BUNDLE

        # Heavy imports happen HERE, not at module load — keeps the GNN
        # dependency cost off Django startup and the ML/DL hot paths.
        import torch

        from .gnn_model_arch import EGraphSAGE_GAT, GIN_GAT

        device = torch.device("cpu")  # inference batch is small; CPU is fine

        # --- scaler ---
        # The GNN node head takes 31 features (node_proj.weight is
        # (hidden, 31)). The expected scaler is therefore a 31-feature
        # StandardScaler. The shipped dl_models/gnn/scaler.pkl is a
        # *53-feature* scaler — a stale artifact from a pre-selection
        # stage of the training pipeline that does not match the model.
        # Guard against that: only use it when it really is 31-feature;
        # otherwise fall back to the canonical 31-feature StandardScaler
        # in dl_models/dnn/ (the GNN's `features_used` list is identical,
        # in the same order, to the DNN's `selected_features`, so the
        # fall-back scaler is fit on exactly the same 31 columns).
        with open(_GNN_DIR / _SCALER_FILE, "rb") as fh:
            scaler = pickle.load(fh)
        n_in = getattr(scaler, "n_features_in_", None)
        if n_in != 31:
            fallback = _GNN_DIR.parent / "dnn" / "scaler.pkl"
            logger.warning(
                "dl_models/gnn/scaler.pkl is a %s-feature scaler but the GNN "
                "expects 31 features; falling back to %s",
                n_in, fallback,
            )
            with open(fallback, "rb") as fh:
                scaler = pickle.load(fh)
            if getattr(scaler, "n_features_in_", None) != 31:
                raise ValueError(
                    "No usable 31-feature scaler found for the GNN engine"
                )

        # --- feature order: prefer the list saved in stage1_metrics.json
        #     (that is the exact column order the scaler/model expect) ---
        feature_order: Optional[List[str]] = None
        metrics_path = _GNN_DIR / _STAGE1_METRICS_FILE
        if metrics_path.exists():
            try:
                with open(metrics_path, "r", encoding="utf-8") as fh:
                    feature_order = json.load(fh).get("features_used")
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not read GNN feature order from metrics: %s", exc)
        if not feature_order:
            # Fallback: the shared 31-feature schema used by ML/DL engines.
            from api.detection.engines._shared import load_feature_names
            feature_order = load_feature_names()
        if len(feature_order) != 31:
            raise ValueError(
                f"GNN expects 31 features, feature order has {len(feature_order)}"
            )

        # --- stage 1: binary head ---
        stage1 = EGraphSAGE_GAT(node_in=31, hidden=128, n_classes=2, heads=4)
        state1 = torch.load(_GNN_DIR / _STAGE1_FILE, map_location=device)
        stage1.load_state_dict(state1)
        stage1.eval().to(device)

        # --- stage 2: 13-class head ---
        stage2 = GIN_GAT(node_in=31, hidden=64, n_classes=13, heads=4)
        state2 = torch.load(_GNN_DIR / _STAGE2_FILE, map_location=device)
        stage2.load_state_dict(state2)
        stage2.eval().to(device)

        _GNN_BUNDLE = {
            "stage1": stage1,
            "stage2": stage2,
            "scaler": scaler,
            "feature_order": list(feature_order),
            "device": device,
        }
        logger.info(
            "GNN models loaded: stage1=EGraphSAGE_GAT stage2=GIN_GAT "
            "features=%d classes=%d threshold=%.2f",
            len(feature_order), len(GNN_CLASS_NAMES), STAGE1_ATTACK_THRESHOLD,
        )
        return _GNN_BUNDLE


def reset_gnn_cache() -> None:
    """Drop the cached bundle so the next ``load_gnn_models`` reloads."""
    global _GNN_BUNDLE
    with _LOAD_LOCK:
        _GNN_BUNDLE = None


# ---------------------------------------------------------------------------
# Feature vectorisation
# ---------------------------------------------------------------------------
def _vectorise_batch(flow_batch: List[Dict[str, Any]], feature_order: List[str]):
    """
    Turn a list of flow feature dicts into a dense ``(N, 31)`` float32
    numpy array in the model's expected column order.

    Missing keys -> 0.0; non-finite values (inf / nan) -> 0.0, matching
    the ML/DL engines' preprocessing so all engines see the same inputs.
    """
    import numpy as np

    n = len(flow_batch)
    mat = np.zeros((n, len(feature_order)), dtype=np.float32)
    for r, flow in enumerate(flow_batch):
        for c, name in enumerate(feature_order):
            try:
                v = float(flow.get(name, 0.0))
                if not np.isfinite(v):
                    v = 0.0
            except (TypeError, ValueError):
                v = 0.0
            mat[r, c] = v
    return mat


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------
def build_graph_from_flows(flow_batch: List[Dict[str, Any]]) -> Any:
    """
    Build a PyG ``Data`` object from a batch of flow feature dicts.

    One node per flow. Edges combine three relations (see module
    docstring for *why* each is used):

      * same-Dst-Port within the batch  (campaign / fan-out structure)
      * KNN(k=8) in scaled feature space (similarity vouching — the
        Infiltration recall driver)
      * self-loops                      (node keeps its own signal)

    ``edge_attr`` is the element-wise mean of the two endpoint node
    feature vectors. Returns a ``torch_geometric.data.Data`` with
    ``x``, ``edge_index``, ``edge_attr``.

    Note: graph topology is built from *scaled* features so KNN distances
    are not dominated by large-magnitude columns (Flow Duration, byte
    counts). The scaling happens in ``predict_gnn`` before this is called.
    """
    import numpy as np
    import torch
    from torch_geometric.data import Data

    bundle = load_gnn_models()
    feature_order = bundle["feature_order"]
    scaler = bundle["scaler"]

    raw = _vectorise_batch(flow_batch, feature_order)
    x_scaled = scaler.transform(raw).astype(np.float32)
    n = x_scaled.shape[0]

    src: List[int] = []
    dst: List[int] = []

    # --- (1) same Dst Port edges ---------------------------------------
    # Group node indices by destination port. Flows to the same service
    # port within one capture window tend to belong to one attack
    # campaign (a port scan, a brute-force run, a DDoS fan-out), so
    # connecting them lets the GNN propagate that campaign signal.
    port_groups: Dict[int, List[int]] = {}
    for i, flow in enumerate(flow_batch):
        try:
            port = int(flow.get("Dst Port", flow.get("dst_port", 0)) or 0)
        except (TypeError, ValueError):
            port = 0
        port_groups.setdefault(port, []).append(i)
    for port, members in port_groups.items():
        if port == 0 or len(members) < 2:
            continue
        # Fully connect the group (small batches — O(group^2) is fine).
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                src += [members[a], members[b]]
                dst += [members[b], members[a]]

    # --- (2) KNN(k=8) in feature space ---------------------------------
    # Connect each node to its k nearest neighbours by Euclidean distance
    # in *scaled* feature space. This is the relation that lets a cluster
    # of stealthy Infiltration flows reinforce one another even when each
    # one looks near-benign in isolation.
    if n > 1:
        k = min(KNN_K, n - 1)
        # Pairwise squared distances — n is a small batch so the dense
        # (n x n) matrix is cheap; no need for a KD-tree here.
        diff = x_scaled[:, None, :] - x_scaled[None, :, :]
        dist2 = np.einsum("ijk,ijk->ij", diff, diff)
        np.fill_diagonal(dist2, np.inf)  # exclude self from KNN
        knn_idx = np.argpartition(dist2, kth=k - 1, axis=1)[:, :k]
        for i in range(n):
            for j in knn_idx[i]:
                src += [i, int(j)]
                dst += [int(j), i]

    # --- (3) self-loops ------------------------------------------------
    for i in range(n):
        src.append(i)
        dst.append(i)

    if not src:  # single isolated node with no port group
        src, dst = [0], [0]

    edge_index = torch.tensor([src, dst], dtype=torch.long)

    # --- edge features: mean of endpoint node vectors ------------------
    x_tensor = torch.from_numpy(x_scaled)
    edge_attr = (x_tensor[edge_index[0]] + x_tensor[edge_index[1]]) / 2.0

    return Data(x=x_tensor, edge_index=edge_index, edge_attr=edge_attr)


# ---------------------------------------------------------------------------
# Two-stage prediction
# ---------------------------------------------------------------------------
def predict_gnn(flow_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run the full two-stage GNN pipeline over a batch of flows.

    Parameters
    ----------
    flow_batch
        List of flow feature dicts (each must contain the 31 golden
        features by name; ``Dst Port`` is also used for graph topology).

    Returns
    -------
    list[dict]
        One dict per input flow, in input order::

            {
                "binary_pred": int,        # 0 = Benign, 1 = Attack
                "multi_pred":  int | None, # 0..12 stage-2 class idx, or None if Benign
                "final_label": str,        # "Benign" or an attack class name
                "confidence":  float,      # 0..1 confidence of final_label
            }

    Stage 1 uses threshold ``STAGE1_ATTACK_THRESHOLD`` (0.35). Flows it
    flags as Attack are routed through stage 2; Benign flows are not.
    """
    if not flow_batch:
        return []

    import torch

    bundle = load_gnn_models()
    stage1 = bundle["stage1"]
    stage2 = bundle["stage2"]
    device = bundle["device"]

    # Build the graph once — both stages share the same topology.
    graph = build_graph_from_flows(flow_batch)
    x = graph.x.to(device)
    edge_index = graph.edge_index.to(device)
    n = x.size(0)

    results: List[Dict[str, Any]] = []
    with torch.no_grad():
        # --- Stage 1: binary Benign vs Attack ---
        logits1 = stage1(x, edge_index)
        probs1 = torch.softmax(logits1, dim=1)
        attack_prob = probs1[:, 1]  # P(Attack)
        binary_pred = (attack_prob >= STAGE1_ATTACK_THRESHOLD).long()

        # --- Stage 2: 13-class attack type (run on the whole graph; we
        #     only READ rows that stage 1 flagged as Attack so the graph
        #     context is preserved for those nodes) ---
        attack_nodes = torch.nonzero(binary_pred == 1, as_tuple=False).view(-1)
        multi_pred = None
        multi_conf = None
        if attack_nodes.numel() > 0:
            logits2 = stage2(x, edge_index)
            probs2 = torch.softmax(logits2, dim=1)
            multi_pred = probs2.argmax(dim=1)       # (n,)
            multi_conf = probs2.max(dim=1).values   # (n,)

        for i in range(n):
            if binary_pred[i].item() == 0:
                # Benign — stage 2 skipped. Confidence is P(Benign).
                results.append({
                    "binary_pred": 0,
                    "multi_pred": None,
                    "final_label": "Benign",
                    "confidence": float(probs1[i, 0].item()),
                })
            else:
                cls_idx = int(multi_pred[i].item())
                label = (
                    GNN_CLASS_NAMES[cls_idx]
                    if 0 <= cls_idx < len(GNN_CLASS_NAMES)
                    else "Unknown"
                )
                results.append({
                    "binary_pred": 1,
                    "multi_pred": cls_idx,
                    "final_label": label,
                    "confidence": float(multi_conf[i].item()),
                })
    return results

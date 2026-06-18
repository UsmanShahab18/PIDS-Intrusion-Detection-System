# Two-Stage GNN Detection Engine

A Graph Neural Network intrusion detector, offered as a **third
selectable detection engine** (`gnn`) alongside the existing `ml`
(XGBoost + LightGBM) and `dl` (two-stage DNN) engines.

Unlike the per-flow ML/DL classifiers, the GNN is **relational** — it
treats network flows as nodes in a graph and lets neighbouring flows
exchange context during inference. That relational signal is what
drives its large gain on stealthy *Infiltration* traffic.

---

## Architecture

| Stage | Model | Task | Layers |
|-------|-------|------|--------|
| 1 | `EGraphSAGE_GAT` | Binary: Benign vs Attack | `Linear(31→128)` → `SAGEConv ×2` → `GATv2Conv(heads=4)` → MLP head (2 logits) |
| 2 | `GIN_GAT` | Multi-class: 13 attack types | `Linear(31→64)` → `GINConv ×2` → `GATv2Conv(heads=4)` → MLP head (13 logits), LayerNorm after each block |

Both stages consume the **same 31 golden features** and feature order
as the ML/DL engines. Stage 2 only runs on flows Stage 1 flagged as
Attack; Benign flows skip it.

Files in this directory:

```
gnn_model_arch.py            PyTorch class definitions (EGraphSAGE_GAT, GIN_GAT)
gnn_inference.py             load / build-graph / predict pipeline
test_gnn.py                  smoke tests (shapes + routing contract)
stage1_egraphsage_best.pt    Stage-1 checkpoint (state_dict)
stage2_gin_gat_best.pt       Stage-2 checkpoint (state_dict)
stage1_metrics.json          Stage-1 metrics + the 31-feature order
stage2_metrics.json          Stage-2 metrics + class names
scaler.pkl                   (see "Scaler note" below)
```

---

## Graph topology

Each flow is one node. Edges combine three relations — the choice of
edge construction is what gives the GNN information a per-flow model
cannot see:

1. **Same-Dst-Port edges** — flows hitting the same destination port
   within a capture window are likely part of one campaign (port scans,
   brute-force runs and DDoS fan-outs all converge on a fixed service
   port). Connecting them lets the campaign signal propagate.
2. **KNN(k=8) feature-space edges** — each node is linked to its 8
   nearest neighbours by Euclidean distance in *scaled* feature space.
   This is the main Infiltration-recall driver: a stealthy Infiltration
   flow looks near-benign in isolation, but a *cluster* of them can
   reinforce one another through message passing.
3. **Self-loops** — every node retains its own signal across layers.

Edge features are the element-wise mean of the two endpoint node
vectors. (The current checkpoints use plain SAGE/GIN/GATv2 layers that
do not consume `edge_attr`; it is attached to the graph anyway so an
edge-aware retrain needs no pipeline change.)

---

## Performance

**Stage 1 — binary (E-GraphSAGE + GATv2)**
- Test Accuracy: 0.9685
- Test F1: 0.9548
- Test AUC: 0.9819

**Stage 2 — multi-class (GIN + GATv2), 13 classes**
- Test Accuracy: 0.9992
- Test Macro F1: 0.9946
- Infiltration F1: 0.9995 (standalone)

**End-to-end pipeline (real production behaviour)**
- Overall Accuracy: 0.8785
- Infiltration F1: **0.6321** — vs DNN baseline 0.27 = **2.34× improvement**
- Stage-1 decision threshold tuned to **0.35** (not the naive 0.5) to
  raise Attack recall on Infiltration.

Trained on CICIDS2018, 31 features, KNN + port + temporal graph topology.

---

## When to use GNN vs the other engines

| Engine | Overall accuracy | Infiltration F1 | Use when… |
|--------|------------------|-----------------|-----------|
| ML (XGBoost + LightGBM) | ~98.24% / ~95.66% | — | You want the highest headline accuracy and lowest latency. |
| DL (two-stage DNN) | ~98.36% | 0.27 | Default deep model; LLM routing compensates for low-confidence flows. |
| **GNN (this engine)** | **87.85%** | **0.63** | **Infiltration / stealthy lateral-movement detection matters more than headline accuracy.** |

**Trade-off:** the GNN has *lower* overall accuracy than ML/DL but
**2.34× better Infiltration F1**. It is an explicit opt-in — the
default detection engine is unchanged, and an admin must select `gnn`
from the Detection Engine card in the UI (or `POST /api/engine/select`).

---

## How it is wired into PIDS

- `api/detection/engines/gnn_engine.py` — `GNNEngine(BaseEngine)`, the
  registry-aware wrapper. Lazy-loads `gnn_inference` on first predict.
- `api/detection/engines/engine_registry.py` — registers the `gnn`
  engine pointing at `dl_models/gnn/`.
- `api/models.py` — `EngineConfig.ENGINE_CHOICES` includes `gnn`
  (migration `0006_engineconfig_gnn_choice`).
- `api/views_engine.py` — `POST /api/engine/select` accepts `gnn` and
  writes an `AuditLog` entry on every engine switch.
- `frontend/src/components/EngineSelector.jsx` — renders the GNN card
  with its metric summary and trade-off disclosure.

`torch` / `torch_geometric` are **lazily imported** — they are only
loaded the first time the GNN engine actually runs a prediction, so
registering the engine costs nothing at Django startup and the ML/DL
hot paths are untouched. If the heavy deps or model files are missing,
`GNNEngine.is_available()` returns `False` and the registry
transparently falls back to another available engine.

Install the dependencies (already added to `requirements.txt`):

```
pip install torch>=2.0 torch-geometric>=2.3
```

---

## Scaler note

The model's node head takes **31** features (`node_proj.weight` is
`(hidden, 31)`). The `scaler.pkl` shipped in this directory is a
**53-feature** `StandardScaler` — a stale artifact from a
pre-feature-selection stage of the training pipeline that does **not**
match the model input.

`gnn_inference.load_gnn_models()` guards against this: it only uses
`dl_models/gnn/scaler.pkl` when it is genuinely 31-feature, and
otherwise logs a warning and falls back to the canonical 31-feature
`StandardScaler` at `dl_models/dnn/scaler.pkl`. The GNN's
`features_used` list is identical, in the same order, to the DNN's
`selected_features`, so the fall-back scaler is fit on exactly the same
31 columns. **Replacing `dl_models/gnn/scaler.pkl` with the correct
31-feature scaler from training is recommended** to remove the warning.

---

## Running the tests

```
cd backend
python -m dl_models.gnn.test_gnn          # GNN pipeline smoke tests
python test_attacks.py                    # includes test_gnn_predictions()
```

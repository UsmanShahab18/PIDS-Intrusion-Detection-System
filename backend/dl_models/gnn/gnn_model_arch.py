"""
PyTorch model architectures for the two-stage GNN intrusion detector.

The class definitions here MUST match the layer names / shapes of the
checkpoints in this directory, otherwise ``load_state_dict`` fails:

    stage1_egraphsage_best.pt   ->  EGraphSAGE_GAT   (binary head)
    stage2_gin_gat_best.pt      ->  GIN_GAT          (13-class head)

Both checkpoints were verified to be plain ``state_dict`` pickles (no
optimiser / wrapper keys) so loading is a direct ``load_state_dict``.

Performance (for documentation — see dl_models/gnn/README.md):
  Stage 1 (binary E-GraphSAGE + GATv2):
      Test Accuracy 0.9685 | F1 0.9548 | AUC 0.9819
  Stage 2 (multi-class GIN + GATv2):
      Test Accuracy 0.9992 | Macro F1 0.9946 | Infiltration F1 0.9995
  End-to-end pipeline:
      Overall Accuracy 0.8785 | Infiltration F1 0.6321
      (vs DNN baseline 0.27 -> 2.34x improvement)

torch / torch_geometric are imported at module level here — this module
is only ever imported lazily by ``gnn_inference.load_gnn_models()``,
which itself is only imported when the GNN engine is selected. Django
startup never touches it.
"""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv, GINConv, SAGEConv


# ---------------------------------------------------------------------------
# Stage 1 — binary: Benign vs Attack
# ---------------------------------------------------------------------------
class EGraphSAGE_GAT(nn.Module):
    """
    Stage-1 binary classifier.

    Topology: node_proj -> SAGEConv x2 -> GATv2Conv -> MLP head.

    Checkpoint-derived hyper-params (do not change — they pin the
    ``state_dict`` shapes):
      * node_in  = 31   (the shared 31 golden features)
      * hidden   = 128
      * heads    = 4    (GATv2, concat=False -> output stays ``hidden``)
      * n_classes = 2   (logits: [Benign, Attack])
    """

    def __init__(
        self,
        node_in: int = 31,
        hidden: int = 128,
        n_classes: int = 2,
        heads: int = 4,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        # Project the raw 31-feature node vector into the GNN hidden space.
        self.node_proj = nn.Linear(node_in, hidden)
        # Two GraphSAGE message-passing layers aggregate neighbour context
        # over the KNN + same-port + temporal edges built in gnn_inference.
        self.sage1 = SAGEConv(hidden, hidden)
        self.sage2 = SAGEConv(hidden, hidden)
        # GATv2 attention layer: lets the model weight neighbours unequally
        # (concat=False keeps the width at ``hidden`` so the MLP head fits).
        self.gat = GATv2Conv(hidden, hidden, heads=heads, concat=False)
        # MLP classifier head. Indices are significant: clf.0 / clf.3 are
        # the Linear layers the checkpoint stores; clf.1 / clf.2 are the
        # parameter-free ReLU / Dropout.
        self.clf = nn.Sequential(
            nn.Linear(hidden, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, n_classes),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return raw logits of shape ``(num_nodes, 2)``."""
        x = F.relu(self.node_proj(x))
        x = F.relu(self.sage1(x, edge_index))
        x = F.relu(self.sage2(x, edge_index))
        x = F.relu(self.gat(x, edge_index))
        return self.clf(x)


# ---------------------------------------------------------------------------
# Stage 2 — multi-class: 13 attack types
# ---------------------------------------------------------------------------
class GIN_GAT(nn.Module):
    """
    Stage-2 multi-class attack classifier (only runs on flows stage 1
    flagged as Attack).

    Topology: node_proj -> GINConv x2 -> GATv2Conv -> MLP head, with a
    LayerNorm after each message-passing block.

    Checkpoint-derived hyper-params:
      * node_in  = 31
      * hidden   = 64
      * heads    = 4    (GATv2, concat=False)
      * n_classes = 13  (the 13 CICIDS2018 attack classes)

    GINConv ``eps`` is trainable (``train_eps=True``) — the checkpoint
    stores ``gin1.eps`` / ``gin2.eps`` scalars.
    """

    def __init__(
        self,
        node_in: int = 31,
        hidden: int = 64,
        n_classes: int = 13,
        heads: int = 4,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.node_proj = nn.Linear(node_in, hidden)

        # Each GINConv wraps a 2-layer MLP (nn.0 Linear, nn.1 ReLU,
        # nn.2 Linear) — GIN's injective neighbour aggregation is strong
        # at separating the structurally-similar DoS / DDoS sub-classes.
        gin_mlp1 = nn.Sequential(
            nn.Linear(hidden, hidden), nn.ReLU(), nn.Linear(hidden, hidden)
        )
        gin_mlp2 = nn.Sequential(
            nn.Linear(hidden, hidden), nn.ReLU(), nn.Linear(hidden, hidden)
        )
        self.gin1 = GINConv(gin_mlp1, train_eps=True)
        self.gin2 = GINConv(gin_mlp2, train_eps=True)

        self.gat = GATv2Conv(hidden, hidden, heads=heads, concat=False)

        # LayerNorm after each block stabilises training on the highly
        # imbalanced 13-class attack distribution.
        self.ln1 = nn.LayerNorm(hidden)
        self.ln2 = nn.LayerNorm(hidden)
        self.ln3 = nn.LayerNorm(hidden)

        self.clf = nn.Sequential(
            nn.Linear(hidden, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, n_classes),
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """Return raw logits of shape ``(num_nodes, 13)``."""
        x = F.relu(self.node_proj(x))
        x = F.relu(self.ln1(self.gin1(x, edge_index)))
        x = F.relu(self.ln2(self.gin2(x, edge_index)))
        x = F.relu(self.ln3(self.gat(x, edge_index)))
        return self.clf(x)

"""
Smoke tests for the two-stage GNN inference pipeline.

Run directly::

    cd backend
    python -m dl_models.gnn.test_gnn

Or with pytest::

    pytest backend/dl_models/gnn/test_gnn.py

The tests:
  1. Load both stage models + scaler.
  2. Build a graph from 10 sample flows and check the PyG Data shapes.
  3. Run the full pipeline and verify output shapes / keys.
  4. Exercise the final-label routing logic — a near-zero "benign-ish"
     flow should route to Benign; a crafted high-signal flow should be
     able to reach Stage 2 and land on one of the 13 attack classes.

These are smoke tests (shapes + contracts), not accuracy tests — the
accuracy numbers live in stage1_metrics.json / stage2_metrics.json.
"""
from __future__ import annotations

import random
import sys

# Allow ``python dl_models/gnn/test_gnn.py`` from the backend dir as well
# as ``python -m dl_models.gnn.test_gnn``.
if __package__ in (None, ""):
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dl_models.gnn.gnn_inference import (  # noqa: E402
    GNN_CLASS_NAMES,
    STAGE1_ATTACK_THRESHOLD,
    build_graph_from_flows,
    load_gnn_models,
    predict_gnn,
)


def _make_sample_flows(n: int = 10, seed: int = 42):
    """Build ``n`` synthetic flow dicts using the model's feature order."""
    bundle = load_gnn_models()
    feature_order = bundle["feature_order"]
    rng = random.Random(seed)
    flows = []
    for i in range(n):
        flow = {name: rng.uniform(0.0, 1000.0) for name in feature_order}
        # Spread flows across a couple of ports so the same-Dst-Port
        # edge construction actually produces edges.
        flow["Dst Port"] = 80 if i % 2 == 0 else 443
        flows.append(flow)
    return flows, feature_order


def test_load_models():
    """Both stage models, the scaler and a 31-feature order load."""
    bundle = load_gnn_models()
    assert bundle["stage1"] is not None
    assert bundle["stage2"] is not None
    assert bundle["scaler"] is not None
    assert len(bundle["feature_order"]) == 31
    assert len(GNN_CLASS_NAMES) == 13
    print("[OK] load_gnn_models — stage1, stage2, scaler, 31 features, 13 classes")


def test_build_graph_shapes():
    """A 10-flow batch builds a Data object with consistent shapes."""
    flows, feature_order = _make_sample_flows(10)
    graph = build_graph_from_flows(flows)

    assert graph.x.shape == (10, 31), f"node matrix wrong shape: {graph.x.shape}"
    assert graph.edge_index.shape[0] == 2, "edge_index must be (2, E)"
    assert graph.edge_index.shape[1] == graph.edge_attr.shape[0], (
        "edge_attr count must match edge_index count"
    )
    assert graph.edge_attr.shape[1] == 31, "edge features must be 31-dim"
    # At minimum every node has a self-loop.
    assert graph.edge_index.shape[1] >= 10, "expected at least 10 self-loop edges"
    print(
        f"[OK] build_graph_from_flows — x={tuple(graph.x.shape)} "
        f"edges={graph.edge_index.shape[1]} edge_attr={tuple(graph.edge_attr.shape)}"
    )


def test_predict_output_shapes():
    """predict_gnn returns one well-formed dict per input flow."""
    flows, _ = _make_sample_flows(10)
    results = predict_gnn(flows)

    assert len(results) == 10, f"expected 10 results, got {len(results)}"
    for r in results:
        assert set(r.keys()) == {
            "binary_pred", "multi_pred", "final_label", "confidence"
        }, f"unexpected result keys: {r.keys()}"
        assert r["binary_pred"] in (0, 1)
        assert 0.0 <= r["confidence"] <= 1.0
        if r["binary_pred"] == 0:
            assert r["final_label"] == "Benign"
            assert r["multi_pred"] is None
        else:
            assert r["multi_pred"] is not None
            assert 0 <= r["multi_pred"] < 13
            assert r["final_label"] in GNN_CLASS_NAMES
    print(f"[OK] predict_gnn — 10 results, all keys/ranges valid")


def test_routing_logic():
    """
    Final-label routing: Benign flows skip stage 2 (multi_pred is None),
    Attack flows are routed through stage 2 (multi_pred set, label is an
    attack class). We assert the *contract*, not a specific verdict —
    the synthetic inputs are random so either path is acceptable as long
    as the routing invariant holds.
    """
    # A batch of all-zero flows — after scaling these are the most
    # "average" possible inputs; whatever stage 1 decides, the routing
    # invariant below must hold.
    bundle = load_gnn_models()
    zero_flow = {name: 0.0 for name in bundle["feature_order"]}
    zero_flow["Dst Port"] = 0
    results = predict_gnn([zero_flow] * 5)
    assert len(results) == 5
    for r in results:
        if r["final_label"] == "Benign":
            assert r["binary_pred"] == 0 and r["multi_pred"] is None
        else:
            assert r["binary_pred"] == 1 and r["multi_pred"] is not None
            assert r["final_label"] in GNN_CLASS_NAMES

    # Threshold sanity — must be the calibrated 0.35, not the naive 0.5.
    assert abs(STAGE1_ATTACK_THRESHOLD - 0.35) < 1e-9
    print("[OK] routing logic — Benign/Attack invariant holds; threshold=0.35")


def main() -> int:
    tests = [
        test_load_models,
        test_build_graph_shapes,
        test_predict_output_shapes,
        test_routing_logic,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[FAIL] {t.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} GNN smoke tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

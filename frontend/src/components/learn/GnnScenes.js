/**
 * GnnScenes — scroll-driven scene data for the GNN "Learn" sub-page.
 *
 * Each scene is a self-contained card consumed by <LearnPage />. The shape is
 * shared across all three stacks (gnn / deep / classical):
 *
 *   {
 *     id:      unique key
 *     kicker:  small label above the title (e.g. "Stage 1 · Flow Graph")
 *     title:   section heading
 *     body:    one or two paragraph explanation
 *     points:  optional bullet list of key takeaways
 *     formula: optional KaTeX string rendered as a block equation
 *   }
 *
 * CASE_NODE_IDXS marks which nodes in the page's mini graph visual should be
 * highlighted as the "attack" case study (passed to LearnPage.highlightIdxs).
 */

export const CASE_NODE_IDXS = [2, 5, 9];

export const GNN_SCENES = [
  {
    id: 'gnn-intro',
    kicker: 'Stage 3 · Graph Engine',
    title: 'From flows to a graph',
    body: 'The graph stage models the network as it really is: hosts are nodes and the flows between them are edges. Instead of judging each packet in isolation, the model reasons over the structure of communication — who talks to whom, how often, and with what pattern.',
    points: [
      'Nodes = hosts / endpoints on the monitored network',
      'Edges = bidirectional flows carrying the 31 golden features',
      'Topology exposes lateral movement a per-flow model would miss',
    ],
  },
  {
    id: 'gnn-egraphsage',
    kicker: 'Message Passing',
    title: 'E-GraphSAGE aggregates edge features',
    body: 'E-GraphSAGE extends GraphSAGE to carry information on the edges themselves — exactly where flow features live. Each node updates its representation by sampling and aggregating the feature vectors of its incident edges, so a host’s embedding reflects the behaviour of all its connections.',
    formula: 'h_v^{(k)} = \\sigma\\!\\left(W^{(k)} \\cdot \\mathrm{AGG}\\big(\\{\\, e_{uv} : u \\in \\mathcal{N}(v) \\,\\}\\big)\\right)',
    points: [
      'Aggregates over edge features, not just neighbour nodes',
      'Inductive: generalises to hosts unseen during training',
    ],
  },
  {
    id: 'gnn-gat',
    kicker: 'Attention',
    title: 'GIN + GAT sharpen the signal',
    body: 'A second pass combines the expressive power of GIN with the selectivity of graph attention (GAT). Attention weights let the model focus on the handful of suspicious edges that actually matter while down-weighting routine background traffic.',
    formula: '\\alpha_{uv} = \\frac{\\exp\\big(\\mathrm{LeakyReLU}(a^{\\top}[Wh_u \\Vert Wh_v])\\big)}{\\sum_{k \\in \\mathcal{N}(v)} \\exp\\big(\\mathrm{LeakyReLU}(a^{\\top}[Wh_k \\Vert Wh_v])\\big)}',
    points: [
      'GIN gives maximal discriminative power between graph structures',
      'GAT learns which neighbours deserve attention',
    ],
  },
  {
    id: 'gnn-case',
    kicker: 'Case Study',
    title: 'Catching lateral movement',
    body: 'When a compromised host starts probing its peers, the attack lights up as an anomalous sub-graph: a burst of new edges fanning out from one node. The highlighted nodes show how the signal propagates outward through message passing until the engine flags the originating host.',
    points: [
      'Single-flow models see normal-looking packets',
      'The graph model sees an abnormal fan-out pattern',
      'Detection localises to the source node, not just the alert',
    ],
  },
  {
    id: 'gnn-verdict',
    kicker: 'Verdict',
    title: 'A structural second opinion',
    body: 'The graph engine is the final stage in the pipeline. It does not replace the classical and deep stages — it corroborates them, adding a topology-aware perspective that turns a list of suspicious flows into a coherent picture of an attack in progress.',
  },
];

export default GNN_SCENES;

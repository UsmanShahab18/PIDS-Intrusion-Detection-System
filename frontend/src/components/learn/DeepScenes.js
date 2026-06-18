/**
 * DeepScenes — scroll-driven scene data for the Deep-Learning "Learn"
 * sub-page. Same scene shape as GnnScenes (see that file for the contract).
 */

export const DEEP_SCENES = [
  {
    id: 'deep-intro',
    kicker: 'Stage 2 · Deep Engine',
    title: 'Learning features the parser missed',
    body: 'After the classical stage triages traffic, a deep neural network looks for the non-linear patterns that hand-crafted thresholds cannot express. It consumes the same 31 golden features but composes them into higher-order representations layer by layer.',
    points: [
      'Operates on the 31 golden features per flow',
      'Captures non-linear feature interactions automatically',
      'Acts as the second opinion before the graph stage',
    ],
  },
  {
    id: 'deep-dnn',
    kicker: 'Architecture',
    title: 'A fully-connected DNN',
    body: 'The core is a feed-forward network of dense layers with ReLU activations and dropout for regularisation. Each layer applies a learned affine transform followed by a non-linearity, progressively warping the feature space until benign and malicious flows become linearly separable.',
    formula: 'a^{(l)} = \\mathrm{ReLU}\\big(W^{(l)} a^{(l-1)} + b^{(l)}\\big)',
    points: [
      'Dense layers with ReLU activations',
      'Dropout between layers to curb over-fitting',
      'Batch-normalised inputs for stable training',
    ],
  },
  {
    id: 'deep-softmax',
    kicker: 'Decision',
    title: 'Calibrated class probabilities',
    body: 'The output layer produces a probability distribution over attack classes via softmax. Because the scores are calibrated, downstream stages can reason about confidence — a low-confidence prediction is escalated to the graph engine rather than acted on blindly.',
    formula: 'P(y = c \\mid x) = \\frac{e^{z_c}}{\\sum_{j} e^{z_j}}',
    points: [
      'Softmax over the attack taxonomy',
      'Confidence drives escalation to the graph stage',
    ],
  },
  {
    id: 'deep-training',
    kicker: 'Training',
    title: 'Cross-entropy with class balancing',
    body: 'The network is trained to minimise categorical cross-entropy, with class weighting to counter the heavy imbalance between benign and rare attack traffic. This keeps the model from collapsing to the majority class — the failure mode that makes naive IDS models useless in production.',
    formula: '\\mathcal{L} = -\\sum_{c} w_c \\, y_c \\log \\hat{y}_c',
  },
  {
    id: 'deep-verdict',
    kicker: 'Verdict',
    title: 'Depth where rules run out',
    body: 'The deep engine fills the gap between fast classical triage and structural graph reasoning. It is where the pipeline learns the subtle, learned signatures of evolving attacks that no static rule could keep up with.',
  },
];

export default DEEP_SCENES;

/**
 * ClassicalScenes — scroll-driven scene data for the Classical-ML "Learn"
 * sub-page. Same scene shape as GnnScenes (see that file for the contract).
 */

export const CLASSICAL_SCENES = [
  {
    id: 'classical-intro',
    kicker: 'Stage 1 · Classical Engine',
    title: 'Fast, cheap first-pass triage',
    body: 'Every flow enters the pipeline here. Gradient-boosted trees give a near-instant verdict on the overwhelming majority of traffic, so the heavier deep and graph stages only ever see what actually warrants a closer look.',
    points: [
      'Sub-20 ms inference on the 31 golden features',
      'Filters the bulk of benign traffic immediately',
      'Hands off only uncertain flows to later stages',
    ],
  },
  {
    id: 'classical-trees',
    kicker: 'Models',
    title: 'XGBoost → LightGBM',
    body: 'Two gradient-boosting libraries run in concert. XGBoost provides robust, well-regularised baselines; LightGBM’s histogram-based, leaf-wise growth makes it fast enough to keep up with line-rate capture. Both build an additive ensemble of decision trees, each correcting the residual errors of the last.',
    formula: '\\hat{y}_i = \\sum_{m=1}^{M} f_m(x_i), \\quad f_m \\in \\mathcal{F}',
    points: [
      'Additive ensembles of shallow decision trees',
      'LightGBM leaf-wise growth for speed',
      'Tree splits are directly interpretable',
    ],
  },
  {
    id: 'classical-objective',
    kicker: 'Optimisation',
    title: 'Regularised gradient boosting',
    body: 'Each new tree is fit to the gradient of a regularised objective, trading off training loss against model complexity. The regularisation term is what keeps the ensemble from memorising noise in the capture data — essential when attack samples are scarce.',
    formula: '\\mathcal{L} = \\sum_i l(y_i, \\hat{y}_i) + \\sum_m \\Omega(f_m)',
    points: [
      'Penalises tree complexity to generalise better',
      'Feature importances expose what drives each verdict',
    ],
  },
  {
    id: 'classical-importance',
    kicker: 'Interpretability',
    title: 'Which features matter',
    body: 'Because the model is tree-based, every decision can be traced back to concrete flow attributes — packet rates, byte ratios, flag counts. That transparency is what makes the classical stage trustworthy as the pipeline’s gatekeeper.',
  },
  {
    id: 'classical-verdict',
    kicker: 'Verdict',
    title: 'The gatekeeper',
    body: 'Classical ML earns its place by being fast, interpretable, and reliable on common traffic. It sets the tempo for the whole system, letting the deep and graph engines spend their compute only where it counts.',
  },
];

export default CLASSICAL_SCENES;

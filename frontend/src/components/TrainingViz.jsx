/**
 * TrainingViz — animated, math-annotated walkthrough of how each
 * detection engine learns and predicts.
 *
 * Three tabs, all on one page:
 *   1. Two-Stage DNN     (the deep learning engine)
 *   2. XGBoost (Stage 1) (the classical-ML binary classifier)
 *   3. LightGBM (Stage 2) (the classical-ML multiclass classifier)
 *
 * Each tab shows:
 *   - A live SVG visualisation that steps through the math
 *   - Play / Pause / Step / Reset controls
 *   - Synchronised equation panel rendered with KaTeX
 *
 * The intent is academic-demo-grade: a teacher should be able to glance
 * at any frame and see "here's the equation, here's where in the model
 * it applies".
 */
import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  Box, Container, Typography, Paper, Tabs, Tab, IconButton,
  Stack, Chip, ToggleButton, ToggleButtonGroup, Tooltip, Divider,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  SkipNext as StepIcon,
  RestartAlt as ResetIcon,
  Memory as MemoryIcon,
  AccountTree as TreeIcon,
  ScatterPlot as DotIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { InlineMath, BlockMath } from 'react-katex';
import 'katex/dist/katex.min.css';


// =====================================================================
// Layout primitives — shared between the three sub-visualisations
// =====================================================================

/**
 * Glass-effect card used for each sub-section.
 */
const Glass = ({ children, sx = {} }) => (
  <Paper
    elevation={0}
    sx={{
      bgcolor: 'rgba(15, 15, 20, 0.85)',
      border: '1px solid rgba(0, 255, 65, 0.25)',
      backdropFilter: 'blur(8px)',
      borderRadius: 2,
      p: 2,
      ...sx,
    }}
  >
    {children}
  </Paper>
);


/**
 * Side panel with the current math step. KaTeX renders block + inline.
 */
function EquationPanel({ title, steps, currentStep }) {
  const step = steps[currentStep] || steps[steps.length - 1];
  return (
    <Glass sx={{ minHeight: 460 }}>
      <Stack spacing={1.5}>
        <Stack direction="row" alignItems="center" spacing={1}>
          <Chip
            size="small"
            label={`Step ${Math.min(currentStep + 1, steps.length)}/${steps.length}`}
            sx={{
              bgcolor: 'rgba(0,212,255,0.15)', color: '#00d4ff',
              border: '1px solid #00d4ff', fontFamily: 'Share Tech Mono',
            }}
          />
          <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontWeight: 'bold' }}>
            {title}
          </Typography>
        </Stack>
        <Divider sx={{ borderColor: 'rgba(0,255,65,0.2)' }} />
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStep}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
          >
            <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                              fontSize: '0.95rem', mb: 1.5 }}>
              {step.heading}
            </Typography>
            {step.equations.map((eq, i) => (
              <Box key={i} sx={{ my: 1.2, color: '#fff' }}>
                <BlockMath math={eq} />
              </Box>
            ))}
            <Typography sx={{ color: '#aaa', fontSize: '0.85rem', mt: 1.5,
                              fontFamily: 'Share Tech Mono', lineHeight: 1.6 }}>
              {step.note}
            </Typography>
          </motion.div>
        </AnimatePresence>
      </Stack>
    </Glass>
  );
}


/**
 * Play / Pause / Step / Reset control bar.
 */
function PlayControls({ playing, onPlay, onPause, onStep, onReset, speed, setSpeed }) {
  return (
    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
      {playing ? (
        <Tooltip title="Pause">
          <IconButton onClick={onPause} sx={{ color: '#ff9800', border: '1px solid #ff9800' }}>
            <PauseIcon />
          </IconButton>
        </Tooltip>
      ) : (
        <Tooltip title="Play">
          <IconButton onClick={onPlay} sx={{ color: '#00d4ff', border: '1px solid #00d4ff' }}>
            <PlayIcon />
          </IconButton>
        </Tooltip>
      )}
      <Tooltip title="Single step forward">
        <IconButton onClick={onStep} sx={{ color: '#00d4ff', border: '1px solid #00d4ff' }}>
          <StepIcon />
        </IconButton>
      </Tooltip>
      <Tooltip title="Reset">
        <IconButton onClick={onReset} sx={{ color: '#aaa', border: '1px solid #555' }}>
          <ResetIcon />
        </IconButton>
      </Tooltip>
      <Box sx={{ flex: 1 }} />
      <Typography sx={{ color: '#888', fontSize: '0.75rem', fontFamily: 'Share Tech Mono' }}>
        Speed
      </Typography>
      <ToggleButtonGroup
        size="small"
        exclusive
        value={speed}
        onChange={(_, v) => v && setSpeed(v)}
        sx={{
          '& .MuiToggleButton-root': {
            color: '#888', borderColor: '#333', fontFamily: 'Share Tech Mono', fontSize: '0.7rem',
            '&.Mui-selected': { color: '#000', bgcolor: '#00d4ff' },
          },
        }}
      >
        <ToggleButton value="slow">0.5×</ToggleButton>
        <ToggleButton value="normal">1×</ToggleButton>
        <ToggleButton value="fast">2×</ToggleButton>
      </ToggleButtonGroup>
    </Stack>
  );
}


// =====================================================================
// 1. DNN — Two-Stage Deep Neural Network
// =====================================================================

/**
 * Layer definitions for both stages of the DNN. Each entry corresponds
 * to one animation step plus one math card on the right.
 */
const DNN_LAYERS_STAGE1 = [
  { kind: 'input',   label: 'Input',     dim: 31 },
  { kind: 'dense',   label: 'Dense',     dim: 256, act: 'ReLU' },
  { kind: 'bn',      label: 'BatchNorm', dim: 256 },
  { kind: 'dropout', label: 'Dropout',   dim: 256, rate: 0.3 },
  { kind: 'dense',   label: 'Dense',     dim: 128, act: 'ReLU' },
  { kind: 'bn',      label: 'BatchNorm', dim: 128 },
  { kind: 'dropout', label: 'Dropout',   dim: 128, rate: 0.3 },
  { kind: 'dense',   label: 'Dense',     dim: 64,  act: 'ReLU' },
  { kind: 'bn',      label: 'BatchNorm', dim: 64 },
  { kind: 'dropout', label: 'Dropout',   dim: 64, rate: 0.2 },
  { kind: 'dense',   label: 'Dense',     dim: 32,  act: 'ReLU' },
  { kind: 'dropout', label: 'Dropout',   dim: 32,  rate: 0.2 },
  { kind: 'output',  label: 'Output',    dim: 1,   act: 'Sigmoid' },
];

const DNN_LAYERS_STAGE2 = [
  ...DNN_LAYERS_STAGE1.slice(0, -1),
  { kind: 'output',  label: 'Output',    dim: 14,  act: 'Softmax' },
];


/**
 * Map a layer to one or more math-card steps. The cards drive the
 * EquationPanel; the index also drives which layer in the SVG glows.
 */
function buildDnnSteps(layers, isStage2) {
  const steps = [];
  steps.push({
    layerIdx: 0,
    heading: 'Forward pass — input vector',
    equations: [
      `\\mathbf{x} \\in \\mathbb{R}^{31}`,
      `\\mathbf{x}_{\\text{scaled}} = \\frac{\\mathbf{x} - \\boldsymbol{\\mu}_{\\text{train}}}{\\boldsymbol{\\sigma}_{\\text{train}}}`,
    ],
    note: '31 flow features (CICFlowMeter schema). The shared StandardScaler is applied before any layer.',
  });

  layers.forEach((L, i) => {
    if (i === 0) return; // input already covered
    if (L.kind === 'dense' || L.kind === 'output') {
      const last = layers[i - 1];
      const lastDim = last.dim;
      const isOutput = L.kind === 'output';
      const isSoftmax = L.act === 'Softmax';
      const isSigmoid = L.act === 'Sigmoid';
      const eqs = [
        `\\mathbf{z}^{(${i})} = \\mathbf{W}^{(${i})} \\mathbf{a}^{(${i - 1})} + \\mathbf{b}^{(${i})}, \\quad \\mathbf{W}^{(${i})} \\in \\mathbb{R}^{${L.dim} \\times ${lastDim}}`,
      ];
      if (isSoftmax) {
        eqs.push(`\\hat{p}_k = \\mathrm{softmax}(\\mathbf{z}^{(${i})})_k = \\frac{e^{z_k}}{\\sum_{j=1}^{${L.dim}} e^{z_j}}`);
      } else if (isSigmoid) {
        eqs.push(`\\hat{y} = \\sigma(z^{(${i})}) = \\frac{1}{1 + e^{-z^{(${i})}}}`);
      } else {
        eqs.push(`\\mathbf{a}^{(${i})} = \\mathrm{ReLU}(\\mathbf{z}^{(${i})}) = \\max(0,\\,\\mathbf{z}^{(${i})})`);
      }
      const heading = isOutput
        ? (isSoftmax ? 'Output — softmax over 13 attack classes' : 'Output — sigmoid P(Attack)')
        : `Dense layer (${L.dim} units, ReLU)`;
      const note = isOutput
        ? (isSoftmax
          ? 'Stage 2 emits a probability distribution over 13 attack classes. Argmax + label_mapping decodes back to attack name.'
          : 'Stage 1 emits P(Attack). Threshold (UDP-aware, default 0.5) decides whether stage 2 runs.')
        : `Affine transform followed by ReLU. Shape: ${lastDim} → ${L.dim}.`;
      steps.push({ layerIdx: i, heading, equations: eqs, note });
    } else if (L.kind === 'bn') {
      steps.push({
        layerIdx: i,
        heading: 'Batch Normalization',
        equations: [
          `\\hat{\\mathbf{a}} = \\frac{\\mathbf{a} - \\mu_{\\mathcal{B}}}{\\sqrt{\\sigma_{\\mathcal{B}}^{2} + \\epsilon}}`,
          `\\mathrm{BN}(\\mathbf{a}) = \\gamma \\hat{\\mathbf{a}} + \\beta`,
        ],
        note: 'Stabilises training by normalising activations to zero-mean / unit-variance, then re-scales with learned γ, β.',
      });
    } else if (L.kind === 'dropout') {
      steps.push({
        layerIdx: i,
        heading: `Dropout (rate ${L.rate})`,
        equations: [
          `m_j \\sim \\mathrm{Bernoulli}(1 - p), \\quad p = ${L.rate}`,
          `\\tilde{a}_j = \\frac{m_j \\cdot a_j}{1 - p}`,
        ],
        note: 'Randomly zeroes activations during training (inverted-dropout scaling keeps expectation constant). Inactive at inference.',
      });
    }
  });

  // Final loss step for context.
  if (isStage2) {
    steps.push({
      layerIdx: layers.length - 1,
      heading: 'Loss — sparse categorical cross-entropy',
      equations: [
        `\\mathcal{L}(\\mathbf{y}, \\hat{\\mathbf{p}}) = -\\sum_{k=1}^{13} y_k \\log \\hat{p}_k`,
        `\\theta \\leftarrow \\theta - \\eta\\, \\nabla_\\theta \\mathcal{L}`,
      ],
      note: 'Backprop minimises log-loss; Adam (η = 1e-3) updates the weights. Infiltration is excluded from Stage 2 by design.',
    });
  } else {
    steps.push({
      layerIdx: layers.length - 1,
      heading: 'Loss — binary cross-entropy',
      equations: [
        `\\mathcal{L}(y, \\hat{y}) = -\\bigl[\\,y \\log \\hat{y} + (1-y) \\log(1-\\hat{y})\\,\\bigr]`,
        `\\theta \\leftarrow \\theta - \\eta\\, \\nabla_\\theta \\mathcal{L}`,
      ],
      note: 'Backprop minimises BCE; Adam (η = 1e-3) updates the weights.',
    });
  }
  return steps;
}


function DNNViz() {
  const [stage, setStage] = useState('stage1');         // 'stage1' | 'stage2'
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState('normal');
  const layers = stage === 'stage1' ? DNN_LAYERS_STAGE1 : DNN_LAYERS_STAGE2;
  const steps = useMemo(() => buildDnnSteps(layers, stage === 'stage2'), [layers, stage]);

  const ms = speed === 'slow' ? 1500 : speed === 'fast' ? 600 : 1000;
  const intRef = useRef();

  useEffect(() => {
    if (!playing) return;
    intRef.current = setInterval(() => {
      setStep(prev => prev + 1 < steps.length ? prev + 1 : (setPlaying(false), prev));
    }, ms);
    return () => clearInterval(intRef.current);
  }, [playing, ms, steps.length]);

  const reset = () => { setStep(0); setPlaying(false); };
  useEffect(() => { reset(); }, [stage]);

  // SVG layout — each layer is a vertical column of small circles.
  const W = 880, H = 460, marginX = 50, marginY = 40;
  const colWidth = (W - 2 * marginX) / Math.max(layers.length - 1, 1);
  const layerColor = (kind) => ({
    input: '#00d4ff', dense: '#00d4ff', bn: '#aa66ff',
    dropout: '#ff9800', output: '#ff3b3b',
  }[kind] || '#888');
  const activeIdx = steps[step]?.layerIdx ?? 0;

  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
        <ToggleButtonGroup
          size="small" exclusive value={stage} onChange={(_, v) => v && setStage(v)}
          sx={{
            '& .MuiToggleButton-root': {
              color: '#888', borderColor: '#333', fontFamily: 'Share Tech Mono',
              '&.Mui-selected': { color: '#000', bgcolor: '#00d4ff' },
            },
          }}
        >
          <ToggleButton value="stage1">Stage 1 — Binary (sigmoid)</ToggleButton>
          <ToggleButton value="stage2">Stage 2 — 13-class (softmax)</ToggleButton>
        </ToggleButtonGroup>
        <Chip
          size="small"
          icon={<MemoryIcon sx={{ fontSize: 16 }} />}
          label={`${layers.reduce((acc, L, i) => i === 0 ? acc : acc + L.dim * (layers[i-1].dim || 0) + L.dim, 0).toLocaleString()} params (approx)`}
          sx={{ bgcolor: '#1a1a1a', color: '#aaa', border: '1px solid #333', fontFamily: 'Share Tech Mono' }}
        />
      </Stack>

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '2fr 1fr' }, gap: 2 }}>
        {/* SVG visualisation */}
        <Glass sx={{ minHeight: 500, position: 'relative' }}>
          <PlayControls
            playing={playing}
            onPlay={() => setPlaying(true)}
            onPause={() => setPlaying(false)}
            onStep={() => setStep(s => Math.min(s + 1, steps.length - 1))}
            onReset={reset}
            speed={speed} setSpeed={setSpeed}
          />
          <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H}
               style={{ background: 'radial-gradient(circle at 30% 30%, rgba(0,255,65,0.04), transparent 60%)' }}>
            {/* Connections between consecutive layers */}
            {layers.slice(0, -1).map((_, i) => {
              const x1 = marginX + i * colWidth;
              const x2 = marginX + (i + 1) * colWidth;
              return Array.from({ length: 6 }).map((__, j) => {
                const y1 = marginY + 30 + j * 60;
                const y2 = marginY + 30 + ((j + (i % 3)) % 6) * 60;
                const lit = i < activeIdx;
                return (
                  <line key={`${i}-${j}`} x1={x1} y1={y1} x2={x2} y2={y2}
                        stroke={lit ? layerColor(layers[i + 1].kind) : '#222'}
                        strokeOpacity={lit ? 0.7 : 0.4}
                        strokeWidth={lit ? 1.4 : 1} />
                );
              });
            })}
            {/* Layer columns */}
            {layers.map((L, i) => {
              const x = marginX + i * colWidth;
              const isActive = i === activeIdx;
              const isPast = i < activeIdx;
              const color = layerColor(L.kind);
              return (
                <g key={i}>
                  {Array.from({ length: 6 }).map((_, j) => {
                    const y = marginY + 30 + j * 60;
                    return (
                      <motion.circle
                        key={j}
                        cx={x} cy={y} r={isActive ? 10 : 8}
                        fill={isActive ? color : isPast ? color : '#0a0a0a'}
                        stroke={color}
                        strokeWidth={2}
                        animate={isActive ? { opacity: [0.5, 1, 0.5] } : { opacity: 1 }}
                        transition={{ duration: 1.2, repeat: isActive ? Infinity : 0 }}
                      />
                    );
                  })}
                  {L.dim > 6 && (
                    <text x={x} y={marginY + 30 + 6 * 60 + 4}
                          textAnchor="middle" fill="#666"
                          style={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}>
                      ⋮ ({L.dim})
                    </text>
                  )}
                  <text x={x} y={H - 18} textAnchor="middle" fill={isActive ? color : '#888'}
                        style={{ fontFamily: 'Share Tech Mono', fontSize: 12, fontWeight: 'bold' }}>
                    {L.label}
                  </text>
                  <text x={x} y={H - 4} textAnchor="middle" fill="#666"
                        style={{ fontFamily: 'Share Tech Mono', fontSize: 10 }}>
                    {L.act ? `${L.dim} • ${L.act}` : L.dim}
                  </text>
                  {isActive && (
                    <motion.circle
                      cx={x} cy={marginY + 12} r={6} fill={color}
                      initial={{ scale: 0 }} animate={{ scale: [0, 1.4, 1] }}
                      transition={{ duration: 0.6 }}
                    />
                  )}
                </g>
              );
            })}
          </svg>
        </Glass>

        <EquationPanel
          title={stage === 'stage1' ? 'DNN Stage 1' : 'DNN Stage 2'}
          steps={steps} currentStep={step}
        />
      </Box>
    </Box>
  );
}


// =====================================================================
// 2. XGBoost — sequential boosted trees, level-wise growth
// =====================================================================

const XGB_STEPS = [
  {
    heading: 'Initial prediction',
    equations: [
      `\\hat{y}_i^{(0)} = \\log\\!\\left(\\frac{p}{1 - p}\\right), \\quad p = \\frac{1}{N}\\sum_i y_i`,
    ],
    note: 'Boosting starts from the log-odds of the training-set base rate. All N samples receive the same initial prediction.',
  },
  {
    heading: 'Tree 1 — fit residuals',
    equations: [
      `g_i = \\partial_{\\hat{y}} \\mathcal{L}(y_i, \\hat{y}_i^{(0)}), \\quad h_i = \\partial^{2}_{\\hat{y}} \\mathcal{L}(y_i, \\hat{y}_i^{(0)})`,
      `\\mathrm{Gain} = \\tfrac{1}{2}\\!\\left[ \\frac{G_L^{2}}{H_L + \\lambda} + \\frac{G_R^{2}}{H_R + \\lambda} - \\frac{(G_L + G_R)^{2}}{H_L + H_R + \\lambda} \\right] - \\gamma`,
    ],
    note: 'Each potential split is scored with first / second-order gradients (g, h). XGBoost grows level-wise — every node at depth d is split before depth d+1.',
  },
  {
    heading: 'Tree 1 — leaf weights',
    equations: [
      `w_j = -\\frac{\\sum_{i \\in I_j} g_i}{\\sum_{i \\in I_j} h_i + \\lambda}`,
      `\\hat{y}_i^{(1)} = \\hat{y}_i^{(0)} + \\eta \\cdot f_1(\\mathbf{x}_i)`,
    ],
    note: 'Leaf values minimise the regularised second-order Taylor approximation of the loss. Predictions are updated with learning rate η.',
  },
  {
    heading: 'Tree 2 — fit new residuals',
    equations: [
      `g_i^{(2)} = \\partial_{\\hat{y}} \\mathcal{L}(y_i, \\hat{y}_i^{(1)}), \\quad h_i^{(2)} = \\partial^{2}_{\\hat{y}} \\mathcal{L}(y_i, \\hat{y}_i^{(1)})`,
      `f_2 = \\arg\\min_{f \\in \\mathcal{F}} \\sum_i \\!\\left[ g_i^{(2)} f(\\mathbf{x}_i) + \\tfrac{1}{2} h_i^{(2)} f(\\mathbf{x}_i)^{2} \\right] + \\Omega(f)`,
    ],
    note: 'Tree 2 is fit to the new residuals — i.e. what tree 1 still got wrong. Ω(f) penalises complexity (γ × leaves + ½λ‖w‖²).',
  },
  {
    heading: 'Tree 3 and beyond',
    equations: [
      `\\hat{y}_i^{(T)} = \\hat{y}_i^{(0)} + \\eta \\sum_{t=1}^{T} f_t(\\mathbf{x}_i)`,
    ],
    note: 'Each subsequent tree shrinks errors further. Final prediction is the η-scaled sum of all trees.',
  },
  {
    heading: 'Final inference (binary)',
    equations: [
      `P(\\text{Attack} \\mid \\mathbf{x}) = \\sigma(\\hat{y}^{(T)}(\\mathbf{x}))`,
    ],
    note: 'Stage 1 collapses the logit to P(Attack) via sigmoid. UDP-aware threshold then decides whether Stage 2 fires.',
  },
];


/**
 * Tiny pseudo-random tree shapes baked in for reproducibility. Each
 * tree's nodes are placed on a level-wise grid; XGBoost grows ALL
 * children at depth d before any at depth d+1.
 */
const XGB_TREES = [
  // Tree 1 (depth 3)
  { nodes: [{ d:0, p:0 }, { d:1, p:0 }, { d:1, p:1 }, { d:2, p:0 }, { d:2, p:1 }, { d:2, p:2 }, { d:2, p:3 }] },
  { nodes: [{ d:0, p:0 }, { d:1, p:0 }, { d:1, p:1 }, { d:2, p:0 }, { d:2, p:1 }, { d:2, p:2 }, { d:2, p:3 }] },
  { nodes: [{ d:0, p:0 }, { d:1, p:0 }, { d:1, p:1 }, { d:2, p:0 }, { d:2, p:1 }, { d:2, p:2 }, { d:2, p:3 }] },
];


function XGBoostViz() {
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState('normal');
  const ms = speed === 'slow' ? 1800 : speed === 'fast' ? 700 : 1200;
  const treeIdx = Math.min(Math.max(step - 1, 0), 2);

  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      setStep(prev => prev + 1 < XGB_STEPS.length ? prev + 1 : (setPlaying(false), prev));
    }, ms);
    return () => clearInterval(id);
  }, [playing, ms]);

  const W = 880, H = 460;
  const treeW = W / 3.2, gap = 20;

  return (
    <Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '2fr 1fr' }, gap: 2 }}>
        <Glass sx={{ minHeight: 540 }}>
          <PlayControls
            playing={playing}
            onPlay={() => setPlaying(true)}
            onPause={() => setPlaying(false)}
            onStep={() => setStep(s => Math.min(s + 1, XGB_STEPS.length - 1))}
            onReset={() => { setStep(0); setPlaying(false); }}
            speed={speed} setSpeed={setSpeed}
          />
          <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.8rem', mb: 1 }}>
            Level-wise growth — every node at depth d is split before depth d+1.
            Each tree is fit to the residuals of the previous tree.
          </Typography>
          <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H}
               style={{ background: 'radial-gradient(circle at 50% 30%, rgba(0,212,255,0.04), transparent 60%)' }}>
            {XGB_TREES.map((tree, ti) => {
              const x0 = ti * (treeW + gap) + 60;
              const isActive = ti === treeIdx && step > 0;
              const isPast = ti < treeIdx && step > 0;
              const color = ti === 0 ? '#00d4ff' : ti === 1 ? '#00d4ff' : '#aa66ff';
              const positions = tree.nodes.map(n => {
                const xPerLevel = treeW / Math.pow(2, n.d + 1);
                return {
                  x: x0 + xPerLevel * (n.p * 2 + 1),
                  y: 60 + n.d * 110,
                };
              });
              return (
                <g key={ti}>
                  {/* edges */}
                  {tree.nodes.map((n, i) => {
                    if (n.d === 0) return null;
                    const parentP = Math.floor(n.p / 2);
                    const parentIdx = tree.nodes.findIndex(m => m.d === n.d - 1 && m.p === parentP);
                    if (parentIdx === -1) return null;
                    return (
                      <motion.line
                        key={`e${i}`}
                        x1={positions[parentIdx].x} y1={positions[parentIdx].y}
                        x2={positions[i].x}        y2={positions[i].y}
                        stroke={(isActive || isPast) ? color : '#222'}
                        strokeWidth={2}
                        initial={{ pathLength: 0 }}
                        animate={{ pathLength: (isActive || isPast) ? 1 : 0 }}
                        transition={{ delay: 0.05 * i, duration: 0.45 }}
                      />
                    );
                  })}
                  {/* nodes */}
                  {tree.nodes.map((n, i) => (
                    <motion.circle
                      key={`n${i}`}
                      cx={positions[i].x} cy={positions[i].y}
                      r={n.d === 0 ? 14 : 11}
                      fill={(isActive || isPast) ? color : '#0a0a0a'}
                      stroke={color} strokeWidth={2}
                      initial={{ scale: 0 }}
                      animate={{ scale: (isActive || isPast) ? 1 : 0.4 }}
                      transition={{ delay: 0.06 * i, duration: 0.35 }}
                    />
                  ))}
                  <text x={x0 + treeW / 2} y={H - 14} textAnchor="middle" fill={color}
                        style={{ fontFamily: 'Share Tech Mono', fontSize: 13, fontWeight: 'bold' }}>
                    Tree {ti + 1}
                  </text>
                  <text x={x0 + treeW / 2} y={H - 30} textAnchor="middle" fill="#666"
                        style={{ fontFamily: 'Share Tech Mono', fontSize: 10 }}>
                    {ti === 0 ? 'fits y' : `fits residuals from T${ti}`}
                  </text>
                  {/* arrow to next tree */}
                  {ti < 2 && (isPast || isActive) && (
                    <motion.path
                      d={`M ${x0 + treeW + 4} ${H/2} L ${x0 + treeW + gap - 6} ${H/2}`}
                      stroke="#ff9800" strokeWidth={2}
                      markerEnd="url(#arrow)"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: isPast || isActive ? 1 : 0 }}
                      transition={{ delay: 0.6 }}
                    />
                  )}
                </g>
              );
            })}
            <defs>
              <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 0 L 10 5 L 0 10 z" fill="#ff9800" />
              </marker>
            </defs>
          </svg>
        </Glass>
        <EquationPanel title="XGBoost — Stage 1 binary classifier"
                       steps={XGB_STEPS} currentStep={step} />
      </Box>
    </Box>
  );
}


// =====================================================================
// 3. LightGBM — leaf-wise growth + histogram-based binning
// =====================================================================

const LGB_STEPS = [
  {
    heading: 'Histogram-based feature binning',
    equations: [
      `\\hat{x}_j = \\mathrm{bin}_k(x_j), \\quad k \\in \\{1, 2, \\ldots, 255\\}`,
    ],
    note: 'Each continuous feature is bucketed into ≤255 bins. Trees iterate over bin boundaries instead of all unique values — orders of magnitude faster on large data.',
  },
  {
    heading: 'Leaf-wise growth — pick the highest-gain leaf',
    equations: [
      `\\mathrm{Gain}_j = \\tfrac{1}{2}\\!\\left[ \\frac{G_L^{2}}{H_L + \\lambda} + \\frac{G_R^{2}}{H_R + \\lambda} - \\frac{(G_L + G_R)^{2}}{H_L + H_R + \\lambda} \\right]`,
      `j^{*} = \\arg\\max_{j \\in \\mathcal{L}_{\\text{leaves}}} \\mathrm{Gain}_j`,
    ],
    note: 'Unlike XGBoost (level-wise), LightGBM splits the SINGLE leaf with the highest gain anywhere in the tree. Lower loss per node, but the tree gets unbalanced.',
  },
  {
    heading: 'Iterate — keep splitting the best leaf',
    equations: [
      `\\text{repeat until } |\\mathcal{L}_{\\text{leaves}}| = \\texttt{num\\_leaves}`,
    ],
    note: 'LightGBM grows leaf-by-leaf until num_leaves is reached. This is asymmetric; max_depth is a soft cap to prevent overfitting on small datasets.',
  },
  {
    heading: 'Tree t — multiclass softmax loss',
    equations: [
      `\\mathcal{L}_{\\text{multi}} = -\\sum_{i=1}^{N} \\sum_{k=1}^{K} y_{i,k} \\log \\hat{p}_{i,k}, \\quad K = 14`,
      `g_{i,k}^{(t)} = \\hat{p}_{i,k}^{(t-1)} - y_{i,k}, \\quad h_{i,k}^{(t)} = \\hat{p}_{i,k}^{(t-1)} (1 - \\hat{p}_{i,k}^{(t-1)})`,
    ],
    note: 'Stage 2 in our project is multiclass — K=14 attack types (Infiltration retained for ML; excluded for DL). One booster head per class.',
  },
  {
    heading: 'Final inference — softmax over all trees',
    equations: [
      `\\hat{p}_k(\\mathbf{x}) = \\frac{e^{\\sum_t f_t^{(k)}(\\mathbf{x})}}{\\sum_{j=1}^{K} e^{\\sum_t f_t^{(j)}(\\mathbf{x})}}`,
    ],
    note: 'Predicted class = argmax over softmax(η Σ trees). new_to_old maps the head index back to the attack name via label_encoder.classes_.',
  },
];


/**
 * Step-by-step shape of a LightGBM tree where each step adds the
 * leaf with maximum gain (asymmetric growth). Indices used to render.
 */
const LGB_TREE_SEQ = [
  { d:0, p:0, parent: null },           // root
  { d:1, p:0, parent: 0 },              // split root → 2 leaves
  { d:1, p:1, parent: 0 },
  { d:2, p:1, parent: 2 },              // split right leaf
  { d:2, p:2, parent: 2 },              // (asymmetric: left leaf NOT split)
  { d:3, p:3, parent: 4 },              // split deepest leaf again
  { d:3, p:4, parent: 4 },
];


function LightGBMViz() {
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState('normal');
  const ms = speed === 'slow' ? 1800 : speed === 'fast' ? 700 : 1200;

  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      setStep(prev => prev + 1 < LGB_STEPS.length ? prev + 1 : (setPlaying(false), prev));
    }, ms);
    return () => clearInterval(id);
  }, [playing, ms]);

  // Tree growth pace — derived from the math step. Step 1 = root, step 2 = leaf-wise expansion.
  const visibleNodes = step <= 0 ? 0 : step === 1 ? 3 : step === 2 ? 5 : LGB_TREE_SEQ.length;

  const W = 880, H = 460;
  const histW = 280;
  const treeArea = { x: histW + 30, w: W - histW - 60 };

  // Histogram bars — fake but illustrative; demonstrate the binning concept.
  const bins = [3, 5, 8, 12, 18, 25, 30, 28, 22, 15, 10, 6, 4, 3, 2];
  const binMax = Math.max(...bins);

  // Tree node positions (depth-based).
  const nodePos = (n) => {
    const xPerLevel = treeArea.w / Math.pow(2, n.d + 1);
    return {
      x: treeArea.x + xPerLevel * (n.p * 2 + 1),
      y: 50 + n.d * 95,
    };
  };

  return (
    <Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '2fr 1fr' }, gap: 2 }}>
        <Glass sx={{ minHeight: 540 }}>
          <PlayControls
            playing={playing}
            onPlay={() => setPlaying(true)}
            onPause={() => setPlaying(false)}
            onStep={() => setStep(s => Math.min(s + 1, LGB_STEPS.length - 1))}
            onReset={() => { setStep(0); setPlaying(false); }}
            speed={speed} setSpeed={setSpeed}
          />
          <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.8rem', mb: 1 }}>
            Histogram-based binning (left) feeds leaf-wise asymmetric tree growth (right).
            Compare with XGBoost's level-wise growth in the previous tab.
          </Typography>
          <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H}
               style={{ background: 'radial-gradient(circle at 70% 30%, rgba(170,102,255,0.05), transparent 60%)' }}>
            {/* Histogram panel */}
            <rect x={20} y={30} width={histW} height={H - 80}
                  fill="rgba(170,102,255,0.04)" stroke="#aa66ff44" strokeWidth={1} rx={6} />
            <text x={20 + histW/2} y={22} textAnchor="middle" fill="#aa66ff"
                  style={{ fontFamily: 'Share Tech Mono', fontSize: 12, fontWeight: 'bold' }}>
              Feature histogram (binned)
            </text>
            {bins.map((v, i) => {
              const barW = (histW - 30) / bins.length;
              const barH = (v / binMax) * (H - 130);
              const x = 30 + i * barW;
              const y = H - 60 - barH;
              return (
                <motion.rect
                  key={i} x={x + 1} y={y} width={barW - 2} height={barH}
                  fill="#aa66ff"
                  initial={{ height: 0, y: H - 60 }}
                  animate={{ height: barH, y }}
                  transition={{ delay: 0.04 * i, duration: 0.4 }}
                  opacity={step >= 0 ? 0.9 : 0.3}
                />
              );
            })}
            <text x={20 + histW/2} y={H - 38} textAnchor="middle" fill="#888"
                  style={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}>
              ≤ 255 bins per feature
            </text>

            {/* Tree panel */}
            <text x={treeArea.x + treeArea.w/2} y={22} textAnchor="middle" fill="#00d4ff"
                  style={{ fontFamily: 'Share Tech Mono', fontSize: 12, fontWeight: 'bold' }}>
              Leaf-wise tree growth (asymmetric)
            </text>
            {/* edges */}
            {LGB_TREE_SEQ.map((n, i) => {
              if (i >= visibleNodes || n.parent === null) return null;
              const pPos = nodePos(LGB_TREE_SEQ[n.parent]);
              const cPos = nodePos(n);
              return (
                <motion.line key={`e${i}`}
                             x1={pPos.x} y1={pPos.y} x2={cPos.x} y2={cPos.y}
                             stroke="#00d4ff" strokeWidth={2}
                             initial={{ pathLength: 0 }}
                             animate={{ pathLength: 1 }}
                             transition={{ duration: 0.4 }} />
              );
            })}
            {/* nodes */}
            {LGB_TREE_SEQ.map((n, i) => {
              if (i >= visibleNodes) return null;
              const { x, y } = nodePos(n);
              const justAdded = i === visibleNodes - 1;
              return (
                <g key={`n${i}`}>
                  <motion.circle cx={x} cy={y} r={n.d === 0 ? 14 : 11}
                                 fill={justAdded ? '#ff9800' : '#00d4ff'}
                                 stroke="#00d4ff" strokeWidth={2}
                                 initial={{ scale: 0 }}
                                 animate={{ scale: 1 }}
                                 transition={{ duration: 0.35 }} />
                  {justAdded && (
                    <motion.circle cx={x} cy={y} r={20}
                                   fill="none" stroke="#ff9800" strokeWidth={2}
                                   initial={{ opacity: 0, scale: 0.5 }}
                                   animate={{ opacity: [0, 1, 0], scale: [0.5, 2, 2.5] }}
                                   transition={{ duration: 1.2, repeat: Infinity }} />
                  )}
                </g>
              );
            })}
            {visibleNodes > 0 && (
              <text x={treeArea.x + treeArea.w/2} y={H - 38} textAnchor="middle" fill="#888"
                    style={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}>
                {visibleNodes} / num_leaves
              </text>
            )}
          </svg>
        </Glass>
        <EquationPanel title="LightGBM — Stage 2 multiclass"
                       steps={LGB_STEPS} currentStep={step} />
      </Box>
    </Box>
  );
}


// =====================================================================
// Main page — tab selector + tab content
// =====================================================================

const TrainingViz = () => {
  const [tab, setTab] = useState(0);

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent',
               background: 'radial-gradient(ellipse at top, rgba(15,20,16,0.65), transparent 70%)',
               pt: 3, pb: 6 }}>
      <Container maxWidth="xl">
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
          <Box>
            <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                              fontSize: '2rem', fontWeight: 'bold' }}>
              How Models Learn
            </Typography>
            <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }}>
              Step-by-step animated walkthrough of every model in the PIDS pipeline,
              with the underlying mathematics rendered alongside each frame.
            </Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            <Chip icon={<DotIcon sx={{ fontSize: 16 }} />} label="Two-Stage DNN" size="small"
                  sx={{ bgcolor: '#00d4ff22', color: '#00d4ff', border: '1px solid #00d4ff',
                        fontFamily: 'Share Tech Mono' }} />
            <Chip icon={<TreeIcon sx={{ fontSize: 16 }} />} label="XGBoost + LightGBM" size="small"
                  sx={{ bgcolor: '#00d4ff22', color: '#00d4ff', border: '1px solid #00d4ff',
                        fontFamily: 'Share Tech Mono' }} />
          </Stack>
        </Stack>

        <Paper sx={{
          bgcolor: 'rgba(10, 18, 36, 0.55)',
          backdropFilter: 'blur(12px) saturate(1.05)',
          WebkitBackdropFilter: 'blur(12px) saturate(1.05)',
          border: '1px solid rgba(0, 212, 255, 0.15)',
          mb: 3,
        }}>
          <Tabs
            value={tab} onChange={(_, v) => setTab(v)}
            textColor="inherit"
            TabIndicatorProps={{ style: { backgroundColor: '#00d4ff', height: 3 } }}
            sx={{
              '& .MuiTab-root': {
                color: '#888', fontFamily: 'Share Tech Mono', fontWeight: 'bold',
                '&.Mui-selected': { color: '#00d4ff' },
              },
            }}
          >
            <Tab label="Two-Stage DNN" />
            <Tab label="XGBoost (Stage 1)" />
            <Tab label="LightGBM (Stage 2)" />
          </Tabs>
        </Paper>

        <Box>
          {tab === 0 && <DNNViz />}
          {tab === 1 && <XGBoostViz />}
          {tab === 2 && <LightGBMViz />}
        </Box>

        <Paper sx={{ mt: 3, p: 2, bgcolor: 'rgba(0, 212, 255, 0.06)',
                     border: '1px solid #00d4ff44' }}>
          <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                            fontSize: '0.85rem', mb: 1, fontWeight: 'bold' }}>
            Why DNN (not CNN) for tabular flow features?
          </Typography>
          <Typography sx={{ color: '#aaa', fontFamily: 'Share Tech Mono', fontSize: '0.8rem',
                            lineHeight: 1.6 }}>
            Convolutional layers exploit <em>spatial locality</em> — pixels next to each other are
            related. Flow features (Dst Port, IAT Mean, Flag Counts, …) have no such ordering;
            permuting columns doesn't change their meaning. A fully-connected DNN treats every
            feature pair as potentially interacting, which matches the underlying data. CNN here
            would either ignore that prior or impose a fake one. We use CNN only in the comparative
            literature analysis to show this same conclusion.
          </Typography>
        </Paper>
      </Container>
    </Box>
  );
};

export default TrainingViz;

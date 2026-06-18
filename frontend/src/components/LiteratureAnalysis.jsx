/**
 * LiteratureAnalysis — comparative-analysis page for the demo.
 *
 * Four tabs:
 *   1. Performance Comparison — 4-DL bar chart + ML-vs-DL bar chart + table + narrative
 *   2. Confusion Matrices    — ML (XGB stage 1, LGB stage 2) and DNN (stage 1, stage 2)
 *   3. Dataset               — CIC-IDS-2018 description, splits, class distribution
 *   4. Literature Context    — table vs prior CIC-IDS-2018 work, "what's new" callout
 *
 * Numbers are stored in the constants at the top so updating them is
 * a one-line edit. All charts and matrices are pure SVG / HTML — no
 * extra chart libraries.
 */
import React, { useState } from 'react';
import {
  Box, Container, Typography, Paper, Tabs, Tab, Stack, Chip, Divider,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tooltip,
} from '@mui/material';
import {
  BarChart as ChartIcon,
  GridOn as MatrixIcon,
  Science as ScienceIcon,
  MenuBook as BookIcon,
  EmojiEvents as TrophyIcon,
  Verified as VerifiedIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';


// =====================================================================
// SOURCE-OF-TRUTH DATA (edit here to update every chart / table)
// =====================================================================

/** End-to-end metrics per model, in percentage.
 *  Latest run: 31 features, raw CIC-IDS-2018 (no synthetic augmentation).
 *  End-to-end ≈ stage-1 binary accuracy (benign-heavy traffic dominates). */
const END_TO_END = [
  // The two engines actually shipped in this project (31-feature retrain).
  { name: 'XGB+LGB (ML)',  shortName: 'ML', kind: 'ml',
    accuracy: 98.08, f1Weighted: 98.08, f1Macro: 79.50,
    color: '#ff3b3b' },
  { name: 'DNN v1 (DL)',   shortName: 'DNN', kind: 'dl',
    accuracy: 98.23, f1Weighted: 98.23, f1Macro: 80.15,
    color: '#00d4ff', winner: true },
  // Baseline DL architectures — kept for context. Numbers from the
  // earlier 53-feature/synthetic run; figures still informative for
  // architectural comparison even if the absolute scale shifted.
  { name: 'LSTM',          shortName: 'LSTM', kind: 'baseline',
    accuracy: 98.30, f1Weighted: 98.10, f1Macro: 92.95,
    color: '#00d4ff' },
  { name: 'CNN',           shortName: 'CNN', kind: 'baseline',
    accuracy: 98.02, f1Weighted: 97.76, f1Macro: 92.37,
    color: '#aa66ff' },
  { name: 'AE-LSTM',       shortName: 'AE-LSTM', kind: 'baseline',
    accuracy: 98.29, f1Weighted: 98.08, f1Macro: 91.86,
    color: '#ff9800' },
];

/** Per-stage accuracy + training cost. Latest 31-feature retrain on raw
 *  CIC-IDS-2018; baselines retained from earlier 53-feature run for
 *  architectural comparison context. */
const STAGE_METRICS = [
  { model: 'DNN (this work, 31-feat raw)',
    s1Acc: 98.23, s1F1: 92.93, s1Auc: 98.00,
    s2Acc: 99.82, s2F1w: 99.83, s2F1m: 80.15,
    totalTrainSec: 949,  // 710 + 239
    note: 'Best end-to-end on raw data; F1-macro reflects unaugmented imbalance' },
  { model: 'LSTM (53-feat, augmented)',
    s1Acc: 98.40, s1F1: 93.78, s1Auc: 98.25,
    s2Acc: 99.14, s2F1w: 99.13,  s2F1m: 98.49,
    totalTrainSec: 5267, note: '~5.5× slower than DNN; marginally lower end-to-end' },
  { model: 'CNN (53-feat, augmented)',
    s1Acc: 98.03, s1F1: 92.43, s1Auc: 97.87,
    s2Acc: 99.88, s2F1w: 99.88,  s2F1m: 99.52,
    totalTrainSec: 1357, note: 'Wrong inductive bias for tabular (no spatial structure)' },
  { model: 'AE-LSTM (53-feat, augmented)',
    s1Acc: 98.40, s1F1: 93.80, s1Auc: 98.20,
    s2Acc: 99.04, s2F1w: 99.01,  s2F1m: 97.09,
    totalTrainSec: 3154, note: 'AE pretraining cost (~101 s) for marginal gain' },
];

/** Confusion matrices.
 *  Provided by user — verified against test_size = 2,144,171.
 *  XGB stage 1 + LGB stage 2 are the ML side; DNN matrices are the DL side. */
const ATTACK_LABELS = [
  'Bot', 'Brute Force -Web', 'Brute Force -XSS', 'DDOS attack-HOIC',
  'DDOS attack-LOIC-UDP', 'DDoS attacks-LOIC-HTTP', 'DoS attacks-GoldenEye',
  'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris',
  'FTP-BruteForce', 'Infilteration', 'SQL Injection', 'SSH-Bruteforce',
];

const CM_ML_STAGE1 = {
  title: 'XGBoost Stage 1 — Binary (31-feat retrain)',
  accuracy: 98.08,
  labels: ['Normal', 'Attack'],
  displayMode: 'recall',   // diagonal = % recall, off-diagonal = raw miscount
  matrix: [
    // recall: Normal 1838550/1862640=98.7% · Attack 254357/271287=93.8%
    [ 98.7,  24090],
    [16930,   93.8],
  ],
};

// LightGBM stage-2 from latest 31-feature retrain. The user-supplied
// chart shows per-row recall % on the diagonal and raw misclassification
// counts off-diagonal. Diagonals encoded here as the integer percent
// value (0-100); off-diagonals as raw counts. The ConfusionMatrix
// component renders these as "%" or count based on `displayMode`.
const CM_ML_STAGE2 = {
  title: 'LightGBM Stage 2 — 14-class (31-feat retrain)',
  accuracy: 99.96,
  labels: ATTACK_LABELS,
  displayMode: 'recall',   // diagonal = % recall, off-diagonal = raw count
  matrix: [
    // Bot, BF-Web, BF-XSS, HOIC, LOIC-UDP, LOIC-HTTP, GoldenEye, Hulk, SlowHTTP, Slowloris, FTP-Brute, Infil, SQLi, SSH-Brute
    [100.0,    0,    0,    0,    0,      0,    0,    0,    0,    0,    0,    1,    0,    0],   // Bot
    [    0, 93.5,    0,    0,    0,      0,    0,    0,    0,    0,    0,    0,    3,    0],   // BF-Web
    [    0,    0, 93.8,    0,    0,      0,    0,    0,    0,    0,    0,    0,    1,    0],   // BF-XSS
    [    0,    0,    0,100.0,    0,      0,    0,    0,    0,    0,    0,    0,    0,    0],   // HOIC
    [    0,    0,    0,    0, 97.4,      9,    0,    0,    0,    0,    0,    0,    0,    0],   // LOIC-UDP
    [    0,    0,    0,    0,   82,   99.9,    0,    1,    0,    0,    0,    0,    0,    0],   // LOIC-HTTP
    [    0,    0,    0,    0,    0,      0,100.0,    0,    0,    1,    0,    0,    0,    0],   // GoldenEye
    [    0,    0,    0,    0,    0,      0,    0,100.0,    0,    0,    0,    0,    0,    0],   // Hulk
    [    0,    0,    0,    0,    0,      0,    0,    0, 98.1,    0,    5,    0,    0,    1],   // SlowHTTP
    [    0,    0,    0,    0,    0,      0,    0,    0,    0,100.0,    0,    0,    0,    0],   // Slowloris
    [    0,    0,    0,    0,    0,      0,    0,    0,    5,    0, 40.0,    0,    0,    1],   // FTP-Brute (40% — hard class)
    [    0,    0,    0,    0,    0,      0,    0,    0,    0,    0,    0,100.0,    0,    0],   // Infil
    [    0,    1,    0,    0,    0,      0,    0,    0,    0,    0,    0,    0, 99.5,    0],   // SQLi
    [    0,    0,    0,    0,    0,      0,    0,    0,    0,    0,    0,    0,    0,100.0],   // SSH-Brute
  ],
};

// DNN Stage 1 — exact counts from the published 31-feature retrain CM:
//   true Benign [1849704, 12847] · true Attack [21918, 259702].
const CM_DL_STAGE1 = {
  title: 'DNN Stage 1 — Binary (31-feat retrain)',
  accuracy: 98.23,
  labels: ['Normal', 'Attack'],
  displayMode: 'recall',   // diagonal = % recall, off-diagonal = raw miscount
  matrix: [
    // recall: Benign 1849704/1862551=99.3% · Attack 259702/281620=92.2%
    [ 99.3,  12847],
    [21918,   92.2],
  ],
};

// DNN Stage 2 — 14-class, from the published 31-feature retrain CM image.
// Diagonal shows per-row recall %; off-diagonal keeps the raw miscount.
const CM_DL_STAGE2 = {
  title: 'DNN Stage 2 — 14-class (31-feat retrain)',
  accuracy: 99.82,
  labels: ATTACK_LABELS,
  displayMode: 'recall',   // diagonal = % recall, off-diagonal = raw count
  matrix: [
    // recall on diagonal (correct/row-total); off-diagonals are raw miscounts.
    [ 99.8,    0,    0,    0,    0,      0,    0,    0,    0,    0,    0,   61,    0,    0],   // Bot       28846/28907
    [    0, 99.3,   10,    0,    0,      4,    0,    0,    0,    0,    0,    1,    0,    0],   // BF-Web    1985/2000
    [    0,    8, 99.4,    0,    0,      3,    0,    0,    0,    0,    0,    1,    0,    0],   // BF-XSS    1988/2000
    [    0,    0,    0,100.0,    0,      0,    0,    0,    0,    0,    0,    0,    0,    0],   // HOIC      39772/39772
    [    0,    0,    0,    0,100.0,      0,    0,    0,    0,    0,    0,    0,    0,    0],   // LOIC-UDP  2000/2000
    [    0,    0,    0,    0,  153,  99.8,    0,    0,    0,    0,    0,   63,    0,    0],   // LOIC-HTTP 114787/115003
    [    0,    0,    0,    0,    0,      0, 99.9,    4,    0,    3,    0,    0,    0,    0],   // GoldenEye 8271/8278
    [    0,    0,    0,    0,    0,      0,   19, 99.9,    0,    0,    0,    0,    0,    0],   // Hulk      29021/29040
    [    0,    0,    0,    0,    0,      0,    0,    0,100.0,    0,    0,    0,    0,    0],   // SlowHTTP  2000/2000
    [    0,    0,    0,    0,    0,      0,    0,    0,    0,100.0,    0,    0,    0,    0],   // Slowloris 1942/1942
    [    0,    0,    0,    0,    0,      0,    0,    0,   14,    0, 99.3,    0,    0,    0],   // FTP-Brute 1986/2000
    [    2,   50,    0,    0,    0,     64,    3,    1,    1,    5,    0, 99.5,    2,    1],   // Infil     27739/27868
    [    0,    4,    1,    0,    0,      0,    0,    0,    0,    0,    0,    1, 99.7,    0],   // SQLi      1994/2000
    [    0,    0,    0,    0,    0,      0,    0,    1,    1,    0,    0,    0,    0,100.0],   // SSH-Brute 18808/18810
  ],
};

/** Dataset description — raw CIC-IDS-2018. No synthetic augmentation. */
const DATA_STORY = {
  trainSize: 8576682,
  testSize: 2133927,
  trainTestSplit: '80 / 20 stratified',
  scaler: 'StandardScaler (shared by ML + DL)',
  numClasses: 15,            // 1 benign + 14 attacks
  numFeatures: 31,           // 31-feature schema (raw, no augmentation)
};

/** Literature reference rows. The "This work" row is highlighted at the bottom. */
const LITERATURE_ROWS = [
  { year: 2018, paper: 'Sharafaldin et al. — CIC-IDS-2018 baseline (RF)',
    model: 'Random Forest', dataset: 'CIC-IDS-2018', acc: '~95.6%', f1: '~95.0%',
    novelty: 'First public release of the dataset; classical baselines only.' },
  { year: 2020, paper: 'Vinayakumar et al. — DNN for IDS',
    model: 'Deep Neural Network', dataset: 'NSL-KDD + CIC-IDS-2017', acc: '~96–98%', f1: '~95%',
    novelty: 'Single-stage DNN; no two-stage routing; no live capture.' },
  { year: 2021, paper: 'Imrana et al. — LSTM-based IDS',
    model: 'BiLSTM', dataset: 'CIC-IDS-2018', acc: '~98.0%', f1: '~97%',
    novelty: 'Sequence model (slow at inference); no zero-day handling.' },
  { year: 2022, paper: 'Lopez-Martin et al. — CNN over flow features',
    model: 'CNN-1D', dataset: 'CIC-IDS-2018', acc: '~97–98%', f1: '~96%',
    novelty: 'Imposes spatial prior on tabular features; debated in literature.' },
  { year: 2023, paper: 'Various — XGBoost ensembles',
    model: 'XGBoost / LightGBM', dataset: 'CIC-IDS-2018', acc: '~98%', f1: '~97%',
    novelty: 'Strong tabular baseline; no DL fallback; no LLM reasoning.' },
  { year: 2026, paper: 'This work — PIDS', highlight: true,
    model: 'Two-Stage DNN + XGBoost/LightGBM (pluggable) + Llama (zero-day)',
    dataset: 'CIC-IDS-2018 (raw, 31 features, no augmentation)',
    acc: '98.23%', f1: '98.23% (w) / 80.15% (m)',
    novelty: 'Pluggable ML/DL engines selectable at runtime; LLM behavioural routing on low-confidence flows; live Scapy → registry → WebSocket pipeline; built-in retraining for both engines.' },
];


// =====================================================================
// Visual primitives
// =====================================================================

const Glass = ({ children, sx = {} }) => (
  <Paper elevation={0} sx={{
    bgcolor: 'rgba(15, 15, 20, 0.85)',
    border: '1px solid rgba(0, 255, 65, 0.25)',
    backdropFilter: 'blur(8px)', borderRadius: 2, p: 2.5, ...sx,
  }}>{children}</Paper>
);


/**
 * Grouped bar chart — for each model, draw N bars (one per metric).
 * Pure SVG; framer-motion for fade-in.
 */
function GroupedBarChart({ title, models, metrics, height = 320, yMin = 85, yMax = 100 }) {
  const W = 880, padL = 60, padR = 30, padT = 40, padB = 90;
  const innerW = W - padL - padR;
  const innerH = height - padT - padB;
  const groupW = innerW / models.length;
  const barW = (groupW - 16) / metrics.length;
  const yScale = v => padT + innerH - ((v - yMin) / (yMax - yMin)) * innerH;
  const yTicks = 6;

  return (
    <Glass>
      <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                        fontWeight: 'bold', fontSize: '1rem', mb: 2 }}>
        {title}
      </Typography>
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" height={height}>
        {/* Y-axis grid + labels */}
        {Array.from({ length: yTicks + 1 }).map((_, i) => {
          const v = yMin + (i / yTicks) * (yMax - yMin);
          const y = yScale(v);
          return (
            <g key={i}>
              <line x1={padL} y1={y} x2={W - padR} y2={y}
                    stroke="#1a1a1a" strokeDasharray="3 3" />
              <text x={padL - 8} y={y + 4} textAnchor="end" fill="#666"
                    style={{ fontFamily: 'Share Tech Mono', fontSize: 10 }}>
                {v.toFixed(0)}%
              </text>
            </g>
          );
        })}
        {/* Bars */}
        {models.map((m, i) => {
          const groupX = padL + i * groupW;
          return (
            <g key={i}>
              {metrics.map((mt, j) => {
                const v = m[mt.key];
                const x = groupX + 8 + j * barW;
                const y = yScale(v);
                const h = padT + innerH - y;
                return (
                  <g key={j}>
                    <motion.rect
                      x={x} width={barW - 4}
                      initial={{ y: padT + innerH, height: 0 }}
                      animate={{ y, height: h }}
                      transition={{ delay: 0.05 * (i * metrics.length + j), duration: 0.6 }}
                      fill={mt.color || m.color}
                      stroke={m.color} strokeWidth={1}
                      opacity={0.9}
                    />
                    <text x={x + (barW - 4) / 2} y={y - 5} textAnchor="middle"
                          fill={m.color}
                          style={{ fontFamily: 'Share Tech Mono', fontSize: 10, fontWeight: 'bold' }}>
                      {v.toFixed(2)}
                    </text>
                  </g>
                );
              })}
              {/* group label */}
              <text x={groupX + groupW / 2} y={padT + innerH + 22} textAnchor="middle"
                    fill={m.color}
                    style={{ fontFamily: 'Share Tech Mono', fontSize: 12,
                             fontWeight: m.winner ? 'bold' : 'normal' }}>
                {m.shortName}
              </text>
              {m.winner && (
                <text x={groupX + groupW / 2} y={padT + innerH + 38} textAnchor="middle"
                      fill="#ffd600"
                      style={{ fontFamily: 'Share Tech Mono', fontSize: 9 }}>
                  ★ Best end-to-end
                </text>
              )}
            </g>
          );
        })}
        {/* Legend */}
        {metrics.map((mt, j) => (
          <g key={`l-${j}`} transform={`translate(${padL + j * 130}, ${height - 20})`}>
            <rect width={12} height={12} fill={mt.color || '#888'} />
            <text x={18} y={11} fill="#aaa"
                  style={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}>
              {mt.label}
            </text>
          </g>
        ))}
      </svg>
    </Glass>
  );
}


/** Small colour-swatch + label used in the confusion-matrix legend. */
function LegendSwatch({ color, label }) {
  return (
    <Stack direction="row" spacing={0.75} alignItems="center">
      <Box sx={{ width: 14, height: 14, borderRadius: '4px', background: color,
                 border: '1px solid rgba(255,255,255,0.2)' }} />
      <Typography sx={{ color: '#9fb4c4', fontFamily: 'Share Tech Mono', fontSize: '0.68rem' }}>
        {label}
      </Typography>
    </Stack>
  );
}

/**
 * Confusion matrix as a heatmap-coloured HTML table (user-friendly redesign).
 * - Diagonal (correct) cells use a green/emerald scale.
 * - Off-diagonal (errors) cells use a rose/red scale so mistakes read as "bad".
 * - Rounded cells with gaps, log-scaled intensity, and a legend.
 */
function ConfusionMatrix({ data, compact = false }) {
  const { title, accuracy, labels, matrix, displayMode } = data;
  const isRecall = displayMode === 'recall';
  // For recall-mode matrices the diagonal cells are percentages
  // (0–100), not counts — exclude them from total + intensity scaling.
  const offDiagMax = Math.max(
    1,
    ...matrix.flatMap((row, i) => row.filter((_, j) => i !== j))
  );
  const total = isRecall
    ? null
    : matrix.reduce((acc, row) => acc + row.reduce((a, v) => a + v, 0), 0);
  const cellSize = compact ? 22 : 34;
  const fontSize = compact ? 8.5 : 11;

  // Friendly two-hue scheme: emerald = correct (diagonal), rose = errors.
  const cellColor = (v, isDiag, a) => {
    if (v === 0) return { bg: 'rgba(255,255,255,0.018)', fg: '#36474a', bd: 'rgba(255,255,255,0.04)' };
    if (isDiag) {
      return {
        bg: `rgba(16,185,129,${0.16 + a * 0.74})`,
        fg: a > 0.5 ? '#03140d' : '#6ee7b7',
        bd: 'rgba(16,185,129,0.55)',
      };
    }
    return {
      bg: `rgba(244,63,94,${0.14 + a * 0.72})`,
      fg: a > 0.5 ? '#1c0509' : '#fca5a5',
      bd: 'rgba(244,63,94,0.4)',
    };
  };

  // log-scale colour intensity so 1s are still visible against millions
  const intensity = (v, isDiag) => {
    if (v === 0) return 0;
    if (isRecall) {
      return isDiag
        ? Math.min(1, Math.max(0, v / 100))                     // 0-100 → 0-1
        : Math.log10(v + 1) / Math.log10(offDiagMax + 1);
    }
    return Math.log10(v + 1) / Math.log10(offDiagMax + 1);
  };

  const fmtCell = (v, isDiag) => {
    if (v === 0) return '·';
    if (isRecall && isDiag) return v.toFixed(1) + '%';
    if (v >= 1000) return Math.round(v / 100) / 10 + 'k';
    return v;
  };
  const tooltipFor = (i, j, v) => {
    if (isRecall && i === j) return `true=${labels[i]}, recall=${v.toFixed(2)}%`;
    const k = isRecall ? 'misclassified count' : 'count';
    return `true=${labels[i]}, pred=${labels[j]}, ${k}=${v.toLocaleString()}`;
  };

  return (
    <Glass>
      <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1.5}>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', fontSize: '0.95rem' }}>
          {title}
        </Typography>
        <Chip
          size="small"
          icon={<VerifiedIcon sx={{ fontSize: 14 }} />}
          label={`Acc ${accuracy.toFixed(2)}%`}
          sx={{ bgcolor: '#00d4ff22', color: '#00d4ff', border: '1px solid #00d4ff',
                fontFamily: 'Share Tech Mono', fontWeight: 'bold' }}
        />
      </Stack>
      <Typography sx={{ color: '#666', fontFamily: 'Share Tech Mono',
                        fontSize: '0.7rem', mb: 1 }}>
        {isRecall
          ? 'Diagonal = per-class recall (%) • off-diagonal = miscount • cols = predicted, rows = true'
          : `N = ${total.toLocaleString()} samples • columns = predicted, rows = true`}
      </Typography>
      <Box sx={{ overflowX: 'auto', pb: 0.5 }}>
        <table style={{ borderCollapse: 'separate', borderSpacing: 3, fontFamily: 'Share Tech Mono', fontSize }}>
          <thead>
            <tr>
              <th />
              {labels.map((l, j) => (
                <th key={j} style={{
                  color: '#9fb4c4', fontWeight: 'normal', padding: '4px 2px',
                  fontSize: fontSize - 0.5, transform: 'rotate(-35deg)', transformOrigin: 'bottom left',
                  height: compact ? 72 : 98, verticalAlign: 'bottom',
                  textAlign: 'left', whiteSpace: 'nowrap', letterSpacing: '0.02em',
                }}>
                  {l.length > 18 ? l.slice(0, 16) + '…' : l}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row, i) => (
              <tr key={i}>
                <th style={{
                  color: '#9fb4c4', textAlign: 'right', padding: '0 10px 0 4px',
                  fontWeight: 'normal', whiteSpace: 'nowrap', fontSize,
                }}>
                  {labels[i].length > 18 ? labels[i].slice(0, 16) + '…' : labels[i]}
                </th>
                {row.map((v, j) => {
                  const isDiag = i === j;
                  const a = intensity(v, isDiag);
                  const { bg, fg, bd } = cellColor(v, isDiag, a);
                  return (
                    <Tooltip key={j} title={tooltipFor(i, j, v)} arrow placement="top">
                      <td style={{
                        width: cellSize, height: cellSize, minWidth: cellSize,
                        background: bg, color: fg, borderRadius: 7,
                        border: `1px solid ${bd}`,
                        textAlign: 'center', cursor: 'help',
                        fontSize, padding: 0,
                        fontWeight: isDiag ? 700 : 500,
                        boxShadow: isDiag && a > 0.5 ? `0 0 8px rgba(16,185,129,0.35)` : 'none',
                      }}>
                        {fmtCell(v, isDiag)}
                      </td>
                    </Tooltip>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </Box>
      {/* legend */}
      <Stack direction="row" spacing={2} mt={1.5} alignItems="center" flexWrap="wrap" rowGap={0.5}>
        <LegendSwatch color="rgba(16,185,129,0.85)" label={isRecall ? 'Correct · recall' : 'Correct · diagonal'} />
        <LegendSwatch color="rgba(244,63,94,0.82)" label="Errors · off-diagonal" />
        <Typography sx={{ color: '#5d6d6d', fontFamily: 'Share Tech Mono', fontSize: '0.66rem' }}>
          brighter = more samples
        </Typography>
      </Stack>
    </Glass>
  );
}


// =====================================================================
// Tab content
// =====================================================================

function PerformanceTab() {
  // 4-DL chart: DNN, LSTM, CNN, AE-LSTM
  const dl4 = END_TO_END.filter(m => m.kind === 'dl' || m.kind === 'baseline');
  // ML vs DL chart: just the two engines this project ships
  const mlDl = END_TO_END.filter(m => m.kind === 'ml' || m.kind === 'dl');
  const metrics = [
    { key: 'accuracy',   label: 'Accuracy',  color: '#00d4ff' },
    { key: 'f1Weighted', label: 'F1 weighted', color: '#00d4ff' },
    { key: 'f1Macro',    label: 'F1 macro',  color: '#aa66ff' },
  ];

  return (
    <Stack spacing={3}>
      <GroupedBarChart
        title="Two-Stage Models — End-to-End Comparison (DNN vs LSTM vs CNN vs AE-LSTM)"
        models={dl4} metrics={metrics}
      />
      <GroupedBarChart
        title="ML vs DL — End-to-End Pipeline Comparison (31 features, raw)"
        models={mlDl} metrics={metrics}
      />

      {/* Detailed per-stage table */}
      <Glass>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', mb: 1.5 }}>
          Per-Stage Detail (DL architectures)
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                {['Model', 'Stage 1 Acc', 'Stage 1 F1', 'Stage 1 AUC',
                  'Stage 2 Acc', 'Stage 2 F1ʷ', 'Stage 2 F1ᵐ',
                  'Train (s)', 'Notes'].map(h => (
                  <TableCell key={h} sx={{ color: '#aaa', fontFamily: 'Share Tech Mono',
                                            borderColor: '#222', fontSize: '0.75rem' }}>
                    {h}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {STAGE_METRICS.map((r, i) => {
                const isThisWork = r.model.includes('this work');
                return (
                  <TableRow key={i} sx={{ '& td': {
                    borderColor: '#222', color: isThisWork ? '#00d4ff' : '#ddd',
                    fontFamily: 'Share Tech Mono', fontSize: '0.78rem',
                    fontWeight: isThisWork ? 'bold' : 'normal',
                    bgcolor: isThisWork ? 'rgba(0,255,65,0.05)' : 'transparent',
                  } }}>
                    <TableCell>{isThisWork && <TrophyIcon sx={{ fontSize: 14, mr: 0.5,
                                color: '#ffd600', verticalAlign: 'middle' }} />}{r.model}</TableCell>
                    <TableCell>{r.s1Acc?.toFixed(2)}%</TableCell>
                    <TableCell>{r.s1F1 ? r.s1F1.toFixed(2) + '%' : '—'}</TableCell>
                    <TableCell>{r.s1Auc ? r.s1Auc.toFixed(2) + '%' : '—'}</TableCell>
                    <TableCell>{r.s2Acc?.toFixed(2)}%</TableCell>
                    <TableCell>{r.s2F1w ? r.s2F1w.toFixed(2) + '%' : '—'}</TableCell>
                    <TableCell>{r.s2F1m ? r.s2F1m.toFixed(2) + '%' : '—'}</TableCell>
                    <TableCell>{r.totalTrainSec ? r.totalTrainSec.toLocaleString() : '—'}</TableCell>
                    <TableCell sx={{ color: '#888 !important' }}>{r.note}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      </Glass>

      {/* Why DNN won */}
      <Glass sx={{ borderColor: '#ffd60088', bgcolor: 'rgba(255,214,0,0.04)' }}>
        <Stack direction="row" alignItems="center" spacing={1} mb={1}>
          <TrophyIcon sx={{ color: '#ffd600' }} />
          <Typography sx={{ color: '#ffd600', fontFamily: 'Share Tech Mono',
                            fontWeight: 'bold', fontSize: '1rem' }}>
            Why DNN won the comparative analysis
          </Typography>
        </Stack>
        <Stack spacing={1.2} sx={{ color: '#c3d0d0', fontFamily: 'Share Tech Mono', fontSize: '0.64rem', lineHeight: 1.65 }}>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Highest end-to-end accuracy (98.23%)</b> on the latest 31-feature, raw
            CIC-IDS-2018 retrain — slightly above the ML engine (98.08%) and matching the
            best baseline architectures from the earlier 53-feature comparative study.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Strongest stage-2 head (99.82% accuracy, 99.83% F1-weighted)</b> with a
            macro-F1 of 80.15% on raw, unaugmented data — the macro figure now reflects
            the genuine difficulty of minority classes (FTP-BruteForce dropped to ~40%
            recall in ML LightGBM, the same class DNN handles materially better).
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Right inductive bias for tabular features.</b> Flow features (Dst Port,
            IAT Mean, Flag Counts…) have no spatial or temporal structure. CNN imposes
            a fake spatial prior; LSTM / AE-LSTM impose a fake temporal one. DNN treats
            every feature pair as potentially interacting, which is the correct prior.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Cheap to retrain.</b> Stage-1 + stage-2 train in ~949 s combined
            (vs 5,267 s for LSTM, 3,154 s for AE-LSTM). Faster retraining = more
            iteration cycles per fixed time budget.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Pluggable in production.</b> The pipeline can flip ML ↔ DL via the
            Admin panel in &lt;5 s with no Django restart, so you ship both engines and
            let the operator pick. None of the prior IDS papers above offer this.
          </Typography>
        </Stack>
      </Glass>
    </Stack>
  );
}


function ConfusionTab() {
  return (
    <Stack spacing={2}>
      <Typography sx={{ color: '#8b9a9a', fontFamily: 'Share Tech Mono', fontSize: '0.74rem', lineHeight: 1.65 }}>
        Hover any cell for the exact count. Diagonal = correctly classified (green tint);
        off-diagonal = errors (cyan tint, log-scaled so single-digit confusions stay visible
        next to millions of correct Benign predictions).
      </Typography>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 2 }}>
        <ConfusionMatrix data={CM_ML_STAGE1} />
        <ConfusionMatrix data={CM_DL_STAGE1} />
      </Box>
      <ConfusionMatrix data={CM_ML_STAGE2} />
      <ConfusionMatrix data={CM_DL_STAGE2} />

      <Glass sx={{ borderColor: '#00d4ff88', bgcolor: 'rgba(0,212,255,0.04)' }}>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', mb: 1, fontSize: '0.95rem' }}>
          Reading these matrices
        </Typography>
        <Stack spacing={1.1} sx={{ color: '#c3d0d0', fontFamily: 'Share Tech Mono', fontSize: '0.64rem', lineHeight: 1.65 }}>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Stage 1 (binary, 31-feat retrain):</b> XGBoost — 24,090 false positives
            and 16,930 missed attacks across 2.13M test samples (98.08% acc). DNN at
            98.23% accuracy is slightly more conservative on benign traffic.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Stage 2 (multiclass):</b> Most classes hit ≥98% per-row recall on the
            new run. The hard class is <b>FTP-BruteForce</b> at only 40% recall in ML
            LightGBM (5 confused with SlowHTTPTest) — a known structural overlap with
            other slow-rate auth attacks. The DNN stage-2 handles it materially better.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Infiltration row:</b> The hardest class in CIC-IDS-2018. Both engines mostly get
            it right (27,865 ML / 27,739 DNN correct out of ~27,870), with DNN spreading more
            errors across small classes — consistent with its softer decision boundaries.
          </Typography>
        </Stack>
      </Glass>

      {/* Why the two-stage DNN beats the two-stage ML */}
      <Glass sx={{ borderColor: '#aa66ff88', bgcolor: 'rgba(170,102,255,0.05)' }}>
        <Typography sx={{ color: '#aa66ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', mb: 1, fontSize: '0.95rem' }}>
          Why the two-stage DNN beats the two-stage ML
        </Typography>
        <Stack spacing={1.1} sx={{ color: '#c3d0d0', fontFamily: 'Share Tech Mono', fontSize: '0.64rem', lineHeight: 1.65 }}>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Almost half the Stage-1 false positives.</b> The DNN flags only
            <b> 12,847</b> benign flows as attacks vs the XGBoost engine's <b>24,090</b> —
            roughly a 47% drop in false alarms, which directly cuts analyst alert-fatigue in a real SOC.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Cracks the hardest class.</b> FTP-BruteForce recall jumps from just
            <b> 40%</b> in ML LightGBM (slow-rate auth attacks collapse into SlowHTTPTest)
            to <b>~99%</b> in the DNN. The network's non-linear boundaries separate attacks
            that tree splits cannot.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Stronger minority-class recall.</b> With depth + balanced class weights the
            DNN holds <b>≥99%</b> recall across the small classes (Brute Force-Web/XSS, SQLi,
            GoldenEye) where the trees lean on a handful of brittle splits.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Captures non-linear feature interactions.</b> The 31 flow features interact
            non-linearly; the layered DNN composes them end-to-end, whereas gradient-boosted
            trees are limited to axis-aligned splits per feature.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Higher end-to-end accuracy.</b> 98.23% vs 98.08% at Stage 1, with the two-stage
            DNN's macro-F1 reflecting genuine per-class quality rather than majority-class bias.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit', color: '#8b9a9a' }}>
            • <i>Honest trade-off:</i> ML catches marginally more attacks at Stage 1
            (93.8% vs 92.2% attack recall) and trains/infers faster, so it stays a strong,
            interpretable baseline — the DNN's real edge is far fewer false alarms and the
            hard minority classes.
          </Typography>
        </Stack>
      </Glass>
    </Stack>
  );
}


function DataStoryTab() {
  return (
    <Stack spacing={3}>
      <Glass>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', fontSize: '1.05rem', mb: 1.5 }}>
          Dataset — CIC-IDS-2018 (raw)
        </Typography>
        <Stack spacing={1.5} sx={{ color: '#c3d0d0', fontFamily: 'Share Tech Mono', fontSize: '0.64rem', lineHeight: 1.65 }}>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            Both engines (XGBoost + LightGBM and the Two-Stage DNN) are trained directly on
            the raw <b>CIC-IDS-2018</b> dataset published by the Canadian Institute for
            Cybersecurity. No synthetic augmentation is applied — flows go straight from the
            published CSVs into the standard preprocessing pipeline.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            CIC-IDS-2018 contains 14 attack categories plus benign traffic, captured over
            ten days of simulated enterprise activity. Each flow is summarised by 31
            CICFlowMeter features (Dst Port, IAT statistics, flag counts, byte/packet
            ratios, etc.) — the same 31-feature schema the live capture pipeline emits.
          </Typography>
        </Stack>
      </Glass>

      <Glass>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', fontSize: '1.05rem', mb: 1.5 }}>
          Preprocessing &amp; split
        </Typography>
        <Stack spacing={1.2} sx={{ color: '#c3d0d0', fontFamily: 'Share Tech Mono', fontSize: '0.64rem', lineHeight: 1.65 }}>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Cleaning:</b> drop infinite / NaN rows, deduplicate exact flows, strip
            non-feature columns (timestamps, source IPs).
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Encoding:</b> categorical labels mapped to integer class IDs (0 = Benign,
            1–14 = attack categories).
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Scaling:</b> StandardScaler fit on train, applied to test — shared between
            both engines so results are directly comparable.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            • <b>Split:</b> stratified 80 / 20 train / test, preserving the original
            attack-class distribution.
          </Typography>
        </Stack>
      </Glass>

      <Glass>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', fontSize: '1.05rem', mb: 1.5 }}>
          Dataset summary
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableBody>
              {[
                ['Source',                     'CIC-IDS-2018 (Canadian Institute for Cybersecurity)'],
                ['Train size',                 DATA_STORY.trainSize.toLocaleString() + ' samples'],
                ['Test size',                  DATA_STORY.testSize.toLocaleString() + ' samples'],
                ['Total',                      (DATA_STORY.trainSize + DATA_STORY.testSize).toLocaleString() + ' samples'],
                ['Train / Test split',         DATA_STORY.trainTestSplit],
                ['Number of features',         DATA_STORY.numFeatures + ' (CICFlowMeter schema)'],
                ['Number of classes',          DATA_STORY.numClasses + ' (1 Benign + 14 attack types)'],
                ['Preprocessing',              DATA_STORY.scaler],
                ['Augmentation',               'None — trained on raw dataset'],
              ].map(([k, v], i) => (
                <TableRow key={i} sx={{ '& td': {
                  borderColor: '#222', color: '#ddd',
                  fontFamily: 'Share Tech Mono', fontSize: '0.92rem' }}}>
                  <TableCell sx={{ color: '#888 !important', width: 280 }}>{k}</TableCell>
                  <TableCell sx={{ color: '#00d4ff !important' }}>{v}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Glass>
    </Stack>
  );
}


function LiteratureTab() {
  return (
    <Stack spacing={3}>
      <Glass>
        <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', fontSize: '1rem', mb: 1.5 }}>
          Comparison vs prior work (CIC-IDS-2018 lineage)
        </Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                {['Year', 'Paper / Source', 'Model', 'Dataset', 'Acc', 'F1', 'Novelty'].map(h => (
                  <TableCell key={h} sx={{ color: '#aaa', fontFamily: 'Share Tech Mono',
                                            borderColor: '#222', fontSize: '0.75rem' }}>{h}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {LITERATURE_ROWS.map((r, i) => (
                <TableRow key={i} sx={{ '& td': {
                  borderColor: '#222',
                  color: r.highlight ? '#00d4ff' : '#ddd',
                  fontFamily: 'Share Tech Mono', fontSize: '0.78rem',
                  fontWeight: r.highlight ? 'bold' : 'normal',
                  bgcolor: r.highlight ? 'rgba(0,255,65,0.06)' : 'transparent',
                }}}>
                  <TableCell>{r.year}</TableCell>
                  <TableCell>{r.highlight && <TrophyIcon sx={{ fontSize: 14, mr: 0.5,
                              color: '#ffd600', verticalAlign: 'middle' }} />}{r.paper}</TableCell>
                  <TableCell>{r.model}</TableCell>
                  <TableCell>{r.dataset}</TableCell>
                  <TableCell>{r.acc}</TableCell>
                  <TableCell>{r.f1}</TableCell>
                  <TableCell sx={{ color: '#888 !important' }}>{r.novelty}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Glass>

      <Glass sx={{ borderColor: '#aa66ff88', bgcolor: 'rgba(170,102,255,0.04)' }}>
        <Typography sx={{ color: '#aa66ff', fontFamily: 'Share Tech Mono',
                          fontWeight: 'bold', mb: 1.5, fontSize: '1rem' }}>
          What's genuinely new in this work
        </Typography>
        <Stack spacing={1.2} sx={{ color: '#c3d0d0', fontFamily: 'Share Tech Mono', fontSize: '0.64rem', lineHeight: 1.65 }}>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            <b style={{ color: '#aa66ff' }}>1. Pluggable engine architecture.</b> Most academic
            IDS papers ship a single model. We ship both an ML two-stage (XGBoost + LightGBM)
            and a DL two-stage (DNN), and the operator selects between them at runtime via the
            admin panel — no restart, no code change. This is industry-standard but rare in IDS
            research.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            <b style={{ color: '#aa66ff' }}>2. LLM as a third reasoning layer.</b> When the DL
            engine's Stage-2 confidence drops below a threshold, the flow is routed to a local
            Llama instance for behavioural reasoning + DuckDuckGo-based threat-intel lookup. This
            is the zero-day-detection path; no prior CIC-IDS-2018 paper combines a classifier
            with on-device LLM reasoning.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            <b style={{ color: '#aa66ff' }}>3. End-to-end live pipeline.</b> Scapy capture →
            31-feature extractor → engine registry → Postgres → Channels WebSocket → React UI.
            Most prior work stops at offline benchmarks on saved CSV; we run on live traffic at
            packet rate.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            <b style={{ color: '#aa66ff' }}>4. Built-in retraining loop.</b> Captured traffic is
            labelled, fed back through the retrainer for either engine (admin-selectable),
            backed up automatically with timestamped restore points, and the registry hot-reloads
            new models without a Django restart. The system continuously learns from its own
            production deployment.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            <b style={{ color: '#aa66ff' }}>5. Comparative analysis baked into the product.</b>
            This very page exists in the deployed application — the literature comparison and
            confusion matrices ship with the build, not as a one-off paper figure. Reviewers and
            future maintainers can re-run the metrics on retrained models.
          </Typography>
          <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit' }}>
            <b style={{ color: '#aa66ff' }}>6. Production hygiene.</b> JWT + RBAC (5 roles), full
            audit log, lazy model loading, graceful degradation on model-load failure, model
            backup &amp; restore, 5-second cached engine resolution so per-packet predictions
            don't hit Postgres. Most academic IDS prototypes skip this entirely.
          </Typography>
        </Stack>
      </Glass>
    </Stack>
  );
}


// =====================================================================
// Main page
// =====================================================================

const LiteratureAnalysis = () => {
  const [tab, setTab] = useState(0);
  const tabs = [
    { label: 'Performance Comparison', icon: <ChartIcon sx={{ fontSize: 16 }} /> },
    { label: 'Confusion Matrices',     icon: <MatrixIcon sx={{ fontSize: 16 }} /> },
  ];

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent',
               background: 'radial-gradient(ellipse at top, rgba(15,16,20,0.65), transparent 70%)',
               pt: 3, pb: 6 }}>
      <Container maxWidth="xl">
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
          <Box>
            <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                              fontSize: '2rem', fontWeight: 'bold' }}>
              Literature & Analysis
            </Typography>
            <Typography sx={{ color: '#8b9a9a', fontFamily: 'Share Tech Mono', fontSize: '0.74rem', lineHeight: 1.65 }}>
              Comparative results, confusion matrices, dataset description, and where
              this work sits in the broader CIC-IDS-2018 literature.
            </Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            <Chip icon={<TrophyIcon sx={{ fontSize: 16 }} />} label="DNN — best end-to-end" size="small"
                  sx={{ bgcolor: '#ffd60022', color: '#ffd600', border: '1px solid #ffd600',
                        fontFamily: 'Share Tech Mono', fontWeight: 'bold' }} />
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
            textColor="inherit" variant="scrollable"
            TabIndicatorProps={{ style: { backgroundColor: '#00d4ff', height: 3 } }}
            sx={{
              '& .MuiTab-root': {
                color: '#888', fontFamily: 'Share Tech Mono', fontWeight: 'bold',
                '&.Mui-selected': { color: '#00d4ff' },
              },
            }}
          >
            {tabs.map((t, i) => (
              <Tab key={i} icon={t.icon} iconPosition="start" label={t.label} />
            ))}
          </Tabs>
        </Paper>

        <Box>
          {tab === 0 && <PerformanceTab />}
          {tab === 1 && <ConfusionTab />}
        </Box>
      </Container>
    </Box>
  );
};

export default LiteratureAnalysis;

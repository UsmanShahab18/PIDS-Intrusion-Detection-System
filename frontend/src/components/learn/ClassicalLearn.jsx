/**
 * ClassicalLearn — scroll-driven "scrollytelling" for the two-stage classical
 * ML IDS (Stage 1: XGBoost level-wise → Stage 2: LightGBM leaf-wise).
 *
 * Single-file React component. No Tailwind (project uses MUI + framer-motion);
 * styling is inline + a tiny CSS block, animation is framer-motion `useScroll`
 * smoothed with `useSpring` for buttery, non-jumpy motion tied to scroll.
 *
 * Phases (per the spec):
 *   1. XGBoost forms LEVEL-WISE  — symmetric tree, row-by-row.
 *   2. Binary flow               — green packet → Normal, red packet → Attack.
 *   3. LightGBM forms LEAF-WISE  — asymmetric tree, one branch grows deep.
 *   4. Multi-class flow          — the red Attack packet → specific attack type.
 *
 * Stages 1+2 share section A; stages 3+4 share section B. Within each section
 * the first ~55% of scroll builds the tree, the rest flows the packets.
 */
import React, { useRef } from 'react';
import { Link } from 'react-router-dom';
import { motion, useScroll, useSpring, useTransform } from 'framer-motion';

const C = {
  bg: '#05080a',
  blue: '#00d4ff',
  blueSoft: '#89ceff',
  green: '#00ff88',
  red: '#ff3b3b',
  purple: '#aa66ff',
  text: '#f1ffef',
  dim: '#7e8c8c',
  panel: 'rgba(255,255,255,0.03)',
  border: 'rgba(255,255,255,0.08)',
};

const MONO = 'ui-monospace, "Share Tech Mono", "SFMono-Regular", Menlo, monospace';

const TABS = [
  { stack: 'classical', to: '/learn/classical', short: 'Classical', accent: C.green },
  { stack: 'deep', to: '/learn/deep', short: 'Deep', accent: C.purple },
  // Graph (GNN) tab disabled until a trained GNN model ships.
];

// ───────────────────────── reusable animated SVG atoms ─────────────────────
function RevealEdge({ p, range, x1, y1, x2, y2, color = 'rgba(255,255,255,0.25)', width = 2 }) {
  const len = useTransform(p, range, [0, 1]);
  const op = useTransform(p, range, [0, 1]);
  return (
    <motion.line
      x1={x1} y1={y1} x2={x2} y2={y2}
      stroke={color} strokeWidth={width} strokeLinecap="round"
      style={{ pathLength: len, opacity: op }}
    />
  );
}

const KIND_COLOR = {
  feature: C.blue,
  normal: C.green,
  attack: C.red,
};

function RevealNode({ p, range, x, y, label, kind = 'feature' }) {
  const isLeaf = kind !== 'feature';
  const rMax = isLeaf ? 16 : 14;
  const r = useTransform(p, range, [2, rMax]);
  const op = useTransform(p, range, [0, 1]);
  const color = KIND_COLOR[kind] || C.blue;
  // Label sits OUTSIDE the marker so long text always fits: features label
  // above the node, leaves label below — keeps clear of the downward edges.
  const labelY = isLeaf ? y + rMax + 16 : y - rMax - 12;
  return (
    <motion.g style={{ opacity: op }}>
      <motion.circle
        cx={x} cy={y} r={r}
        fill={isLeaf ? `${color}22` : 'rgba(0,212,255,0.10)'}
        stroke={color} strokeWidth={2}
        style={{ filter: `drop-shadow(0 0 6px ${color}66)` }}
      />
      <text
        x={x} y={labelY}
        textAnchor="middle" dominantBaseline="middle"
        fontSize={12} fontFamily={MONO}
        fill={isLeaf ? color : C.blueSoft}
        stroke={C.bg} strokeWidth={3} paintOrder="stroke"
        style={{ fontWeight: isLeaf ? 700 : 500, letterSpacing: '0.02em' }}
      >
        {label}
      </text>
    </motion.g>
  );
}

function Packet({ p, range, pts, color }) {
  const n = pts.length;
  const inputs = pts.map((_, i) => range[0] + ((range[1] - range[0]) * i) / (n - 1));
  const x = useTransform(p, inputs, pts.map((pt) => pt[0]));
  const y = useTransform(p, inputs, pts.map((pt) => pt[1]));
  const op = useTransform(
    p,
    [range[0] - 0.03, range[0], range[1] - 0.02, Math.min(range[1] + 0.04, 1)],
    [0, 1, 1, 1],
  );
  return (
    <>
      <motion.circle cx={x} cy={y} r={13} fill={`${color}22`} style={{ opacity: op }} />
      <motion.circle
        cx={x} cy={y} r={7} fill={color}
        style={{ opacity: op, filter: `drop-shadow(0 0 10px ${color})` }}
      />
    </>
  );
}

// Crossfading caption that swaps copy as the section scrolls.
function Caption({ p, range, accent, kicker, title, body }) {
  const op = useTransform(p, [range[0], range[0] + 0.06, range[1] - 0.06, range[1]], [0, 1, 1, 0]);
  const y = useTransform(p, [range[0], range[0] + 0.08], [24, 0]);
  return (
    <motion.div style={{ opacity: op, y, position: 'absolute', inset: 0, pointerEvents: 'none' }}>
      <div style={{ maxWidth: 360 }}>
        <div style={{ fontFamily: MONO, fontSize: 12, letterSpacing: '0.18em', textTransform: 'uppercase', color: accent, marginBottom: 12 }}>
          {kicker}
        </div>
        <h3 style={{ fontSize: 'clamp(1.3rem,2.4vw,1.9rem)', fontWeight: 800, margin: '0 0 14px', lineHeight: 1.15, color: C.text }}>
          {title}
        </h3>
        <p style={{ color: '#b9cbb9', fontSize: 15.5, lineHeight: 1.7, margin: 0 }}>{body}</p>
      </div>
    </motion.div>
  );
}

// ───────────────────────── Stage 1+2 : XGBoost ─────────────────────────────
function XGBoostStage() {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end end'] });
  const p = useSpring(scrollYProgress, { stiffness: 80, damping: 22, mass: 0.35 });

  // symmetric level-wise tree (root → 2 → 4 leaves)
  const root = [380, 50];
  const l1a = [220, 165], l1b = [540, 165];
  const lf0 = [120, 300], lf1 = [300, 300], lf2 = [460, 300], lf3 = [640, 300];

  return (
    <div ref={ref} style={{ height: '320vh', position: 'relative' }}>
      <div style={{ position: 'sticky', top: 0, height: '100vh', display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto', padding: '0 24px', width: '100%', display: 'grid', gridTemplateColumns: '360px 1fr', gap: 28, alignItems: 'center' }}>
          <div style={{ position: 'relative', height: 220 }}>
            <Caption p={p} range={[0.0, 0.5]} accent={C.green}
              kicker="Stage 1 · XGBoost"
              title="Builds level-wise"
              body="XGBoost grows the tree row by row — it finishes an entire depth level before starting the next. Each split tests one of the 31 flow features to quickly filter out normal traffic." />
            <Caption p={p} range={[0.5, 1.0]} accent={C.blue}
              kicker="Stage 1 · Binary"
              title="Normal vs Attack"
              body="A flow drops in at the root and follows the splits. A benign flow (green) settles in a Normal leaf; a malicious one (red) ends in an Attack leaf — handed to Stage 2." />
          </div>

          <svg viewBox="0 0 760 360" style={{ width: '100%', maxHeight: '78vh' }}>
            {/* edges */}
            <RevealEdge p={p} range={[0.12, 0.22]} x1={root[0]} y1={root[1]} x2={l1a[0]} y2={l1a[1]} color={`${C.blue}88`} />
            <RevealEdge p={p} range={[0.12, 0.22]} x1={root[0]} y1={root[1]} x2={l1b[0]} y2={l1b[1]} color={`${C.blue}88`} />
            <RevealEdge p={p} range={[0.28, 0.38]} x1={l1a[0]} y1={l1a[1]} x2={lf0[0]} y2={lf0[1]} color={`${C.green}66`} />
            <RevealEdge p={p} range={[0.28, 0.38]} x1={l1a[0]} y1={l1a[1]} x2={lf1[0]} y2={lf1[1]} color={`${C.red}66`} />
            <RevealEdge p={p} range={[0.28, 0.38]} x1={l1b[0]} y1={l1b[1]} x2={lf2[0]} y2={lf2[1]} color={`${C.green}66`} />
            <RevealEdge p={p} range={[0.28, 0.38]} x1={l1b[0]} y1={l1b[1]} x2={lf3[0]} y2={lf3[1]} color={`${C.red}66`} />
            {/* level 0 */}
            <RevealNode p={p} range={[0.03, 0.12]} x={root[0]} y={root[1]} label="Flow Duration" />
            {/* level 1 */}
            <RevealNode p={p} range={[0.16, 0.26]} x={l1a[0]} y={l1a[1]} label="Dst Port" />
            <RevealNode p={p} range={[0.16, 0.26]} x={l1b[0]} y={l1b[1]} label="Fwd Pkts/s" />
            {/* level 2 (leaves) */}
            <RevealNode p={p} range={[0.30, 0.42]} x={lf0[0]} y={lf0[1]} label="Normal" kind="normal" />
            <RevealNode p={p} range={[0.30, 0.42]} x={lf1[0]} y={lf1[1]} label="Attack" kind="attack" />
            <RevealNode p={p} range={[0.30, 0.42]} x={lf2[0]} y={lf2[1]} label="Normal" kind="normal" />
            <RevealNode p={p} range={[0.30, 0.42]} x={lf3[0]} y={lf3[1]} label="Attack" kind="attack" />

            {/* Phase 2 packets */}
            <Packet p={p} range={[0.58, 0.82]} color={C.green} pts={[root, l1a, lf0]} />
            <Packet p={p} range={[0.62, 0.88]} color={C.red} pts={[root, l1b, lf3]} />
          </svg>
        </div>
      </div>
    </div>
  );
}

// ───────────────────────── Stage 3+4 : LightGBM ────────────────────────────
function LightGBMStage() {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end end'] });
  const p = useSpring(scrollYProgress, { stiffness: 80, damping: 22, mass: 0.35 });

  // asymmetric leaf-wise tree: one branch grows deep, side leaves split off.
  const root = [120, 55];
  const n1 = [275, 130], n2 = [415, 215], n3 = [555, 300];
  const deepLeaf = [670, 380];
  const s1 = [70, 175], s2 = [215, 250], s3 = [350, 335];

  return (
    <div ref={ref} style={{ height: '340vh', position: 'relative' }}>
      <div style={{ position: 'sticky', top: 0, height: '100vh', display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto', padding: '0 24px', width: '100%', display: 'grid', gridTemplateColumns: '360px 1fr', gap: 28, alignItems: 'center' }}>
          <div style={{ position: 'relative', height: 240 }}>
            <Caption p={p} range={[0.0, 0.5]} accent={C.purple}
              kicker="Stage 2 · LightGBM"
              title="Grows leaf-wise"
              body="LightGBM repeatedly splits the single highest-gain leaf, so one branch plunges deep while others stay shallow — an asymmetric tree tuned to specific attack signatures." />
            <Caption p={p} range={[0.5, 1.0]} accent={C.red}
              kicker="Stage 2 · Multi-class"
              title="Pin the attack type"
              body="The Attack packet from Stage 1 enters here and rides the deep branch down — each split matching a signature — until it lands on the exact class: DDoS LOIC-HTTP." />
          </div>

          <svg viewBox="0 0 760 440" style={{ width: '100%', maxHeight: '80vh' }}>
            {/* deep branch edges */}
            <RevealEdge p={p} range={[0.12, 0.20]} x1={root[0]} y1={root[1]} x2={n1[0]} y2={n1[1]} color={`${C.purple}99`} />
            <RevealEdge p={p} range={[0.26, 0.34]} x1={n1[0]} y1={n1[1]} x2={n2[0]} y2={n2[1]} color={`${C.purple}99`} />
            <RevealEdge p={p} range={[0.40, 0.48]} x1={n2[0]} y1={n2[1]} x2={n3[0]} y2={n3[1]} color={`${C.purple}99`} />
            <RevealEdge p={p} range={[0.52, 0.60]} x1={n3[0]} y1={n3[1]} x2={deepLeaf[0]} y2={deepLeaf[1]} color={`${C.red}99`} />
            {/* shallow side leaves */}
            <RevealEdge p={p} range={[0.16, 0.24]} x1={root[0]} y1={root[1]} x2={s1[0]} y2={s1[1]} color="rgba(255,255,255,0.18)" />
            <RevealEdge p={p} range={[0.30, 0.38]} x1={n1[0]} y1={n1[1]} x2={s2[0]} y2={s2[1]} color="rgba(255,255,255,0.18)" />
            <RevealEdge p={p} range={[0.44, 0.52]} x1={n2[0]} y1={n2[1]} x2={s3[0]} y2={s3[1]} color="rgba(255,255,255,0.18)" />

            {/* nodes — leaf-wise reveal order (deep branch first) */}
            <RevealNode p={p} range={[0.03, 0.12]} x={root[0]} y={root[1]} label="Pkt Len Std" />
            <RevealNode p={p} range={[0.16, 0.24]} x={s1[0]} y={s1[1]} label="FTP-Brute" kind="attack" />
            <RevealNode p={p} range={[0.18, 0.26]} x={n1[0]} y={n1[1]} label="SYN Flag Cnt" />
            <RevealNode p={p} range={[0.30, 0.38]} x={s2[0]} y={s2[1]} label="SQL Inject" kind="attack" />
            <RevealNode p={p} range={[0.32, 0.40]} x={n2[0]} y={n2[1]} label="Bwd Pkts/s" />
            <RevealNode p={p} range={[0.44, 0.52]} x={s3[0]} y={s3[1]} label="Normal" kind="normal" />
            <RevealNode p={p} range={[0.46, 0.54]} x={n3[0]} y={n3[1]} label="Init Win Byts" />
            <RevealNode p={p} range={[0.56, 0.64]} x={deepLeaf[0]} y={deepLeaf[1]} label="DDoS LOIC-HTTP" kind="attack" />

            {/* Phase 4: red Attack packet down the deep branch */}
            <Packet p={p} range={[0.66, 0.96]} color={C.red} pts={[root, n1, n2, n3, deepLeaf]} />
          </svg>
        </div>
      </div>
    </div>
  );
}

// ───────────────────────── page shell ──────────────────────────────────────
export default function ClassicalLearn() {
  return (
    <div style={{ background: 'linear-gradient(rgba(5,8,10,0.55), rgba(5,8,10,0.55)), radial-gradient(1200px 600px at 50% -10%, rgba(0,255,136,0.10), transparent)', color: C.text, minHeight: '100vh' }}>
      <div style={{ maxWidth: 1180, margin: '0 auto', padding: '96px 24px 24px' }}>
        {/* stack switcher */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 40, flexWrap: 'wrap' }}>
          {TABS.map((t) => {
            const active = t.stack === 'classical';
            return (
              <Link key={t.stack} to={t.to} style={{
                fontFamily: MONO, fontSize: 13, letterSpacing: '0.08em', textDecoration: 'none',
                padding: '8px 16px', borderRadius: 999,
                color: active ? C.bg : t.accent, background: active ? t.accent : 'transparent',
                border: `1px solid ${t.accent}`, fontWeight: active ? 700 : 500,
              }}>{t.short}</Link>
            );
          })}
        </div>

        {/* hero */}
        <header style={{ marginBottom: 24 }}>
          <div style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.2em', textTransform: 'uppercase', color: C.green, marginBottom: 16 }}>
            XGBoost → LightGBM
          </div>
          <h1 style={{ fontSize: 'clamp(2rem,6vw,3.4rem)', fontWeight: 800, lineHeight: 1.05, margin: '0 0 18px' }}>
            Classical Machine Learning
          </h1>
          <p style={{ color: '#b9cbb9', fontSize: 18, lineHeight: 1.6, margin: 0, maxWidth: 560 }}>
            Two stages of gradient-boosted trees. Watch each one build — then watch a live flow fall through it to a verdict.
          </p>
          <p style={{ color: C.dim, fontSize: 13, marginTop: 22, fontFamily: MONO }}>Scroll to build the trees ↓</p>
        </header>
      </div>

      <XGBoostStage />
      <LightGBMStage />

      <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 24px 120px', textAlign: 'center' }}>
        <h2 style={{ fontSize: 'clamp(1.4rem,3vw,2rem)', fontWeight: 800, margin: '0 0 14px' }}>Two stages, one verdict</h2>
        <p style={{ color: '#b9cbb9', fontSize: 16, lineHeight: 1.7, margin: 0 }}>
          XGBoost screens every flow fast (Normal vs Attack); LightGBM names the attack. The same trees you watched build are
          the ones scoring live traffic on your dashboard.
        </p>
        <div style={{ marginTop: 28, display: 'flex', gap: 10, justifyContent: 'center' }}>
          <Link to="/learn/deep" style={{ fontFamily: MONO, fontSize: 13, textDecoration: 'none', padding: '10px 18px', borderRadius: 999, color: C.purple, border: `1px solid ${C.purple}` }}>
            Next: Deep →
          </Link>
        </div>
      </div>
    </div>
  );
}

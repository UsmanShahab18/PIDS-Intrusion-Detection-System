/**
 * DeepLearn — scroll-driven scrollytelling for the two-stage DEEP-LEARNING IDS.
 *
 *   Stage 1: Binary DNN (sigmoid)      → Normal vs Attack
 *   Stage 2: Multi-class DNN (softmax) → specific attack type
 *
 * Same engine as ClassicalLearn: framer-motion `useScroll` + `useSpring` for
 * buttery scroll-tied animation. Per stage, the first ~55% of scroll builds the
 * network layer-by-layer; the rest fires an activation pulse to a verdict.
 */
import React, { useRef } from 'react';
import { Link } from 'react-router-dom';
import { motion, useScroll, useSpring, useTransform } from 'framer-motion';

const C = {
  bg: '#05080a', blue: '#00d4ff', blueSoft: '#89ceff', green: '#00ff88',
  red: '#ff3b3b', purple: '#aa66ff', text: '#f1ffef', dim: '#7e8c8c',
};
const MONO = 'ui-monospace, "Share Tech Mono", Menlo, monospace';
const TABS = [
  { stack: 'classical', to: '/learn/classical', short: 'Classical', accent: C.green },
  { stack: 'deep', to: '/learn/deep', short: 'Deep', accent: C.purple },
  // Graph (GNN) tab disabled until a trained GNN model ships.
];

// ── helpers ────────────────────────────────────────────────────────────────
const column = (x, count, top, bottom) => {
  if (count === 1) return [[x, (top + bottom) / 2]];
  const step = (bottom - top) / (count - 1);
  return Array.from({ length: count }, (_, i) => [x, top + i * step]);
};

function Neuron({ p, range, x, y, color = C.purple, rMax = 7 }) {
  const r = useTransform(p, range, [0, rMax]);
  const op = useTransform(p, range, [0, 1]);
  return (
    <motion.circle cx={x} cy={y} r={r} fill={`${color}22`} stroke={color} strokeWidth={1.6}
      style={{ opacity: op, filter: `drop-shadow(0 0 5px ${color}55)` }} />
  );
}

// All dense connections between two columns fade in as one cheap group.
function ConnGroup({ p, range, a, b, color = 'rgba(170,102,255,0.16)' }) {
  const op = useTransform(p, range, [0, 1]);
  return (
    <motion.g style={{ opacity: op }}>
      {a.map((pa, i) => b.map((pb, j) => (
        <line key={`${i}-${j}`} x1={pa[0]} y1={pa[1]} x2={pb[0]} y2={pb[1]} stroke={color} strokeWidth={1} />
      )))}
    </motion.g>
  );
}

function LayerLabel({ p, range, x, y, text, color = C.blueSoft }) {
  const op = useTransform(p, range, [0, 1]);
  return (
    <motion.text x={x} y={y} textAnchor="middle" fontFamily={MONO} fontSize={11} fill={color}
      stroke={C.bg} strokeWidth={3} paintOrder="stroke" style={{ opacity: op }}>{text}</motion.text>
  );
}

function Chip({ p, range, x, y, label, color }) {
  const op = useTransform(p, range, [0, 1]);
  const w = Math.max(78, label.length * 7.4 + 22);
  return (
    <motion.g style={{ opacity: op }}>
      <rect x={x} y={y - 15} rx={15} width={w} height={30} fill={`${color}20`} stroke={color} strokeWidth={1.6} />
      <text x={x + w / 2} y={y + 1} textAnchor="middle" dominantBaseline="middle" fontFamily={MONO}
        fontSize={12} fill={color} fontWeight={700} stroke={C.bg} strokeWidth={3} paintOrder="stroke">{label}</text>
    </motion.g>
  );
}

function Packet({ p, range, pts, color }) {
  const n = pts.length;
  const inputs = pts.map((_, i) => range[0] + ((range[1] - range[0]) * i) / (n - 1));
  const x = useTransform(p, inputs, pts.map((q) => q[0]));
  const y = useTransform(p, inputs, pts.map((q) => q[1]));
  const op = useTransform(p, [range[0] - 0.03, range[0], range[1] - 0.02, Math.min(range[1] + 0.04, 1)], [0, 1, 1, 1]);
  return (
    <>
      <motion.circle cx={x} cy={y} r={13} fill={`${color}22`} style={{ opacity: op }} />
      <motion.circle cx={x} cy={y} r={7} fill={color} style={{ opacity: op, filter: `drop-shadow(0 0 10px ${color})` }} />
    </>
  );
}

function Caption({ p, range, accent, kicker, title, body }) {
  const op = useTransform(p, [range[0], range[0] + 0.06, range[1] - 0.06, range[1]], [0, 1, 1, 0]);
  const y = useTransform(p, [range[0], range[0] + 0.08], [24, 0]);
  return (
    <motion.div style={{ opacity: op, y, position: 'absolute', inset: 0, pointerEvents: 'none' }}>
      <div style={{ maxWidth: 360 }}>
        <div style={{ fontFamily: MONO, fontSize: 12, letterSpacing: '0.18em', textTransform: 'uppercase', color: accent, marginBottom: 12 }}>{kicker}</div>
        <h3 style={{ fontSize: 'clamp(1.3rem,2.4vw,1.9rem)', fontWeight: 800, margin: '0 0 14px', lineHeight: 1.15, color: C.text }}>{title}</h3>
        <p style={{ color: '#b9cbb9', fontSize: 15.5, lineHeight: 1.7, margin: 0 }}>{body}</p>
      </div>
    </motion.div>
  );
}

function StageShell({ heightVh, children, leftHeight = 230 }) {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end end'] });
  const p = useSpring(scrollYProgress, { stiffness: 80, damping: 22, mass: 0.35 });
  return (
    <div ref={ref} style={{ height: `${heightVh}vh`, position: 'relative' }}>
      <div style={{ position: 'sticky', top: 0, height: '100vh', display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto', padding: '0 24px', width: '100%', display: 'grid', gridTemplateColumns: '360px 1fr', gap: 28, alignItems: 'center' }}>
          {children(p, leftHeight)}
        </div>
      </div>
    </div>
  );
}

// ── Stage 1 — Binary DNN ─────────────────────────────────────────────────
function BinaryDNN() {
  const inp = column(70, 6, 60, 300);
  const h1 = column(195, 6, 60, 300);
  const h2 = column(320, 5, 80, 280);
  const h3 = column(440, 5, 80, 280);
  const h4 = column(555, 4, 110, 250);
  const out = column(645, 1, 180, 180);
  const normalChip = [710, 130];
  const attackChip = [710, 235];
  // representative activation paths (one neuron per column → output → chip)
  const greenPath = [inp[1], h1[1], h2[1], h3[1], h4[1], out[0], [normalChip[0], normalChip[1]]];
  const redPath = [inp[4], h1[4], h2[3], h3[3], h4[2], out[0], [attackChip[0], attackChip[1]]];
  return (
    <StageShell heightVh={320}>
      {(p) => (<>
        <div style={{ position: 'relative', height: 230 }}>
          <Caption p={p} range={[0, 0.5]} accent={C.purple}
            kicker="Stage 1 · Binary DNN"
            title="Layers learn the pattern"
            body="A feed-forward network builds layer by layer — 31 features in, then 256 → 128 → 64 → 32 neurons. Each layer composes the features into higher-order signals a single threshold can't express." />
          <Caption p={p} range={[0.5, 1]} accent={C.blue}
            kicker="Stage 1 · Sigmoid"
            title="Normal vs Attack"
            body="A flow activates a path through the network; the final sigmoid neuron fires. A benign flow lands Normal (green); a malicious one lands Attack (red) — passed to Stage 2." />
        </div>
        <svg viewBox="0 0 800 360" style={{ width: '100%', maxHeight: '80vh' }}>
          <ConnGroup p={p} range={[0.12, 0.20]} a={inp} b={h1} />
          <ConnGroup p={p} range={[0.20, 0.28]} a={h1} b={h2} />
          <ConnGroup p={p} range={[0.28, 0.36]} a={h2} b={h3} />
          <ConnGroup p={p} range={[0.36, 0.44]} a={h3} b={h4} />
          <ConnGroup p={p} range={[0.44, 0.50]} a={h4} b={out} color="rgba(0,212,255,0.25)" />
          {inp.map(([x, y], i) => <Neuron key={`i${i}`} p={p} range={[0.03, 0.10]} x={x} y={y} color={C.blueSoft} />)}
          {h1.map(([x, y], i) => <Neuron key={`a${i}`} p={p} range={[0.12, 0.18]} x={x} y={y} />)}
          {h2.map(([x, y], i) => <Neuron key={`b${i}`} p={p} range={[0.20, 0.26]} x={x} y={y} />)}
          {h3.map(([x, y], i) => <Neuron key={`c${i}`} p={p} range={[0.28, 0.34]} x={x} y={y} />)}
          {h4.map(([x, y], i) => <Neuron key={`d${i}`} p={p} range={[0.36, 0.42]} x={x} y={y} />)}
          <Neuron p={p} range={[0.44, 0.50]} x={out[0][0]} y={out[0][1]} color={C.blue} rMax={9} />
          <LayerLabel p={p} range={[0.05, 0.12]} x={70} y={325} text="31 features" />
          <LayerLabel p={p} range={[0.20, 0.26]} x={320} y={305} text="hidden" />
          <LayerLabel p={p} range={[0.46, 0.52]} x={645} y={205} text="sigmoid" color={C.blue} />
          <Chip p={p} range={[0.48, 0.55]} x={normalChip[0]} y={normalChip[1]} label="Normal" color={C.green} />
          <Chip p={p} range={[0.48, 0.55]} x={attackChip[0]} y={attackChip[1]} label="Attack" color={C.red} />
          <Packet p={p} range={[0.58, 0.82]} color={C.green} pts={greenPath} />
          <Packet p={p} range={[0.62, 0.90]} color={C.red} pts={redPath} />
        </svg>
      </>)}
    </StageShell>
  );
}

// ── Stage 2 — Multi-class DNN ────────────────────────────────────────────
function MultiDNN() {
  const inp = column(55, 6, 60, 320);
  const h1 = column(170, 7, 50, 330);
  const h2 = column(285, 6, 60, 320);
  const h3 = column(395, 5, 80, 300);
  const h4 = column(495, 4, 110, 270);
  const h5 = column(580, 4, 120, 260);
  const chips = [
    { y: 70, label: 'DDoS LOIC-HTTP' },
    { y: 140, label: 'SQL Injection' },
    { y: 210, label: 'FTP-BruteForce' },
    { y: 280, label: 'Botnet' },
  ];
  const chipX = 660;
  const redPath = [inp[4], h1[5], h2[4], h3[3], h4[2], h5[1], [chipX, chips[0].y]];
  return (
    <StageShell heightVh={340}>
      {(p) => (<>
        <div style={{ position: 'relative', height: 240 }}>
          <Caption p={p} range={[0, 0.5]} accent={C.purple}
            kicker="Stage 2 · Multi-class DNN"
            title="Deeper, wider network"
            body="A larger network (512 → 256 → 128 → 64 → 32) learns the fine-grained signatures that separate attack families — far more capacity than Stage 1's binary screen." />
          <Caption p={p} range={[0.5, 1]} accent={C.red}
            kicker="Stage 2 · Softmax"
            title="Name the attack"
            body="The Attack flow from Stage 1 fires through; softmax outputs a probability per class and the strongest wins — here, DDoS LOIC-HTTP." />
        </div>
        <svg viewBox="0 0 800 380" style={{ width: '100%', maxHeight: '82vh' }}>
          <ConnGroup p={p} range={[0.12, 0.20]} a={inp} b={h1} />
          <ConnGroup p={p} range={[0.20, 0.28]} a={h1} b={h2} />
          <ConnGroup p={p} range={[0.28, 0.36]} a={h2} b={h3} />
          <ConnGroup p={p} range={[0.36, 0.43]} a={h3} b={h4} />
          <ConnGroup p={p} range={[0.43, 0.50]} a={h4} b={h5} />
          {inp.map(([x, y], i) => <Neuron key={`i${i}`} p={p} range={[0.03, 0.10]} x={x} y={y} color={C.blueSoft} />)}
          {h1.map(([x, y], i) => <Neuron key={`a${i}`} p={p} range={[0.12, 0.18]} x={x} y={y} />)}
          {h2.map(([x, y], i) => <Neuron key={`b${i}`} p={p} range={[0.20, 0.26]} x={x} y={y} />)}
          {h3.map(([x, y], i) => <Neuron key={`c${i}`} p={p} range={[0.28, 0.34]} x={x} y={y} />)}
          {h4.map(([x, y], i) => <Neuron key={`d${i}`} p={p} range={[0.36, 0.42]} x={x} y={y} />)}
          {h5.map(([x, y], i) => <Neuron key={`e${i}`} p={p} range={[0.43, 0.49]} x={x} y={y} />)}
          <LayerLabel p={p} range={[0.05, 0.12]} x={55} y={345} text="31 features" />
          <LayerLabel p={p} range={[0.14, 0.20]} x={170} y={350} text="512" />
          <LayerLabel p={p} range={[0.45, 0.52]} x={580} y={285} text="softmax" color={C.red} />
          {chips.map((c, i) => (
            <Chip key={c.label} p={p} range={[0.50, 0.58]} x={chipX} y={c.y}
              label={c.label} color={i === 0 ? C.red : 'rgba(255,255,255,0.5)'} />
          ))}
          <Packet p={p} range={[0.64, 0.95]} color={C.red} pts={redPath} />
        </svg>
      </>)}
    </StageShell>
  );
}

export default function DeepLearn() {
  return (
    <div style={{ background: 'linear-gradient(rgba(5,8,10,0.55), rgba(5,8,10,0.55)), radial-gradient(1200px 600px at 50% -10%, rgba(170,102,255,0.12), transparent)', color: C.text, minHeight: '100vh' }}>
      <div style={{ maxWidth: 1180, margin: '0 auto', padding: '96px 24px 24px' }}>
        <div style={{ display: 'flex', gap: 8, marginBottom: 40, flexWrap: 'wrap' }}>
          {TABS.map((t) => {
            const active = t.stack === 'deep';
            return (
              <Link key={t.stack} to={t.to} style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.08em', textDecoration: 'none', padding: '8px 16px', borderRadius: 999, color: active ? C.bg : t.accent, background: active ? t.accent : 'transparent', border: `1px solid ${t.accent}`, fontWeight: active ? 700 : 500 }}>{t.short}</Link>
            );
          })}
        </div>
        <header style={{ marginBottom: 24 }}>
          <div style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.2em', textTransform: 'uppercase', color: C.purple, marginBottom: 16 }}>DNN → DNN</div>
          <h1 style={{ fontSize: 'clamp(2rem,6vw,3.4rem)', fontWeight: 800, lineHeight: 1.05, margin: '0 0 18px' }}>Deep Learning</h1>
          <p style={{ color: '#b9cbb9', fontSize: 18, lineHeight: 1.6, margin: 0, maxWidth: 560 }}>
            Two neural networks. The first screens every flow; the second names the attack. Watch each one build, then watch a flow activate it.
          </p>
          <p style={{ color: C.dim, fontSize: 13, marginTop: 22, fontFamily: MONO }}>Scroll to build the networks ↓</p>
        </header>
      </div>
      <BinaryDNN />
      <MultiDNN />
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 24px 120px', textAlign: 'center' }}>
        <h2 style={{ fontSize: 'clamp(1.4rem,3vw,2rem)', fontWeight: 800, margin: '0 0 14px' }}>Depth where rules run out</h2>
        <p style={{ color: '#b9cbb9', fontSize: 16, lineHeight: 1.7, margin: 0 }}>
          The binary DNN filters fast; the multi-class DNN learns subtle, evolving signatures no static threshold could keep up with.
        </p>
        <div style={{ marginTop: 28, display: 'flex', gap: 10, justifyContent: 'center' }}>
          <Link to="/learn/classical" style={{ fontFamily: MONO, fontSize: 13, textDecoration: 'none', padding: '10px 18px', borderRadius: 999, color: C.green, border: `1px solid ${C.green}` }}>← Back to Classical</Link>
        </div>
      </div>
    </div>
  );
}

/**
 * GnnLearn — scroll-driven scrollytelling for the two-stage GRAPH NEURAL NETWORK
 * IDS.
 *
 *   Stage 1: E-GraphSAGE — aggregate neighbour EDGE features (message passing)
 *   Stage 2: GIN + GAT   — attention sharpens the signal → flag the attack
 *
 * Hosts are nodes, flows are edges. Same scroll engine as the other Learn
 * pages (useScroll + useSpring). Stage A builds the graph then passes messages;
 * Stage B applies attention then renders the verdict (lateral movement).
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
  { stack: 'gnn', to: '/learn/gnn', short: 'Graph', accent: C.blueSoft },
];

// Shared graph layout: a core host ringed by neighbour hosts.
const CENTER = [380, 210];
const NEIGHBOURS = (() => {
  const n = 7, R = 158;
  return Array.from({ length: n }, (_, i) => {
    const a = -Math.PI / 2 + (i / n) * Math.PI * 2;
    return { x: Math.round(CENTER[0] + Math.cos(a) * R), y: Math.round(CENTER[1] + Math.sin(a) * R), ip: `.${10 + i}` };
  });
})();
const SUSPECT = 1; // index of the compromised host

// ── atoms ────────────────────────────────────────────────────────────────
function GraphEdge({ p, revealRange, a, b, baseColor = 'rgba(137,206,255,0.35)', width = 1.6, attnRange = [0.999, 1], attnColor, attnWidth }) {
  const len = useTransform(p, revealRange, [0, 1]);
  const op = useTransform(p, revealRange, [0, 1]);
  const w = useTransform(p, attnRange, [width, attnWidth || width]);
  const stroke = useTransform(p, attnRange, [baseColor, attnColor || baseColor]);
  return (
    <motion.line x1={a[0]} y1={a[1]} x2={b[0]} y2={b[1]} strokeLinecap="round"
      stroke={stroke} style={{ pathLength: len, opacity: op, strokeWidth: w }} />
  );
}

function GraphNode({ p, revealRange, x, y, label, baseColor = C.blueSoft, rMax = 22, flagRange = [0.999, 1], flagColor }) {
  const r = useTransform(p, revealRange, [0, rMax]);
  const op = useTransform(p, revealRange, [0, 1]);
  const stroke = useTransform(p, flagRange, [baseColor, flagColor || baseColor]);
  const fill = useTransform(p, flagRange, [`${baseColor}1f`, `${(flagColor || baseColor)}33`]);
  return (
    <motion.g style={{ opacity: op }}>
      <motion.circle cx={x} cy={y} r={r} fill={fill} stroke={stroke} strokeWidth={2}
        style={{ filter: `drop-shadow(0 0 7px ${baseColor}55)` }} />
      <text x={x} y={y + rMax + 15} textAnchor="middle" dominantBaseline="middle" fontFamily={MONO}
        fontSize={11} fill={baseColor} stroke={C.bg} strokeWidth={3} paintOrder="stroke">{label}</text>
    </motion.g>
  );
}

function Pulse({ p, range, a, b, color }) {
  const x = useTransform(p, range, [a[0], b[0]]);
  const y = useTransform(p, range, [a[1], b[1]]);
  const op = useTransform(p, [range[0] - 0.02, range[0], range[1] - 0.02, range[1]], [0, 1, 1, 0]);
  return <motion.circle cx={x} cy={y} r={5} fill={color} style={{ opacity: op, filter: `drop-shadow(0 0 8px ${color})` }} />;
}

function Chip({ p, range, x, y, label, color }) {
  const op = useTransform(p, range, [0, 1]);
  const w = Math.max(80, label.length * 7.4 + 22);
  return (
    <motion.g style={{ opacity: op }}>
      <rect x={x - w / 2} y={y - 15} rx={15} width={w} height={30} fill={`${color}20`} stroke={color} strokeWidth={1.6} />
      <text x={x} y={y + 1} textAnchor="middle" dominantBaseline="middle" fontFamily={MONO} fontSize={12}
        fill={color} fontWeight={700} stroke={C.bg} strokeWidth={3} paintOrder="stroke">{label}</text>
    </motion.g>
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

function StageShell({ heightVh, children }) {
  const ref = useRef(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end end'] });
  const p = useSpring(scrollYProgress, { stiffness: 80, damping: 22, mass: 0.35 });
  return (
    <div ref={ref} style={{ height: `${heightVh}vh`, position: 'relative' }}>
      <div style={{ position: 'sticky', top: 0, height: '100vh', display: 'flex', alignItems: 'center', overflow: 'hidden' }}>
        <div style={{ maxWidth: 1180, margin: '0 auto', padding: '0 24px', width: '100%', display: 'grid', gridTemplateColumns: '360px 1fr', gap: 28, alignItems: 'center' }}>
          {children(p)}
        </div>
      </div>
    </div>
  );
}

// ── Stage 1 — E-GraphSAGE (message passing) ───────────────────────────────
function EGraphSAGE() {
  return (
    <StageShell heightVh={320}>
      {(p) => (<>
        <div style={{ position: 'relative', height: 230 }}>
          <Caption p={p} range={[0, 0.5]} accent={C.blueSoft}
            kicker="Stage 1 · Graph"
            title="Hosts and flows"
            body="The network becomes a graph: each host is a node, each flow between them an edge carrying the 31 features. Topology exposes patterns a per-flow model can't see." />
          <Caption p={p} range={[0.5, 1]} accent={C.blue}
            kicker="Stage 1 · E-GraphSAGE"
            title="Aggregate the edges"
            body="E-GraphSAGE updates each host by sampling and aggregating the feature vectors of its incident edges — so a node's embedding reflects the behaviour of every connection touching it." />
        </div>
        <svg viewBox="0 0 760 420" style={{ width: '100%', maxHeight: '82vh' }}>
          {NEIGHBOURS.map((nb, i) => (
            <GraphEdge key={`e${i}`} p={p} revealRange={[0.12, 0.24]} a={CENTER} b={[nb.x, nb.y]} />
          ))}
          {NEIGHBOURS.map((nb, i) => (
            <GraphNode key={`n${i}`} p={p} revealRange={[0.03, 0.14]} x={nb.x} y={nb.y} label={nb.ip} />
          ))}
          <GraphNode p={p} revealRange={[0.03, 0.14]} x={CENTER[0]} y={CENTER[1]} label="core" baseColor={C.blue} rMax={26} />
          {/* message passing: neighbours → core */}
          {NEIGHBOURS.map((nb, i) => (
            <Pulse key={`p${i}`} p={p} range={[0.52 + i * 0.025, 0.78 + i * 0.025]} a={[nb.x, nb.y]} b={CENTER} color={C.blueSoft} />
          ))}
        </svg>
      </>)}
    </StageShell>
  );
}

// ── Stage 2 — GIN + GAT (attention → verdict) ─────────────────────────────
function GinGat() {
  const suspect = NEIGHBOURS[SUSPECT];
  return (
    <StageShell heightVh={340}>
      {(p) => (<>
        <div style={{ position: 'relative', height: 240 }}>
          <Caption p={p} range={[0, 0.5]} accent={C.purple}
            kicker="Stage 2 · GIN + GAT"
            title="Attention sharpens it"
            body="GIN gives maximal power to tell graph structures apart; GAT learns attention weights that spotlight the few suspicious edges that matter and down-weight routine traffic." />
          <Caption p={p} range={[0.5, 1]} accent={C.red}
            kicker="Stage 2 · Verdict"
            title="Catch lateral movement"
            body="A compromised host fans out new edges to its peers — an anomalous sub-graph. Attention lights those edges, the source node is flagged, and the engine names the attack." />
        </div>
        <svg viewBox="0 0 760 420" style={{ width: '100%', maxHeight: '82vh' }}>
          {NEIGHBOURS.map((nb, i) => {
            const hot = i === SUSPECT;
            return (
              <GraphEdge key={`e${i}`} p={p} revealRange={[0.04, 0.14]} a={CENTER} b={[nb.x, nb.y]}
                attnRange={hot ? [0.26, 0.42] : [0.26, 0.42]}
                attnColor={hot ? C.red : 'rgba(137,206,255,0.12)'}
                attnWidth={hot ? 4 : 1} width={1.6} />
            );
          })}
          {/* lateral-movement edges fanning from the suspect to peers */}
          <GraphEdge p={p} revealRange={[0.44, 0.56]} a={[suspect.x, suspect.y]} b={[NEIGHBOURS[2].x, NEIGHBOURS[2].y]} baseColor={`${C.red}99`} width={2.4} />
          <GraphEdge p={p} revealRange={[0.48, 0.60]} a={[suspect.x, suspect.y]} b={[NEIGHBOURS[0].x, NEIGHBOURS[0].y]} baseColor={`${C.red}99`} width={2.4} />
          {NEIGHBOURS.map((nb, i) => (
            <GraphNode key={`n${i}`} p={p} revealRange={[0.02, 0.12]} x={nb.x} y={nb.y} label={nb.ip}
              flagRange={i === SUSPECT ? [0.5, 0.64] : [0.999, 1]} flagColor={i === SUSPECT ? C.red : undefined}
              baseColor={C.blueSoft} />
          ))}
          <GraphNode p={p} revealRange={[0.02, 0.12]} x={CENTER[0]} y={CENTER[1]} label="core" baseColor={C.blue} rMax={26}
            flagRange={[0.56, 0.7]} flagColor={C.red} />
          <Chip p={p} range={[0.68, 0.8]} x={CENTER[0]} y={384} label="Attack · Lateral Movement" color={C.red} />
        </svg>
      </>)}
    </StageShell>
  );
}

export default function GnnLearn() {
  return (
    <div style={{ background: 'linear-gradient(rgba(5,8,10,0.55), rgba(5,8,10,0.55)), radial-gradient(1200px 600px at 50% -10%, rgba(0,212,255,0.12), transparent)', color: C.text, minHeight: '100vh' }}>
      <div style={{ maxWidth: 1180, margin: '0 auto', padding: '96px 24px 24px' }}>
        <div style={{ display: 'flex', gap: 8, marginBottom: 40, flexWrap: 'wrap' }}>
          {TABS.map((t) => {
            const active = t.stack === 'gnn';
            return (
              <Link key={t.stack} to={t.to} style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.08em', textDecoration: 'none', padding: '8px 16px', borderRadius: 999, color: active ? C.bg : t.accent, background: active ? t.accent : 'transparent', border: `1px solid ${t.accent}`, fontWeight: active ? 700 : 500 }}>{t.short}</Link>
            );
          })}
        </div>
        <header style={{ marginBottom: 24 }}>
          <div style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.2em', textTransform: 'uppercase', color: C.blueSoft, marginBottom: 16 }}>E-GraphSAGE → GIN + GAT</div>
          <h1 style={{ fontSize: 'clamp(2rem,6vw,3.4rem)', fontWeight: 800, lineHeight: 1.05, margin: '0 0 18px' }}>Graph Neural Network</h1>
          <p style={{ color: '#b9cbb9', fontSize: 18, lineHeight: 1.6, margin: 0, maxWidth: 560 }}>
            Topology-aware detection that reasons over the structure of network communication — who talks to whom, and how.
          </p>
          <p style={{ color: C.dim, fontSize: 13, marginTop: 22, fontFamily: MONO }}>Scroll to build the graph ↓</p>
        </header>
      </div>
      <EGraphSAGE />
      <GinGat />
      <div style={{ maxWidth: 720, margin: '0 auto', padding: '40px 24px 120px', textAlign: 'center' }}>
        <h2 style={{ fontSize: 'clamp(1.4rem,3vw,2rem)', fontWeight: 800, margin: '0 0 14px' }}>A structural second opinion</h2>
        <p style={{ color: '#b9cbb9', fontSize: 16, lineHeight: 1.7, margin: 0 }}>
          Single-flow models see normal-looking packets; the graph engine sees an abnormal fan-out and localises the attack to its source host.
        </p>
        <div style={{ marginTop: 28, display: 'flex', gap: 10, justifyContent: 'center' }}>
          <Link to="/learn/classical" style={{ fontFamily: MONO, fontSize: 13, textDecoration: 'none', padding: '10px 18px', borderRadius: 999, color: C.green, border: `1px solid ${C.green}` }}>Back to Classical →</Link>
        </div>
      </div>
    </div>
  );
}

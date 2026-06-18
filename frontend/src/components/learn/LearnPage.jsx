/**
 * LearnPage — unified scroll-driven "Learn" experience shared by all three
 * model stacks (gnn / deep / classical). It is data-driven: the parent route
 * passes a `scenes` array (see GnnScenes.js for the scene contract) and the
 * page renders a sticky animated graph visual alongside scroll-revealed
 * scene cards.
 *
 * Props
 *   stack        'gnn' | 'deep' | 'classical' — selects the accent + header
 *   scenes       array of scene objects to render as sections
 *   highlightIdxs (optional) node indices to highlight in the mini graph
 *   attackHueFn  (optional) (i) => 0..1 hue for the i-th highlighted node
 */
import React, { useRef, useMemo } from 'react';
import { motion, useScroll, useTransform, useReducedMotion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { BlockMath } from 'react-katex';
import 'katex/dist/katex.min.css';

const STACKS = {
  gnn: {
    label: 'Graph Neural Network',
    accent: '#89ceff',
    tagline: 'E-GraphSAGE → GIN + GAT',
    blurb: 'Topology-aware detection that reasons over the structure of network communication.',
  },
  deep: {
    label: 'Deep Learning',
    accent: '#aa66ff',
    tagline: 'DNN → DNN',
    blurb: 'Layered neural networks that learn the non-linear signatures of evolving attacks.',
  },
  classical: {
    label: 'Classical Machine Learning',
    accent: '#00ff88',
    tagline: 'XGBoost → LightGBM',
    blurb: 'Fast, interpretable gradient-boosted trees that triage traffic at line rate.',
  },
};

const TABS = [
  { stack: 'classical', to: '/learn/classical', short: 'Classical' },
  { stack: 'deep', to: '/learn/deep', short: 'Deep' },
  { stack: 'gnn', to: '/learn/gnn', short: 'Graph' },
];

// ---------------------------------------------------------------------------
// Sticky mini-graph — a small SVG network whose highlighted nodes pulse to
// echo the "attack case study" described in the scene copy.
// ---------------------------------------------------------------------------
function MiniGraph({ accent, highlightIdxs = [], attackHueFn }) {
  const reduce = useReducedMotion();
  const nodes = useMemo(() => {
    // Deterministic ring + centre layout so SSR/CSR stay identical.
    const pts = [{ x: 160, y: 160 }];
    const ring = 9;
    for (let i = 0; i < ring; i++) {
      const a = (i / ring) * Math.PI * 2;
      pts.push({ x: 160 + Math.cos(a) * 110, y: 160 + Math.sin(a) * 110 });
    }
    return pts;
  }, []);

  const highlighted = new Set(highlightIdxs);

  return (
    <svg viewBox="0 0 320 320" style={{ width: '100%', maxWidth: 360, aspectRatio: '1 / 1' }}>
      {/* edges from centre to ring */}
      {nodes.slice(1).map((n, i) => (
        <line
          key={`e${i}`}
          x1={nodes[0].x}
          y1={nodes[0].y}
          x2={n.x}
          y2={n.y}
          stroke={accent}
          strokeOpacity={highlighted.has(i + 1) ? 0.7 : 0.18}
          strokeWidth={highlighted.has(i + 1) ? 2 : 1}
        />
      ))}
      {/* nodes */}
      {nodes.map((n, i) => {
        const isHot = highlighted.has(i);
        const hue = isHot && attackHueFn ? attackHueFn(highlightIdxs.indexOf(i)) : null;
        const fill = hue != null ? `hsl(${Math.round(hue * 360)}, 90%, 62%)` : accent;
        return (
          <motion.circle
            key={`n${i}`}
            cx={n.x}
            cy={n.y}
            r={i === 0 ? 12 : 7}
            fill={fill}
            fillOpacity={isHot || i === 0 ? 0.95 : 0.5}
            animate={
              reduce || !isHot
                ? undefined
                : { r: [7, 11, 7], fillOpacity: [0.95, 0.6, 0.95] }
            }
            transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut', delay: i * 0.12 }}
          />
        );
      })}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// One scroll-revealed scene card.
// ---------------------------------------------------------------------------
function SceneCard({ scene, accent }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 40 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
      style={{
        background: 'rgba(255,255,255,0.03)',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 16,
        padding: '32px 28px',
        marginBottom: 28,
        backdropFilter: 'blur(8px)',
      }}
    >
      {scene.kicker && (
        <div
          style={{
            fontFamily: 'ui-monospace, monospace',
            fontSize: 12,
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
            color: accent,
            marginBottom: 12,
          }}
        >
          {scene.kicker}
        </div>
      )}
      <h2 style={{ fontSize: 'clamp(1.4rem, 3vw, 2rem)', fontWeight: 700, color: '#f1ffef', margin: '0 0 16px', lineHeight: 1.15 }}>
        {scene.title}
      </h2>
      {scene.body && (
        <p style={{ color: '#b9cbb9', fontSize: 16, lineHeight: 1.7, margin: '0 0 20px' }}>{scene.body}</p>
      )}
      {scene.formula && (
        <div
          style={{
            overflowX: 'auto',
            padding: '16px 12px',
            margin: '0 0 20px',
            background: 'rgba(0,0,0,0.25)',
            borderRadius: 10,
            border: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <BlockMath math={scene.formula} />
        </div>
      )}
      {Array.isArray(scene.points) && scene.points.length > 0 && (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: 10 }}>
          {scene.points.map((p, i) => (
            <li key={i} style={{ display: 'flex', gap: 10, color: '#cfe0cf', fontSize: 15, lineHeight: 1.5 }}>
              <span style={{ color: accent, flexShrink: 0 }}>▸</span>
              <span>{p}</span>
            </li>
          ))}
        </ul>
      )}
    </motion.section>
  );
}

export default function LearnPage({ stack = 'gnn', scenes = [], highlightIdxs = [], attackHueFn }) {
  const meta = STACKS[stack] || STACKS.gnn;
  const heroRef = useRef(null);
  const reduce = useReducedMotion();

  const { scrollYProgress } = useScroll();
  const barWidth = useTransform(scrollYProgress, [0, 1], ['0%', '100%']);
  const { scrollYProgress: heroProgress } = useScroll({
    target: heroRef,
    offset: ['start start', 'end start'],
  });
  const heroY = useTransform(heroProgress, [0, 1], [0, reduce ? 0 : 80]);
  const heroOpacity = useTransform(heroProgress, [0, 1], [1, 0.2]);

  return (
    <div style={{ minHeight: '100vh', background: 'radial-gradient(1200px 600px at 50% -10%, rgba(40,60,80,0.35), transparent), #05080a', color: '#f1ffef' }}>
      {/* scroll progress bar */}
      <motion.div
        style={{
          position: 'fixed',
          top: 64,
          left: 0,
          height: 3,
          background: meta.accent,
          zIndex: 60,
          width: barWidth,
          boxShadow: `0 0 12px ${meta.accent}`,
        }}
      />

      <div style={{ maxWidth: 1100, margin: '0 auto', padding: '96px 20px 80px' }}>
        {/* stack switcher */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 32, flexWrap: 'wrap' }}>
          {TABS.map((t) => {
            const active = t.stack === stack;
            const a = STACKS[t.stack].accent;
            return (
              <Link
                key={t.stack}
                to={t.to}
                style={{
                  fontFamily: 'ui-monospace, monospace',
                  fontSize: 13,
                  letterSpacing: '0.08em',
                  textDecoration: 'none',
                  padding: '8px 16px',
                  borderRadius: 999,
                  color: active ? '#05080a' : a,
                  background: active ? a : 'transparent',
                  border: `1px solid ${a}`,
                  fontWeight: active ? 700 : 500,
                }}
              >
                {t.short}
              </Link>
            );
          })}
        </div>

        {/* hero */}
        <motion.header
          ref={heroRef}
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(0, 1.3fr) minmax(0, 1fr)',
            gap: 32,
            alignItems: 'center',
            marginBottom: 64,
            y: heroY,
            opacity: heroOpacity,
          }}
        >
          <div>
            <div
              style={{
                fontFamily: 'ui-monospace, monospace',
                fontSize: 13,
                letterSpacing: '0.2em',
                textTransform: 'uppercase',
                color: meta.accent,
                marginBottom: 16,
              }}
            >
              {meta.tagline}
            </div>
            <h1 style={{ fontSize: 'clamp(2rem, 6vw, 3.4rem)', fontWeight: 800, lineHeight: 1.05, margin: '0 0 20px' }}>
              {meta.label}
            </h1>
            <p style={{ color: '#b9cbb9', fontSize: 18, lineHeight: 1.6, margin: 0, maxWidth: 520 }}>{meta.blurb}</p>
            <p style={{ color: '#6f7f6f', fontSize: 13, marginTop: 24, fontFamily: 'ui-monospace, monospace' }}>
              Scroll to explore ↓
            </p>
          </div>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <MiniGraph accent={meta.accent} highlightIdxs={highlightIdxs} attackHueFn={attackHueFn} />
          </div>
        </motion.header>

        {/* scenes */}
        {scenes.length === 0 ? (
          <div style={{ color: '#b9cbb9', textAlign: 'center', padding: '40px 0' }}>
            Content for this stage is coming soon.
          </div>
        ) : (
          scenes.map((scene) => <SceneCard key={scene.id} scene={scene} accent={meta.accent} />)
        )}
      </div>
    </div>
  );
}

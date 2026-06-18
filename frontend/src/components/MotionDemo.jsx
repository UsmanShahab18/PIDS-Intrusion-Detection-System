import React, { lazy, Suspense, useRef } from 'react';
import { motion, useScroll, useTransform, useReducedMotion } from 'framer-motion';
import {
  Login as LoginIcon,
  AccountTree as TreeIcon,
  Schema as SchemaIcon,
  Insights as InsightsIcon,
  Speed as SpeedIcon,
  VerifiedUser as ShieldIcon,
  CheckCircle as CheckIcon,
  Analytics as AnalyticsIcon,
  Bolt as BoltIcon,
  Security as SecurityIcon,
  ShieldOutlined as LogoIcon,
  NotificationsNone as BellIcon,
  SettingsOutlined as GearIcon,
  PersonOutline as PersonIcon,
} from '@mui/icons-material';

import './MotionDemo.css';

// Heavy modules are code-split — only fetched when /demo mounts.
const Starfield = lazy(() => import('./Starfield'));
const DemoCore3D = lazy(() => import('./demo/DemoCore3D'));

const STATS = [
  { icon: <SchemaIcon />, kicker: 'Architecture', value: '6 Engines × Stages', foot: 'Fully Integrated', footIcon: <CheckIcon sx={{ fontSize: 14 }} /> },
  { icon: <InsightsIcon />, kicker: 'Extraction', value: '31 Golden Features', foot: 'Real-time parsing', footIcon: <AnalyticsIcon sx={{ fontSize: 14 }} /> },
  { icon: <SpeedIcon />, kicker: 'Latency', value: '<20ms Inference', foot: 'Ultra-low delay', footIcon: <BoltIcon sx={{ fontSize: 14 }} /> },
  { icon: <ShieldIcon />, kicker: 'Reliability', value: '99.9% Uptime', foot: 'Mission critical', footIcon: <SecurityIcon sx={{ fontSize: 14 }} /> },
];

const NAV = ['Dashboard', 'Threats', 'Retraining', 'Diagnostics'];

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.1, delayChildren: 0.1 } },
};
const cardVar = {
  hidden: { opacity: 0, y: 20, scale: 0.96 },
  show: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] } },
};

export default function MotionDemo() {
  const heroRef = useRef(null);
  const reduce = useReducedMotion();

  // Scroll-driven parallax on the network core (smooth 3D depth, no WebGL).
  const { scrollYProgress } = useScroll({
    target: heroRef,
    offset: ['start start', 'end start'],
  });
  const coreY = useTransform(scrollYProgress, [0, 1], [0, reduce ? 0 : 140]);
  const coreScale = useTransform(scrollYProgress, [0, 1], [1, reduce ? 1 : 1.15]);
  const coreRotate = useTransform(scrollYProgress, [0, 1], [0, reduce ? 0 : 12]);
  const coreOpacity = useTransform(scrollYProgress, [0, 1], [0.9, 0.25]);

  return (
    <div className="cc-root">
      <div className="cc-ambient" />
      <Suspense fallback={null}>
        <Starfield count={130} />
      </Suspense>

      {/* Glass top nav */}
      <nav
        className="cc-nav"
        style={{ position: 'fixed', top: 0, width: '100%', zIndex: 50, height: 64 }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', height: '100%', maxWidth: 1280, margin: '0 auto', padding: '0 40px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 700, fontSize: 22, color: '#f1ffef', letterSpacing: '-0.02em' }}>
            <LogoIcon sx={{ color: '#00ff88' }} /> PIDS
          </div>
          <div className="cc-nav-links" style={{ display: 'flex', gap: 32, alignItems: 'center' }}>
            {NAV.map((n) => (
              <span key={n} style={{ color: '#b9cbb9', fontSize: 16, cursor: 'pointer' }}>{n}</span>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#b9cbb9' }}>
            <button className="cc-iconbtn" aria-label="Notifications" style={iconBtn}><BellIcon /></button>
            <button className="cc-iconbtn" aria-label="Settings" style={iconBtn}><GearIcon /></button>
            <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <PersonIcon sx={{ fontSize: 18 }} />
            </div>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <main style={{ position: 'relative', zIndex: 10, maxWidth: 1152, margin: '0 auto', padding: '120px 16px 64px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div ref={heroRef} className="glass-panel" style={{ width: '100%', padding: '48px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', position: 'relative', overflow: 'hidden' }}>
          {/* Parallax 3D core — real react-three-fiber scene */}
          <motion.div
            className="cc-core-mask"
            style={{ position: 'relative', width: '100%', maxWidth: 620, height: 420, margin: '0 auto 8px', y: coreY, scale: coreScale, rotate: coreRotate, opacity: coreOpacity }}
          >
            <Suspense fallback={null}>
              <DemoCore3D />
            </Suspense>
            {/* Centered engine label, like the reference */}
            <div className="mono" style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
              <span style={{ color: '#cdefff', fontSize: 18, letterSpacing: '0.2em', textShadow: '0 0 12px rgba(137,206,255,0.8)' }}>PIDS</span>
              <span style={{ color: '#89ceff', fontSize: 11, letterSpacing: '0.3em', opacity: 0.85 }}>ENGINE</span>
            </div>
          </motion.div>

          <div style={{ position: 'relative', zIndex: 10 }}>
            <h1 style={{ fontSize: 'clamp(2rem, 6vw, 3rem)', fontWeight: 700, color: '#f1ffef', margin: '0 0 24px', maxWidth: 720, lineHeight: 1.1 }}>
              Predictive <span className="neon-text" style={{ fontWeight: 700 }}>Intrusion</span> Detection
            </h1>
            <p className="mono" style={{ color: '#89ceff', marginBottom: 40, letterSpacing: '0.08em' }}>
              XGBOOST → LIGHTGBM · DNN → DNN
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 24, justifyContent: 'center' }}>
              <motion.button whileTap={{ scale: 0.97 }} className="btn-primary-glow mono" style={btn}>
                <LoginIcon sx={{ fontSize: 18 }} /> Login to Dashboard
              </motion.button>
              <motion.button whileTap={{ scale: 0.97 }} className="btn-glass-ghost mono" style={btn}>
                <TreeIcon sx={{ fontSize: 18 }} /> Explore Architecture
              </motion.button>
            </div>
          </div>
        </div>

        {/* Stat cards */}
        <motion.div
          variants={container}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: '-60px' }}
          style={{ display: 'grid', gap: 24, width: '100%', marginTop: 48, gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}
        >
          {STATS.map((s) => (
            <motion.div key={s.kicker} variants={cardVar} className="glass-card" style={{ padding: 24, position: 'relative', overflow: 'hidden' }}>
              <div style={{ position: 'absolute', right: -16, top: -16, color: 'rgba(255,255,255,0.05)' }}>
                {React.cloneElement(s.icon, { sx: { fontSize: 110 } })}
              </div>
              <div className="mono" style={{ color: '#b9cbb9', marginBottom: 8, fontSize: 14, position: 'relative' }}>{s.kicker}</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#f1ffef', position: 'relative', letterSpacing: '-0.01em' }}>{s.value}</div>
              <div style={{ height: 1, background: 'rgba(255,255,255,0.1)', margin: '16px 0 8px' }} />
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#b9cbb9' }}>
                <span style={{ color: '#00ff88', display: 'inline-flex' }}>{s.footIcon}</span>{s.foot}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </main>
    </div>
  );
}

const iconBtn = { width: 40, height: 40, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'inherit', background: 'transparent', border: 'none', cursor: 'pointer' };
const btn = { display: 'inline-flex', alignItems: 'center', gap: 8, padding: '16px 32px', fontSize: 12, letterSpacing: '0.15em', border: 'none' };

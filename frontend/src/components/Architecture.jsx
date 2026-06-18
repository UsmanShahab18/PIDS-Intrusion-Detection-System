/**
 * Architecture — System pipeline + interactive 3D model showcase.
 *
 * Big single Three.js scene that swaps its central object based on the
 * active model tab:
 *
 *   XGBoost   — a binary decision tree (Stage-1 classical ML)
 *   LightGBM  — a stack of gradient-boosted trees (Stage-2 classical ML)
 *   DNN       — a dense multi-layer perceptron (DL engine)
 *   GNN       — a graph neural network with KNN-style edges (new engine)
 *
 * Tab switches smoothly fade the previous model out and the next one in;
 * the camera holds steady so the user sees a clean morph.
 *
 * Below the scene: live metrics for the active model + the existing
 * pipeline / tech-stack content (unchanged in meaning, restyled).
 */
import React, { useEffect, useRef, useState } from 'react';
import { Box, Container, Typography, Paper, Grid, Stack, Chip, Button } from '@mui/material';
import {
  Psychology as AIIcon,
  Storage as DatabaseIcon,
  Router as NetworkIcon,
  Code as CodeIcon,
  Cloud as CloudIcon,
  ArrowForward as ArrowIcon,
  Speed as SpeedIcon,
  Bolt as DLIcon,
  Functions as MLIcon,
  Hub as GNNIcon,
} from '@mui/icons-material';
import * as THREE from 'three';


// ---------------------------------------------------------------------------
// Model metadata + Three.js builders
// ---------------------------------------------------------------------------
const MODELS = {
  xgboost: {
    label: 'XGBoost',
    sub: 'Stage 1 · Binary Classifier (Normal vs Attack)',
    // amber keeps XGBoost visually distinct from LightGBM (cyan) and
    // GNN (mint) — the four model tabs each get their own colour.
    accent: '#ffb627',
    icon: MLIcon,
    metrics: [
      { k: 'Accuracy',  v: '98.24%' },
      { k: 'Type',      v: 'Gradient-boosted trees' },
      { k: 'Role',      v: 'Stage 1 — binary head' },
      { k: 'Output',    v: 'Normal | Attack' },
    ],
    blurb: 'A tree-ensemble classical-ML model trained on 31 golden CICIDS-2018 features. Fast, interpretable, and the production default for stage-1 routing.',
  },
  lightgbm: {
    label: 'LightGBM',
    sub: 'Stage 2 · 14-class Attack Categoriser',
    accent: '#00d4ff',
    icon: MLIcon,
    metrics: [
      { k: 'Accuracy',  v: '95.66%' },
      { k: 'Type',      v: 'Histogram-based GBDT' },
      { k: 'Role',      v: 'Stage 2 — multi-class head' },
      { k: 'Output',    v: '14 attack classes' },
    ],
    blurb: 'A second tree ensemble that takes only flows stage 1 flagged as Attack and labels them with one of fourteen CICIDS-2018 attack classes (Infiltration included).',
  },
  dnn: {
    label: 'DNN',
    sub: 'Two-stage Deep Neural Network (Keras)',
    accent: '#aa66ff',
    icon: DLIcon,
    metrics: [
      { k: 'Accuracy',         v: '98.36%' },
      { k: 'Type',             v: 'Dense MLP × 2' },
      { k: 'Role',             v: 'Pluggable DL engine' },
      { k: 'Infiltration F1',  v: '0.27' },
    ],
    blurb: 'Two sequential dense networks: stage 1 binary, stage 2 13-class softmax (Infiltration intentionally excluded — the LLM compensates via low-confidence routing).',
  },
  gnn: {
    label: 'GNN',
    sub: 'Two-Stage Graph Neural Network (E-GraphSAGE + GIN)',
    accent: '#4d9d7e',
    icon: GNNIcon,
    metrics: [
      { k: 'Accuracy',         v: '87.85%' },
      { k: 'Type',             v: 'SAGE+GAT / GIN+GAT' },
      { k: 'Role',             v: 'New pluggable engine' },
      { k: 'Infiltration F1',  v: '0.63  (2.34× better)' },
    ],
    blurb: 'Relational model: flows are nodes, edges are same-Dst-Port + KNN(k=8) + self-loops. Lower overall accuracy than ML/DL but 2.34× better Infiltration F1 — opt-in for stealthy lateral-movement detection.',
  },
};

/** Build a binary decision tree: 1 root, 2 children, 4 grandchildren. */
function buildXGBoostGroup(color) {
  const g = new THREE.Group();
  const mat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 1 });
  const lineMat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.7 });
  const sphereGeo = new THREE.SphereGeometry(0.22, 18, 18);

  // depth, x-spread, y-level
  const nodes = [
    { pos: [0,  1.6, 0] },
    { pos: [-1.4, 0.4, 0] }, { pos: [ 1.4, 0.4, 0] },
    { pos: [-2.1, -0.9, 0] }, { pos: [-0.6, -0.9, 0] },
    { pos: [ 0.6, -0.9, 0] }, { pos: [ 2.1, -0.9, 0] },
  ];
  const meshes = nodes.map((n) => {
    const m = new THREE.Mesh(sphereGeo, mat.clone());
    m.position.set(...n.pos);
    g.add(m);
    return m;
  });
  // edges
  const edges = [[0,1],[0,2],[1,3],[1,4],[2,5],[2,6]];
  edges.forEach(([a,b]) => {
    const line = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints([
        meshes[a].position, meshes[b].position,
      ]),
      lineMat.clone()
    );
    g.add(line);
  });
  return g;
}

/** LightGBM — three small offset trees representing boosting rounds. */
function buildLightGBMGroup(color) {
  const g = new THREE.Group();
  const offsets = [-2.2, 0, 2.2];
  offsets.forEach((dx, i) => {
    const t = buildXGBoostGroup(color);
    t.position.x = dx;
    t.position.z = -i * 0.6;
    t.scale.setScalar(0.65);
    // make later trees more transparent — visual analogy for residual learners.
    // `baseOpacity` is the value the fade loop in Architecture.jsx lerps toward
    // when this group is the active tab (active target × baseOpacity).
    t.traverse((o) => {
      if (o.material) {
        o.material = o.material.clone();
        o.material.transparent = true;
        const base = 1 - i * 0.25;
        o.material.userData = { ...(o.material.userData || {}), baseOpacity: base };
        o.material.opacity = base;
      }
    });
    g.add(t);
  });
  return g;
}

/** DNN — 4 columns of nodes, fully connected. */
function buildDNNGroup(color) {
  const g = new THREE.Group();
  const layers = [4, 6, 6, 3];                  // input → 2 hidden → output
  const spacing = 1.3;
  const sphereGeo = new THREE.SphereGeometry(0.15, 14, 14);
  const matBase = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 1 });
  const lineMat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.18 });

  const positions = [];
  layers.forEach((count, li) => {
    const x = (li - (layers.length - 1) / 2) * spacing;
    const layer = [];
    for (let i = 0; i < count; i++) {
      const y = (i - (count - 1) / 2) * 0.55;
      const m = new THREE.Mesh(sphereGeo, matBase.clone());
      m.position.set(x, y, 0);
      g.add(m);
      layer.push(m.position);
    }
    positions.push(layer);
  });
  // fully-connect adjacent layers
  for (let li = 0; li < positions.length - 1; li++) {
    positions[li].forEach((a) => {
      positions[li + 1].forEach((b) => {
        const line = new THREE.Line(
          new THREE.BufferGeometry().setFromPoints([a, b]),
          lineMat.clone()
        );
        g.add(line);
      });
    });
  }
  return g;
}

/** GNN — random nodes with KNN-style edges in a spherical cloud. */
function buildGNNGroup(color) {
  const g = new THREE.Group();
  const N = 26;
  const sphereGeo = new THREE.SphereGeometry(0.13, 14, 14);
  const matBase = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 1 });
  const lineMat = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.35 });

  // sample points on/inside a sphere
  const pts = [];
  for (let i = 0; i < N; i++) {
    const r = 1.6 + Math.random() * 0.4;
    const u = Math.random(), v = Math.random();
    const theta = 2 * Math.PI * u;
    const phi = Math.acos(2 * v - 1);
    const p = new THREE.Vector3(
      r * Math.sin(phi) * Math.cos(theta),
      r * Math.sin(phi) * Math.sin(theta),
      r * Math.cos(phi)
    );
    pts.push(p);
    const m = new THREE.Mesh(sphereGeo, matBase.clone());
    m.position.copy(p);
    g.add(m);
  }
  // K nearest neighbours edges
  const K = 3;
  pts.forEach((p, i) => {
    const dists = pts
      .map((q, j) => ({ j, d: i === j ? Infinity : p.distanceToSquared(q) }))
      .sort((a, b) => a.d - b.d).slice(0, K);
    dists.forEach(({ j }) => {
      if (j < i) return; // avoid duplicates
      const line = new THREE.Line(
        new THREE.BufferGeometry().setFromPoints([p, pts[j]]),
        lineMat.clone()
      );
      g.add(line);
    });
  });
  return g;
}

const BUILDERS = {
  xgboost: buildXGBoostGroup,
  lightgbm: buildLightGBMGroup,
  dnn: buildDNNGroup,
  gnn: buildGNNGroup,
};


// ---------------------------------------------------------------------------
// Architecture page component
// ---------------------------------------------------------------------------
const Architecture = () => {
  const containerRef = useRef(null);
  const groupsRef = useRef({});       // { xgboost: Group, lightgbm: Group, ... }
  const targetsRef = useRef({});      // { xgboost: 0..1, ... }
  const [active, setActive] = useState('xgboost');

  // ---- mount Three.js scene once ----
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const W = container.clientWidth;
    const H = 460;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setSize(W, H);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, W / H, 0.1, 100);
    camera.position.set(0, 0.4, 6.5);

    scene.add(new THREE.AmbientLight(0x6090ff, 0.6));
    const pl1 = new THREE.PointLight(0xffffff, 0.6); pl1.position.set(5, 4, 6); scene.add(pl1);

    // gentle backdrop ring so the scene doesn't feel empty
    const ring = new THREE.Mesh(
      new THREE.TorusGeometry(3.6, 0.015, 16, 200),
      new THREE.MeshBasicMaterial({ color: 0x00d4ff, transparent: true, opacity: 0.25 })
    );
    ring.rotation.x = Math.PI / 2;
    ring.position.y = -1.4;
    scene.add(ring);

    // build all 4 groups; start hidden, fade the active one in
    Object.entries(BUILDERS).forEach(([key, build]) => {
      const grp = build(new THREE.Color(MODELS[key].accent));
      scene.add(grp);
      // collect all materials so we can fade them as one
      const mats = [];
      grp.traverse((o) => { if (o.material) mats.push(o.material); });
      grp.userData.mats = mats;
      groupsRef.current[key] = grp;
      targetsRef.current[key] = key === 'xgboost' ? 1 : 0;
    });

    // mouse parallax limited to scene container
    let mx = 0, my = 0, tmx = 0, tmy = 0;
    const onMove = (e) => {
      const rect = container.getBoundingClientRect();
      tmx = ((e.clientX - rect.left) / rect.width - 0.5) * 0.6;
      tmy = ((e.clientY - rect.top) / rect.height - 0.5) * 0.4;
    };
    container.addEventListener('mousemove', onMove);

    const onResize = () => {
      const nw = container.clientWidth;
      camera.aspect = nw / H;
      camera.updateProjectionMatrix();
      renderer.setSize(nw, H);
    };
    window.addEventListener('resize', onResize);

    const clock = new THREE.Clock();
    let rafId = 0;
    const animate = () => {
      const t = clock.getElapsedTime();

      mx += (tmx - mx) * 0.06;
      my += (tmy - my) * 0.06;

      Object.entries(groupsRef.current).forEach(([key, grp]) => {
        // fade opacity toward target
        const target = targetsRef.current[key];
        const mats = grp.userData.mats;
        let avg = 0;
        for (const m of mats) {
          m.opacity += (target * (m.userData?.baseOpacity ?? 1) - m.opacity) * 0.08;
          avg += m.opacity;
        }
        avg /= mats.length || 1;
        // only rotate / show the visible group(s)
        grp.visible = avg > 0.01;
        if (grp.visible) {
          grp.rotation.y = t * 0.25 + mx * 0.6;
          grp.rotation.x = my * 0.3;
        }
      });

      ring.rotation.z = t * 0.08;

      renderer.render(scene, camera);
      rafId = requestAnimationFrame(animate);
    };
    animate();

    return () => {
      cancelAnimationFrame(rafId);
      container.removeEventListener('mousemove', onMove);
      window.removeEventListener('resize', onResize);
      // dispose everything we created
      Object.values(groupsRef.current).forEach((grp) => {
        grp.traverse((o) => {
          if (o.geometry) o.geometry.dispose();
          if (o.material) o.material.dispose();
        });
      });
      ring.geometry.dispose(); ring.material.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
    };
  }, []);

  // ---- update fade targets on tab change ----
  useEffect(() => {
    Object.keys(targetsRef.current).forEach((k) => {
      targetsRef.current[k] = k === active ? 1 : 0;
    });
  }, [active]);

  const meta = MODELS[active];

  // ---- scroll fade-in for cards ----
  const revealRef = useRef([]);
  useEffect(() => {
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => {
        if (e.isIntersecting) e.target.classList.add('rev-in');
      }),
      { threshold: 0.15 }
    );
    revealRef.current.forEach((el) => el && io.observe(el));
    return () => io.disconnect();
  }, []);
  const addRev = (i) => (el) => { revealRef.current[i] = el; };

  return (
    <Box sx={{
      minHeight: '100vh',
      bgcolor: 'transparent', // reveal the global Cyber3DBackground
      py: 4,
    }}>
      {/* tiny inline keyframes for reveal */}
      <style>{`
        .rev { opacity: 0; transform: translateY(28px); transition: opacity .8s ease, transform .8s ease; }
        .rev.rev-in { opacity: 1; transform: translateY(0); }
      `}</style>

      <Container maxWidth="xl">
        {/* ============================ HEADER ============================ */}
        <Box sx={{ textAlign: 'center', mb: 4 }} ref={addRev(0)} className="rev">
          <Typography variant="overline" sx={{
            color: '#00d4ff', letterSpacing: '0.4em', fontFamily: 'Share Tech Mono',
          }}>
            PIDS · System Architecture
          </Typography>
          <Typography sx={{
            mt: 1, mb: 1.5,
            fontWeight: 800, lineHeight: 1.02, letterSpacing: '-0.02em',
            fontSize: { xs: '2rem', md: '3.4rem' },
            background: 'linear-gradient(180deg, #fff 0%, #b9d8ff 60%, #6aa6ff 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
          }}>
            Four Models, One Pipeline
          </Typography>
          <Typography sx={{ color: '#9bb1cf', maxWidth: 760, mx: 'auto' }}>
            PIDS ships <strong>four pluggable detection models</strong> behind a single
            two-stage pipeline. Switch tabs to inspect each model in 3D — admins
            select the active engine at runtime from the admin panel.
          </Typography>
        </Box>

        {/* ============================ MODEL TABS + 3D ============================ */}
        <Paper
          ref={addRev(1)}
          className="rev"
          sx={{
            p: { xs: 2, md: 3 },
            bgcolor: 'rgba(10, 18, 36, 0.55)',
            border: '1px solid rgba(0, 212, 255, 0.20)',
            backdropFilter: 'blur(12px) saturate(1.05)',
            borderRadius: 3,
            mb: 4,
            overflow: 'hidden',
            position: 'relative',
          }}
        >
          {/* tab strip */}
          <Stack direction="row" spacing={1.2} flexWrap="wrap" useFlexGap sx={{ mb: 2 }}>
            {Object.entries(MODELS).map(([key, m]) => {
              const Icon = m.icon;
              const isActive = key === active;
              return (
                <Button
                  key={key}
                  onClick={() => setActive(key)}
                  startIcon={<Icon />}
                  sx={{
                    fontFamily: 'Share Tech Mono',
                    letterSpacing: '0.15em',
                    fontWeight: 700,
                    px: 2.2, py: 1,
                    borderRadius: 2,
                    color: isActive ? '#001821' : m.accent,
                    backgroundColor: isActive ? m.accent : 'rgba(255,255,255,0.02)',
                    border: `1px solid ${isActive ? m.accent : 'rgba(255,255,255,0.10)'}`,
                    boxShadow: isActive ? `0 0 18px ${m.accent}66` : 'none',
                    transition: 'all .15s',
                    '&:hover': {
                      backgroundColor: isActive ? m.accent : `${m.accent}22`,
                      borderColor: m.accent,
                    },
                  }}
                >
                  {m.label}
                </Button>
              );
            })}
          </Stack>

          {/* 3D canvas + side panel */}
          <Grid container spacing={2}>
            <Grid item xs={12} md={7}>
              <Box
                ref={containerRef}
                sx={{
                  width: '100%',
                  height: 460,
                  borderRadius: 2,
                  background:
                    'radial-gradient(ellipse at 50% 30%, rgba(0,212,255,0.10), transparent 70%), rgba(0,0,0,0.35)',
                  border: '1px solid rgba(0, 212, 255, 0.18)',
                  overflow: 'hidden',
                }}
              />
            </Grid>

            {/* Side info */}
            <Grid item xs={12} md={5}>
              <Box sx={{ p: 1, height: '100%' }}>
                <Stack direction="row" alignItems="center" spacing={1.2} mb={1}>
                  <Box sx={{
                    width: 38, height: 38, borderRadius: 1.2,
                    display: 'grid', placeItems: 'center',
                    bgcolor: `${meta.accent}1F`,
                    border: `1px solid ${meta.accent}66`,
                    color: meta.accent,
                  }}>
                    <meta.icon />
                  </Box>
                  <Box>
                    <Typography sx={{
                      fontFamily: 'Share Tech Mono', color: meta.accent,
                      fontSize: '1.25rem', fontWeight: 700, lineHeight: 1.1,
                    }}>
                      {meta.label}
                    </Typography>
                    <Typography sx={{ color: '#9bb1cf', fontSize: '0.85rem' }}>
                      {meta.sub}
                    </Typography>
                  </Box>
                </Stack>

                <Typography sx={{ color: '#cfd9ee', fontSize: '0.95rem', mt: 1.5 }}>
                  {meta.blurb}
                </Typography>

                <Box sx={{
                  mt: 2,
                  display: 'grid',
                  gridTemplateColumns: { xs: '1fr 1fr', sm: '1fr 1fr' },
                  gap: 1.2,
                }}>
                  {meta.metrics.map(({ k, v }) => (
                    <Paper key={k} sx={{
                      p: 1.4,
                      bgcolor: 'rgba(0,0,0,0.4)',
                      border: '1px solid rgba(255,255,255,0.06)',
                      borderRadius: 1.5,
                    }}>
                      <Typography sx={{
                        fontSize: '0.68rem', color: '#7e93b6',
                        letterSpacing: '0.22em', fontFamily: 'Share Tech Mono',
                        textTransform: 'uppercase', mb: 0.4,
                      }}>{k}</Typography>
                      <Typography sx={{
                        color: meta.accent, fontFamily: 'Share Tech Mono',
                        fontSize: '0.98rem', fontWeight: 700,
                      }}>{v}</Typography>
                    </Paper>
                  ))}
                </Box>

                <Stack direction="row" spacing={1} sx={{ mt: 2 }} flexWrap="wrap" useFlexGap>
                  <Chip size="small" label="31 features" sx={{
                    bgcolor: 'rgba(255,255,255,0.06)', color: '#cfd9ee',
                    fontFamily: 'Share Tech Mono',
                  }} />
                  <Chip size="small" label="CICIDS-2018" sx={{
                    bgcolor: 'rgba(255,255,255,0.06)', color: '#cfd9ee',
                    fontFamily: 'Share Tech Mono',
                  }} />
                  {active === 'gnn' && (
                    <Chip size="small" label="NEW · Opt-in" sx={{
                      bgcolor: `${meta.accent}33`, color: meta.accent,
                      border: `1px solid ${meta.accent}`,
                      fontFamily: 'Share Tech Mono', fontWeight: 700,
                    }} />
                  )}
                </Stack>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* ============================ DETECTION PIPELINE ============================ */}
        <Typography
          variant="h5"
          ref={addRev(2)}
          className="rev"
          sx={{
            color: '#00d4ff', mb: 2, fontFamily: 'Share Tech Mono',
            letterSpacing: '0.18em', textTransform: 'uppercase', fontSize: '1rem',
          }}
        >
          ◆ Detection Pipeline
        </Typography>

        <Paper
          ref={addRev(3)}
          className="rev"
          sx={{
            p: { xs: 2, md: 3 }, mb: 4,
            bgcolor: 'rgba(10, 18, 36, 0.55)',
            border: '1px solid rgba(0, 212, 255, 0.20)',
            backdropFilter: 'blur(12px)',
            borderRadius: 3,
          }}
        >
          <Grid container spacing={2} alignItems="center" justifyContent="center">
            {[
              { stage: 'Stage 1', name: 'XGBoost / DNN / GNN', color: '#4d9d7e', icon: <SpeedIcon />, sub: 'Binary head — Normal vs Attack' },
              { stage: 'Stage 2', name: 'LightGBM / DNN / GNN', color: '#2196f3', icon: <AIIcon />, sub: 'Multi-class attack categoriser' },
              { stage: 'Stage 3', name: 'Ollama Mistral 7B', color: '#9c27b0', icon: <CloudIcon />, sub: 'LLM behavioural analysis · CVE / DDG' },
              { stage: 'Stage 4', name: 'Rate Detector', color: '#ff9800', icon: <NetworkIcon />, sub: 'Connection-flood / brute-force trigger' },
            ].map((s, i, arr) => (
              <React.Fragment key={s.stage}>
                <Grid item xs={12} sm={6} md={2.5}>
                  <Paper sx={{
                    p: 2.4,
                    bgcolor: `${s.color}14`,
                    border: `1.5px solid ${s.color}`,
                    borderRadius: 2,
                    textAlign: 'center',
                    minHeight: 170,
                  }}>
                    {React.cloneElement(s.icon, { sx: { fontSize: 32, color: s.color, mb: 0.5 } })}
                    <Typography sx={{ color: s.color, fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }}>
                      {s.stage}
                    </Typography>
                    <Typography sx={{ color: s.color, fontWeight: 700, mt: 0.5 }}>
                      {s.name}
                    </Typography>
                    <Typography sx={{ color: '#9bb1cf', fontSize: '0.8rem', mt: 0.5 }}>
                      {s.sub}
                    </Typography>
                  </Paper>
                </Grid>
                {i < arr.length - 1 && (
                  <Grid item xs={12} md={0.4} sx={{ textAlign: 'center', display: { xs: 'none', md: 'block' } }}>
                    <ArrowIcon sx={{ fontSize: 26, color: '#00d4ff' }} />
                  </Grid>
                )}
              </React.Fragment>
            ))}
          </Grid>

          <Box sx={{
            mt: 3, p: 2.4,
            border: '1px dashed rgba(0, 212, 255, 0.55)',
            borderRadius: 2,
            bgcolor: 'rgba(0, 212, 255, 0.04)',
          }}>
            <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontWeight: 700, mb: 0.5 }}>
              ⚙ Pluggable Engine Architecture
            </Typography>
            <Typography sx={{ color: '#cfd9ee', fontSize: '0.95rem' }}>
              Stages 1 &amp; 2 are served by <strong>three interchangeable engines</strong> —
              <Box component="span" sx={{ color: '#4d9d7e', mx: 0.5 }}>ML (XGBoost + LightGBM)</Box>,
              <Box component="span" sx={{ color: '#aa66ff', mx: 0.5 }}>DL (two-stage DNN)</Box>, or the
              new <Box component="span" sx={{ color: '#4d9d7e', mx: 0.5 }}>GNN</Box> engine. The active
              engine is selected at runtime from the admin panel; no Django restart required.
            </Typography>
          </Box>
        </Paper>

        {/* ============================ TECH STACK ============================ */}
        <Typography
          variant="h5"
          ref={addRev(4)}
          className="rev"
          sx={{
            color: '#00d4ff', mb: 2, fontFamily: 'Share Tech Mono',
            letterSpacing: '0.18em', textTransform: 'uppercase', fontSize: '1rem',
          }}
        >
          ◆ Technology Stack
        </Typography>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            {
              title: 'Frontend', color: '#2196f3', icon: <CodeIcon />,
              items: ['React 18', 'Material-UI', 'Recharts', 'Three.js', 'Axios'],
            },
            {
              title: 'Backend', color: '#4d9d7e', icon: <DatabaseIcon />,
              items: ['Django 4.2 + DRF', 'PostgreSQL', 'Channels + Redis', 'Scapy', 'JWT RBAC'],
            },
            {
              title: 'ML / DL / GNN / AI', color: '#9c27b0', icon: <AIIcon />,
              items: [
                'XGBoost · LightGBM',
                'DNN (TensorFlow / Keras)',
                'GNN (PyTorch + torch-geometric)',
                'Ollama Mistral 7B',
                'Scikit-learn',
              ],
            },
          ].map((box, idx) => (
            <Grid item xs={12} md={4} key={box.title}>
              <Paper
                ref={addRev(5 + idx)}
                className="rev"
                sx={{
                  p: 2.6, height: '100%',
                  bgcolor: 'rgba(10, 18, 36, 0.55)',
                  border: `1px solid ${box.color}55`,
                  borderRadius: 3,
                  backdropFilter: 'blur(10px)',
                  transition: 'all .25s',
                  '&:hover': {
                    border: `1px solid ${box.color}`,
                    boxShadow: `0 0 20px ${box.color}33`,
                    transform: 'translateY(-3px)',
                  },
                }}
              >
                <Stack direction="row" alignItems="center" spacing={1.4} mb={1.5}>
                  <Box sx={{ color: box.color }}>{box.icon}</Box>
                  <Typography sx={{ color: box.color, fontFamily: 'Share Tech Mono', fontWeight: 700 }}>
                    {box.title}
                  </Typography>
                </Stack>
                <Box component="ul" sx={{
                  m: 0, pl: 2.4, color: '#cfd9ee', fontSize: '0.92rem', lineHeight: 1.7,
                }}>
                  {box.items.map((it) => <li key={it}>{it}</li>)}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ============================ KEY FEATURES ============================ */}
        <Typography
          variant="h5"
          ref={addRev(8)}
          className="rev"
          sx={{
            color: '#00d4ff', mb: 2, fontFamily: 'Share Tech Mono',
            letterSpacing: '0.18em', textTransform: 'uppercase', fontSize: '1rem',
          }}
        >
          ◆ Key Capabilities
        </Typography>

        <Grid container spacing={2}>
          {[
            { title: 'Real-time Detection', desc: 'Live Scapy packet capture, sub-second inference, instant WebSocket alerts.', color: '#00bcd4' },
            { title: 'Hybrid ML Pipeline',  desc: 'Four-stage classification combining tabular ML, deep learning, and graph reasoning.', color: '#4d9d7e' },
            { title: 'LLM Threat Intel',    desc: 'Local Ollama Mistral 7B enriches suspicious flows with explanations and CVE context.', color: '#9c27b0' },
            { title: 'Zero-Day Detection',  desc: 'Behavioural anomaly analysis + DuckDuckGo lookups to surface unknown attack patterns.', color: '#ff3b6b' },
            { title: 'Online Retraining',   desc: 'Operators can retrain ML and DL models on accumulated flows without downtime.', color: '#ff9800' },
            { title: 'GNN — New',           desc: '2.34× better Infiltration detection vs DNN. Opt-in via admin panel.', color: '#4d9d7e' },
          ].map((f, i) => (
            <Grid item xs={12} sm={6} md={4} key={f.title}>
              <Paper
                ref={addRev(9 + i)}
                className="rev"
                sx={{
                  p: 2.4, height: '100%',
                  bgcolor: 'rgba(10, 18, 36, 0.5)',
                  border: `1px solid ${f.color}44`,
                  borderLeft: `4px solid ${f.color}`,
                  borderRadius: 2,
                  backdropFilter: 'blur(8px)',
                }}
              >
                <Typography sx={{
                  color: f.color, mb: 0.5, fontFamily: 'Share Tech Mono', fontWeight: 700,
                }}>
                  {f.title}
                </Typography>
                <Typography sx={{ color: '#9bb1cf', fontSize: '0.9rem' }}>
                  {f.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </Container>
    </Box>
  );
};

export default Architecture;

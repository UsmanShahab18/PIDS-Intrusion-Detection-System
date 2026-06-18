/**
 * LandingPage — public entry. Lets the global Cyber3DBackground (mounted
 * at the App shell, zIndex: -1) be the only 3D element so the page no
 * longer stacks two competing scenes on top of each other.
 *
 * Structure:
 *   - Hero: eyebrow chip + headline + tagline + CTA (Dashboard if
 *     authenticated, Login otherwise)
 *   - Meta pills (flows/sec, models, uptime, latency) — purely
 *     decorative; values are mocked client-side
 *   - Core Features cards (ML+DL, LLM, Real-Time)
 *   - Tech stack chip cloud
 *   - Final CTA
 *
 * Reveal-on-scroll uses IntersectionObserver (no GSAP dependency).
 */
import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Box, Container, Typography, Button, Grid, Paper, Chip, Stack,
} from '@mui/material';
import {
  Memory as MLIcon,
  Hub as GNNIcon,
  Psychology as LLMIcon,
  Bolt as RealtimeIcon,
  ArrowForward as ArrowIcon,
  Shield as ShieldIcon,
  Login as LoginIcon,
} from '@mui/icons-material';


// ---------------------------------------------------------------------------
// Static content
// ---------------------------------------------------------------------------

/**
 * Three engines — the project's evolution. Every engine has the same
 * two-stage shape: Stage 1 is a binary head (Benign vs Attack); Stage 2
 * is a multi-class attack categoriser. Only the underlying model
 * family changes between engines.
 */
const ENGINES = [
  {
    key: 'ml',
    iter: 'ITERATION 01',
    title: 'Classical ML',
    sub: 'The baseline.',
    accent: '#00d4ff',
    icon: MLIcon,
    stage1: 'XGBoost',
    stage2: 'LightGBM',
    blurb: 'Started here. Two gradient-boosted trees — a fast, interpretable, strong tabular baseline. Still production-grade.',
  },
  {
    key: 'dl',
    iter: 'ITERATION 02',
    title: 'Deep Learning',
    sub: 'Suggested upgrade — go deeper.',
    accent: '#aa66ff',
    icon: RealtimeIcon,
    stage1: 'DNN',
    stage2: 'DNN',
    blurb: 'Internal recommendation: replace the trees with a two-stage Keras DNN. Best end-to-end accuracy of the three engines.',
  },
  // GNN iteration disabled until a trained model ships.
];

const FEATURES = [
  {
    icon: MLIcon, accent: '#00d4ff', title: '2 Pluggable Engines',
    body: 'ML and DL engines both expose the same two-stage interface. Switch the active engine at runtime from the admin panel — no Django restart.',
  },
  {
    icon: LLMIcon, accent: '#ff3df0', title: 'LLM Threat Intelligence',
    body: 'Local Ollama Mistral 7B enriches suspicious flows with CVE context and natural-language remediation tips.',
  },
  {
    icon: RealtimeIcon, accent: '#ffb627', title: 'Real-Time Defense',
    body: 'Live Scapy packet capture, sub-second inference, instant WebSocket alerts to the dashboard.',
  },
];

const STACK = [
  'Django 4.2', 'DRF', 'Channels', 'Redis', 'PostgreSQL',
  'React 18', 'Material-UI', 'Three.js',
  'XGBoost', 'LightGBM', 'TensorFlow / Keras',
  'Ollama · Mistral 7B', 'Scapy', 'JWT RBAC',
];


// ---------------------------------------------------------------------------
// Reveal hook
// ---------------------------------------------------------------------------
function useReveal() {
  const refs = useRef([]);
  useEffect(() => {
    const io = new IntersectionObserver(
      (entries) => entries.forEach((e) => e.isIntersecting && e.target.classList.add('rev-in')),
      { threshold: 0.12 }
    );
    refs.current.forEach((el) => el && io.observe(el));
    return () => io.disconnect();
  }, []);
  return (i) => (el) => { refs.current[i] = el; };
}


// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
const LandingPage = () => {
  const isLoggedIn = !!sessionStorage.getItem('pids_tokens');
  const addRev = useReveal();

  // typewriter tagline
  const FULL = 'XGBoost → LightGBM · DNN → DNN.';
  const [typed, setTyped] = useState('');
  useEffect(() => {
    let i = 0;
    const id = setInterval(() => {
      i++;
      setTyped(FULL.slice(0, i));
      if (i >= FULL.length) clearInterval(id);
    }, 32);
    return () => clearInterval(id);
  }, []);

  return (
    <Box sx={{
      minHeight: '100vh',
      // transparent so the global Cyber3DBackground (App-shell, zIndex -1)
      // is the only 3D element on this page.
      bgcolor: 'transparent',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* tiny reveal CSS */}
      <style>{`
        .rev { opacity: 0; transform: translateY(28px); transition: opacity .8s ease, transform .8s ease; }
        .rev.rev-in { opacity: 1; transform: translateY(0); }
        @keyframes blink { 50% { opacity: .3 } }
        .cursor { display:inline-block; width:.6ch; animation: blink 1s steps(2) infinite; color:#00d4ff; }
        @keyframes drift { 0%,100%{ transform: translateY(0)} 50%{ transform: translateY(6px)} }
      `}</style>

      <Container maxWidth="lg" sx={{ position: 'relative', zIndex: 2 }}>
        {/* ============================ HERO ============================ */}
        <Box sx={{
          minHeight: { xs: '92vh', md: '94vh' },
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          textAlign: 'center', py: { xs: 6, md: 8 },
        }} ref={addRev(0)} className="rev">

          <Chip
            icon={<ShieldIcon sx={{ color: '#4d9d7e !important' }} />}
            label="PIDS 3D CORE · COMMAND CENTER ONLINE"
            sx={{
              fontFamily: 'Share Tech Mono', letterSpacing: '.35em',
              color: '#00d4ff', fontSize: '.72rem',
              border: '1px solid rgba(0, 212, 255, 0.35)',
              background: 'rgba(0, 212, 255, 0.06)',
              backdropFilter: 'blur(6px)',
              px: .5,
            }}
          />

          <Typography sx={{
            mt: 3, fontWeight: 800, lineHeight: 1.02, letterSpacing: '-0.02em',
            fontSize: { xs: '2.4rem', sm: '3.4rem', md: '5rem' },
            background: 'linear-gradient(180deg, #ffffff 0%, #b9d8ff 55%, #6aa6ff 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            textShadow: '0 0 60px rgba(0, 200, 255, 0.15)',
          }}>
            PREDICTIVE&nbsp;
            <Box component="span" sx={{
              background: 'linear-gradient(90deg, #00d4ff, #ff3df0)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>
              INTRUSION
            </Box>
            &nbsp;DETECTION
          </Typography>

          <Typography sx={{
            mt: 2, color: '#9bb1cf',
            fontFamily: 'Share Tech Mono',
            letterSpacing: '.18em', textTransform: 'uppercase',
            fontSize: { xs: '.8rem', md: '.95rem' },
            minHeight: '1.4em',
          }}>
            {typed}<span className="cursor">▌</span>
          </Typography>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ mt: 5 }}>
            <Button
              component={Link}
              to={isLoggedIn ? '/dashboard' : '/login'}
              variant="contained"
              endIcon={<ArrowIcon />}
              startIcon={!isLoggedIn ? <LoginIcon /> : null}
              sx={{
                px: 4, py: 1.6,
                fontFamily: 'Share Tech Mono', fontWeight: 800, letterSpacing: '.18em',
                fontSize: '.95rem',
                color: '#001821', bgcolor: '#00d4ff',
                borderRadius: 2,
                boxShadow: '0 0 24px rgba(0, 212, 255, .45)',
                '&:hover': { bgcolor: '#00d4ff', boxShadow: '0 0 36px rgba(0, 212, 255, .8)' },
              }}
            >
              {isLoggedIn ? 'ACCESS DASHBOARD' : 'LOGIN TO DASHBOARD'}
            </Button>

            <Button
              component={Link}
              to="/architecture"
              variant="outlined"
              sx={{
                px: 4, py: 1.6,
                fontFamily: 'Share Tech Mono', fontWeight: 700, letterSpacing: '.18em',
                fontSize: '.95rem', borderRadius: 2,
                color: '#00d4ff', borderColor: 'rgba(0, 212, 255, .5)',
                '&:hover': { borderColor: '#00d4ff', bgcolor: 'rgba(0, 212, 255, .08)' },
              }}
            >
              EXPLORE ARCHITECTURE
            </Button>
          </Stack>

          {/* meta pills */}
          <Box sx={{
            mt: 7, display: 'grid',
            gridTemplateColumns: { xs: 'repeat(2, 1fr)', sm: 'repeat(4, 1fr)' },
            gap: 1.5, width: '100%', maxWidth: 760,
          }}>
            {[
              { k: '3 × 2', v: 'Engines × Stages' },
              { k: '31', v: 'Golden features' },
              { k: '< 20 ms', v: 'Inference' },
              { k: '99.98%', v: 'Uptime' },
            ].map((p) => (
              <Paper key={p.v} sx={{
                p: 1.4, bgcolor: 'rgba(10, 18, 36, 0.5)',
                border: '1px solid rgba(0, 212, 255, 0.18)',
                backdropFilter: 'blur(10px)', borderRadius: 1.6, textAlign: 'center',
              }}>
                <Typography sx={{
                  fontFamily: 'Share Tech Mono', color: '#00d4ff',
                  fontSize: '1.15rem', fontWeight: 700,
                }}>
                  {p.k}
                </Typography>
                <Typography sx={{
                  color: '#7e93b6', fontSize: '.65rem',
                  letterSpacing: '.22em', textTransform: 'uppercase',
                }}>
                  {p.v}
                </Typography>
              </Paper>
            ))}
          </Box>

          {/* scroll cue */}
          <Box sx={{
            mt: 6, color: '#7e93b6', fontFamily: 'Share Tech Mono',
            letterSpacing: '.3em', fontSize: '.65rem', textTransform: 'uppercase',
          }}>
            Scroll
            <Box sx={{ mt: .5, animation: 'drift 1.6s ease-in-out infinite' }}>▾</Box>
          </Box>
        </Box>

        {/* ============================ ENGINE EVOLUTION ============================ */}
        <Box sx={{ py: { xs: 4, md: 6 } }}>
          <Typography
            ref={addRev(1)} className="rev"
            sx={{
              textAlign: 'center', color: '#00d4ff', fontFamily: 'Share Tech Mono',
              letterSpacing: '.4em', fontSize: '.85rem', textTransform: 'uppercase',
              mb: 1,
            }}
          >
            ◆ The Research Journey
          </Typography>
          <Typography
            ref={addRev(2)} className="rev"
            sx={{
              textAlign: 'center', color: '#e6edf7',
              fontWeight: 800, mb: 1,
              fontSize: { xs: '1.6rem', md: '2.4rem' }, letterSpacing: '-0.02em',
            }}
          >
            From gradient trees, to deep nets, to graphs.
          </Typography>
          <Typography
            ref={addRev(3)} className="rev"
            sx={{
              textAlign: 'center', color: '#9bb1cf',
              maxWidth: 720, mx: 'auto', mb: 4,
            }}
          >
            Two full pipelines, each a two-stage detector. Started classical,
            then upgraded to deep learning on internal feedback.
          </Typography>

          <Grid container spacing={2}>
            {ENGINES.map((e, i) => {
              const Icon = e.icon;
              return (
                <Grid item xs={12} md={4} key={e.key}>
                  <Paper
                    ref={addRev(4 + i)} className="rev"
                    sx={{
                      p: 3, height: '100%', position: 'relative',
                      bgcolor: 'rgba(10, 18, 36, 0.6)',
                      border: `1px solid ${e.accent}44`,
                      borderTop: `3px solid ${e.accent}`,
                      borderRadius: 2, backdropFilter: 'blur(10px)',
                      transition: 'transform .25s, box-shadow .25s, border-color .25s',
                      '&:hover': {
                        transform: 'translateY(-4px)',
                        boxShadow: `0 16px 50px ${e.accent}33`,
                        borderColor: e.accent,
                      },
                    }}
                  >
                    {e.badge && (
                      <Chip
                        size="small" label={e.badge}
                        sx={{
                          position: 'absolute', top: 12, right: 12,
                          bgcolor: `${e.accent}26`, color: e.accent,
                          border: `1px solid ${e.accent}`,
                          fontFamily: 'Share Tech Mono', fontWeight: 700, fontSize: '.65rem',
                        }}
                      />
                    )}

                    <Typography sx={{
                      color: e.accent, fontFamily: 'Share Tech Mono',
                      letterSpacing: '.3em', fontSize: '.7rem', textTransform: 'uppercase',
                    }}>
                      {e.iter}
                    </Typography>

                    <Stack direction="row" alignItems="center" spacing={1.4} sx={{ mt: 1, mb: .5 }}>
                      <Box sx={{
                        width: 42, height: 42, borderRadius: 1.4,
                        display: 'grid', placeItems: 'center',
                        bgcolor: `${e.accent}1F`, border: `1px solid ${e.accent}55`,
                        color: e.accent,
                      }}>
                        <Icon />
                      </Box>
                      <Box>
                        <Typography sx={{ color: '#eaf4ff', fontWeight: 700, fontSize: '1.1rem', lineHeight: 1.1 }}>
                          {e.title}
                        </Typography>
                        <Typography sx={{ color: '#7e93b6', fontSize: '.78rem' }}>
                          {e.sub}
                        </Typography>
                      </Box>
                    </Stack>

                    {/* Stage 1 → Stage 2 visual */}
                    <Box sx={{
                      mt: 2, mb: 1.5,
                      display: 'grid',
                      gridTemplateColumns: '1fr auto 1fr',
                      alignItems: 'center', gap: 1,
                    }}>
                      <Paper sx={{
                        p: 1.2, textAlign: 'center',
                        bgcolor: `${e.accent}10`,
                        border: `1px solid ${e.accent}44`,
                        borderRadius: 1.2,
                      }}>
                        <Typography sx={{
                          color: '#7e93b6', fontFamily: 'Share Tech Mono',
                          fontSize: '.6rem', letterSpacing: '.22em',
                          textTransform: 'uppercase', mb: .3,
                        }}>
                          Stage 1 · Binary
                        </Typography>
                        <Typography sx={{
                          color: e.accent, fontFamily: 'Share Tech Mono',
                          fontWeight: 700, fontSize: '.95rem',
                        }}>
                          {e.stage1}
                        </Typography>
                      </Paper>
                      <ArrowIcon sx={{ color: e.accent, fontSize: 22 }} />
                      <Paper sx={{
                        p: 1.2, textAlign: 'center',
                        bgcolor: `${e.accent}10`,
                        border: `1px solid ${e.accent}44`,
                        borderRadius: 1.2,
                      }}>
                        <Typography sx={{
                          color: '#7e93b6', fontFamily: 'Share Tech Mono',
                          fontSize: '.6rem', letterSpacing: '.22em',
                          textTransform: 'uppercase', mb: .3,
                        }}>
                          Stage 2 · Multi-class
                        </Typography>
                        <Typography sx={{
                          color: e.accent, fontFamily: 'Share Tech Mono',
                          fontWeight: 700, fontSize: '.95rem',
                        }}>
                          {e.stage2}
                        </Typography>
                      </Paper>
                    </Box>

                    <Typography sx={{ color: '#9bb1cf', fontSize: '.88rem', lineHeight: 1.55 }}>
                      {e.blurb}
                    </Typography>
                  </Paper>
                </Grid>
              );
            })}
          </Grid>
        </Box>

        {/* ============================ FEATURES ============================ */}
        <Box sx={{ py: { xs: 4, md: 6 } }}>
          <Typography
            ref={addRev(7)} className="rev"
            sx={{
              textAlign: 'center', color: '#00d4ff', fontFamily: 'Share Tech Mono',
              letterSpacing: '.4em', fontSize: '.85rem', textTransform: 'uppercase',
              mb: 1,
            }}
          >
            ◆ Core Capabilities
          </Typography>
          <Typography
            ref={addRev(8)} className="rev"
            sx={{
              textAlign: 'center', color: '#e6edf7',
              fontWeight: 800, mb: 5,
              fontSize: { xs: '1.6rem', md: '2.4rem' }, letterSpacing: '-0.02em',
            }}
          >
            Three engines. Two stages each. Live defence.
          </Typography>

          <Grid container spacing={2}>
            {FEATURES.map((f, i) => {
              const Icon = f.icon;
              return (
                <Grid item xs={12} sm={6} md={3} key={f.title}>
                  <Paper
                    ref={addRev(9 + i)} className="rev"
                    sx={{
                      p: 3, height: '100%', position: 'relative',
                      bgcolor: 'rgba(10, 18, 36, 0.55)',
                      border: `1px solid ${f.accent}33`,
                      borderRadius: 2, backdropFilter: 'blur(10px)',
                      transition: 'transform .25s, box-shadow .25s, border-color .25s',
                      '&:hover': {
                        transform: 'translateY(-4px)',
                        borderColor: f.accent,
                        boxShadow: `0 16px 50px ${f.accent}33`,
                      },
                    }}
                  >
                    {f.badge && (
                      <Chip
                        size="small"
                        label={f.badge}
                        sx={{
                          position: 'absolute', top: 12, right: 12,
                          bgcolor: `${f.accent}26`, color: f.accent,
                          border: `1px solid ${f.accent}`,
                          fontFamily: 'Share Tech Mono', fontWeight: 700, fontSize: '.65rem',
                        }}
                      />
                    )}
                    <Box sx={{
                      width: 46, height: 46, mb: 1.6,
                      borderRadius: 1.5, display: 'grid', placeItems: 'center',
                      bgcolor: `${f.accent}1F`, border: `1px solid ${f.accent}55`,
                      color: f.accent,
                    }}>
                      <Icon />
                    </Box>
                    <Typography sx={{
                      color: '#eaf4ff', fontWeight: 700, mb: .5, fontSize: '1.05rem',
                    }}>
                      {f.title}
                    </Typography>
                    <Typography sx={{ color: '#9bb1cf', fontSize: '.9rem', lineHeight: 1.55 }}>
                      {f.body}
                    </Typography>
                  </Paper>
                </Grid>
              );
            })}
          </Grid>
        </Box>

        {/* ============================ TECH STACK ============================ */}
        <Box sx={{ py: { xs: 4, md: 6 } }}>
          <Typography
            ref={addRev(13)} className="rev"
            sx={{
              textAlign: 'center', color: '#00d4ff', fontFamily: 'Share Tech Mono',
              letterSpacing: '.4em', fontSize: '.85rem', textTransform: 'uppercase', mb: 1,
            }}
          >
            ◆ Technology Stack
          </Typography>
          <Typography
            ref={addRev(14)} className="rev"
            sx={{
              textAlign: 'center', color: '#9bb1cf',
              maxWidth: 720, mx: 'auto', mb: 3.5,
            }}
          >
            Production-grade open-source stack — every layer is fully scriptable, auditable, and offline-capable.
          </Typography>

          <Box ref={addRev(15)} className="rev"
            sx={{
              display: 'flex', flexWrap: 'wrap', gap: 1, justifyContent: 'center',
              maxWidth: 920, mx: 'auto',
            }}
          >
            {STACK.map((s) => (
              <Chip
                key={s} label={s}
                sx={{
                  fontFamily: 'Share Tech Mono', letterSpacing: '.06em',
                  color: '#cfd9ee',
                  bgcolor: 'rgba(10,18,36,.55)',
                  border: '1px solid rgba(0, 212, 255, .2)',
                  backdropFilter: 'blur(8px)',
                  '&:hover': { borderColor: '#00d4ff', color: '#00d4ff' },
                }}
              />
            ))}
          </Box>
        </Box>

        {/* ============================ FINAL CTA ============================ */}
        <Box sx={{ py: { xs: 5, md: 8 }, textAlign: 'center' }}>
          <Paper
            ref={addRev(16)} className="rev"
            sx={{
              p: { xs: 3, md: 5 }, mx: 'auto', maxWidth: 820,
              bgcolor: 'rgba(10,18,36,0.55)',
              border: '1px solid rgba(0, 212, 255, 0.25)',
              borderRadius: 3, backdropFilter: 'blur(12px)',
              position: 'relative', overflow: 'hidden',
            }}
          >
            <Typography sx={{
              fontWeight: 800, mb: 1, fontSize: { xs: '1.6rem', md: '2.2rem' },
              background: 'linear-gradient(90deg, #00d4ff, #ff3df0)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>
              Ready to see PIDS in action?
            </Typography>
            <Typography sx={{ color: '#9bb1cf', mb: 3 }}>
              Enter the command centre — live traffic, real-time alerts, two-stage detection stack.
            </Typography>
            <Button
              component={Link}
              to={isLoggedIn ? '/dashboard' : '/login'}
              variant="contained"
              endIcon={<ArrowIcon />}
              sx={{
                px: 4, py: 1.5,
                fontFamily: 'Share Tech Mono', fontWeight: 800, letterSpacing: '.18em',
                color: '#001821', bgcolor: '#00d4ff', borderRadius: 2,
                boxShadow: '0 0 24px rgba(0, 212, 255, .45)',
                '&:hover': { bgcolor: '#00d4ff', boxShadow: '0 0 36px rgba(0, 212, 255, .8)' },
              }}
            >
              {isLoggedIn ? 'ACCESS DASHBOARD' : 'GET STARTED'}
            </Button>
          </Paper>

          <Typography sx={{
            mt: 4, color: '#5e7298', fontFamily: 'Share Tech Mono',
            letterSpacing: '.22em', fontSize: '.7rem', textTransform: 'uppercase',
          }}>
            © {new Date().getFullYear()} PIDS · Predictive Intrusion Detection System
          </Typography>
        </Box>
      </Container>
    </Box>
  );
};

export default LandingPage;

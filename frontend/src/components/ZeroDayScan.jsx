/**
 * ZeroDayScan — on-demand DuckDuckGo + LLM zero-day workflow visualiser.
 *
 * Layout:
 *   Top-left:  scan input form (port + protocol + optional IPs + optional features JSON)
 *   Top-right: animated 6-step workflow timeline (each step's status + duration)
 *   Bottom:    final verdict card + recent zero-day discoveries table
 *
 * The animation is driven by the response to /api/zero-day/scan/ —
 * each step in the trace is revealed in sequence with framer-motion
 * after the request returns, so the user sees a clear narrative even
 * when the backend completed the steps in milliseconds.
 */
import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Container, Typography, Paper, Stack, Chip, Button, TextField,
  ToggleButton, ToggleButtonGroup, Divider, CircularProgress, Alert,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Tooltip, IconButton,
} from '@mui/material';
import {
  Search as SearchIcon,
  Public as DDGIcon,
  Bolt as LLMIcon,
  CheckCircle as OkIcon,
  Cancel as BadIcon,
  Verified as VerifiedIcon,
  RestartAlt as ResetIcon,
  ExpandMore as ExpandIcon,
  Refresh as RefreshIcon,
  Shield as ShieldIcon,
  Functions as FeatureIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { API_BASE } from '../config';


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


// Step icon + colour table.
const STEP_VISUAL = {
  safety_check: { icon: ShieldIcon,  color: '#00d4ff' },
  build_queries:{ icon: SearchIcon,  color: '#aa66ff' },
  duckduckgo:   { icon: DDGIcon,     color: '#ff9800' },
  behavioural:  { icon: FeatureIcon, color: '#00d4ff' },
  llm_analysis: { icon: LLMIcon,     color: '#ffd600' },
  verdict:      { icon: VerifiedIcon,color: '#ff3b3b' },
};


/**
 * One row in the workflow timeline. `revealed` controls visibility so
 * we can stagger steps after the response lands.
 */
function StepCard({ step, revealed }) {
  const meta = STEP_VISUAL[step.step] || { icon: VerifiedIcon, color: '#888' };
  const Icon = meta.icon;

  // Step-specific tag pulled out of `result` for the at-a-glance line.
  const headline = (() => {
    switch (step.step) {
      case 'safety_check':
        return step.result?.is_safe ? 'WHITELISTED' : 'NOT WHITELISTED';
      case 'build_queries':
        return `${step.result?.queries?.length || 0} queries built`;
      case 'duckduckgo':
        return `${step.result?.total_hits || 0} hits across ${step.result?.searches?.length || 0} queries`;
      case 'behavioural':
        return step.result?.is_attack
          ? `${step.result?.attack_type || 'Suspicious'} (${((step.result?.confidence || 0) * 100).toFixed(0)}%)`
          : 'No anomaly';
      case 'llm_analysis':
        if (step.result?.skipped) return `Skipped: ${step.result.reason}`;
        if (step.result?.error)   return `Error: ${step.result.error.slice(0, 40)}`;
        return `${step.result?.attack_category || 'Unknown'} (${((step.result?.confidence || 0) * 100).toFixed(0)}%)`;
      case 'verdict':
        return `${step.result?.attack_category || 'Unknown'} (${((step.result?.confidence || 0) * 100).toFixed(0)}%)`;
      default:
        return '';
    }
  })();

  return (
    <motion.div
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: revealed ? 1 : 0.18, x: revealed ? 0 : -16 }}
      transition={{ duration: 0.4 }}
      style={{ marginBottom: 12 }}
    >
      <Glass sx={{ p: 1.5, borderColor: revealed ? meta.color + '88' : '#222' }}>
        <Stack direction="row" alignItems="center" spacing={1.5}>
          <Box sx={{
            width: 36, height: 36, borderRadius: '50%',
            bgcolor: revealed ? meta.color + '22' : '#1a1a1a',
            border: `2px solid ${revealed ? meta.color : '#333'}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Icon sx={{ color: revealed ? meta.color : '#555', fontSize: 20 }} />
          </Box>
          <Box sx={{ flex: 1 }}>
            <Typography sx={{ color: revealed ? '#fff' : '#666', fontFamily: 'Share Tech Mono',
                              fontSize: '0.85rem', fontWeight: 'bold' }}>
              {step.label}
            </Typography>
            <Typography sx={{ color: revealed ? meta.color : '#444',
                              fontFamily: 'Share Tech Mono', fontSize: '0.7rem' }}>
              {headline}
            </Typography>
          </Box>
          <Chip
            size="small"
            label={`${step.duration_ms} ms`}
            sx={{ bgcolor: '#1a1a1a', color: '#888', border: '1px solid #333',
                  fontFamily: 'Share Tech Mono', fontSize: '0.65rem' }}
          />
        </Stack>

        {/* DuckDuckGo hits expandable detail */}
        {revealed && step.step === 'duckduckgo' && step.result?.searches?.length > 0 && (
          <Box sx={{ mt: 1.5, pl: 5, color: '#aaa', fontFamily: 'Share Tech Mono', fontSize: '0.7rem' }}>
            {step.result.searches.map((s, i) => (
              <Box key={i} sx={{ mb: 1 }}>
                <Typography sx={{ color: meta.color, fontFamily: 'inherit', fontSize: 'inherit', mb: 0.3 }}>
                  &gt; {s.query}
                </Typography>
                {(s.hits || []).slice(0, 2).map((h, j) => (
                  <Box key={j} sx={{ pl: 2, color: '#888', mb: 0.3 }}>
                    <Typography sx={{ fontFamily: 'inherit', fontSize: 'inherit', color: '#ccc' }}>
                      • {h.title || '(no title)'}
                    </Typography>
                    <Typography sx={{ fontFamily: 'inherit', fontSize: '0.65rem', pl: 1.5 }}>
                      {(h.snippet || '').slice(0, 120)}{(h.snippet || '').length > 120 ? '…' : ''}
                    </Typography>
                  </Box>
                ))}
                {(!s.hits || s.hits.length === 0) && (
                  <Typography sx={{ pl: 2, color: '#555', fontFamily: 'inherit', fontSize: 'inherit' }}>
                    (no results — falling back to internal threat DB)
                  </Typography>
                )}
              </Box>
            ))}
          </Box>
        )}

        {/* Behavioural reason */}
        {revealed && step.step === 'behavioural' && step.result?.reason && (
          <Box sx={{ mt: 1, pl: 5, color: '#aaa', fontFamily: 'Share Tech Mono',
                     fontSize: '0.7rem' }}>
            {step.result.reason}
          </Box>
        )}

        {/* LLM reasoning */}
        {revealed && step.step === 'llm_analysis' && step.result?.reasoning && (
          <Box sx={{ mt: 1, pl: 5, color: '#aaa', fontFamily: 'Share Tech Mono',
                     fontSize: '0.7rem', borderLeft: `2px solid ${meta.color}33`,
                     ml: 5, pl: 1.5 }}>
            {step.result.reasoning}
          </Box>
        )}

        {/* Verdict reasoning (longer) */}
        {revealed && step.step === 'verdict' && step.result?.reasoning && (
          <Box sx={{ mt: 1, pl: 5, color: '#fff', fontFamily: 'Share Tech Mono',
                     fontSize: '0.75rem' }}>
            {step.result.reasoning}
          </Box>
        )}
      </Glass>
    </motion.div>
  );
}


// =====================================================================
// Main page
// =====================================================================

const ZeroDayScan = () => {
  const [form, setForm] = useState({
    port: '4444', protocol: 'TCP',
    src_ip: '', dst_ip: '',
    features_json: '{}',
  });
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [response, setResponse] = useState(null); // full backend response
  const [revealedSteps, setRevealedSteps] = useState(0);
  const [recent, setRecent] = useState([]);
  const [recentLoading, setRecentLoading] = useState(false);

  const fetchRecent = useCallback(async () => {
    setRecentLoading(true);
    try {
      const r = await axios.get(`${API_BASE}/zero-day/recent/?limit=10`);
      setRecent(r.data.rows || []);
    } catch (err) {
      // best-effort; surface nothing if endpoint not available
      setRecent([]);
    } finally {
      setRecentLoading(false);
    }
  }, []);

  useEffect(() => { fetchRecent(); }, [fetchRecent]);

  const handleScan = async () => {
    setError('');
    setResponse(null);
    setRevealedSteps(0);
    setScanning(true);

    let features = {};
    if (form.features_json && form.features_json.trim() !== '{}') {
      try {
        features = JSON.parse(form.features_json);
      } catch {
        setError('Features JSON is invalid — must be a JSON object.');
        setScanning(false);
        return;
      }
    }

    try {
      const body = {
        port: parseInt(form.port, 10),
        protocol: form.protocol,
        src_ip: form.src_ip.trim(),
        dst_ip: form.dst_ip.trim(),
        features,
      };
      const r = await axios.post(`${API_BASE}/zero-day/scan/`, body);
      setResponse(r.data);
    } catch (err) {
      setError(err?.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  // Stagger-reveal the steps in the workflow once a response lands.
  useEffect(() => {
    if (!response?.steps) return;
    setRevealedSteps(0);
    const total = response.steps.length;
    let i = 0;
    const id = setInterval(() => {
      i += 1;
      setRevealedSteps(i);
      if (i >= total) clearInterval(id);
    }, 450);
    return () => clearInterval(id);
  }, [response]);

  const verdict = response?.verdict;

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent',
               background: 'radial-gradient(ellipse at top, rgba(20,16,15,0.65), transparent 70%)',
               pt: 3, pb: 6 }}>
      <Container maxWidth="xl">
        {/* Header */}
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
          <Box>
            <Typography sx={{ color: '#ff9800', fontFamily: 'Share Tech Mono',
                              fontSize: '2rem', fontWeight: 'bold' }}>
              Zero-Day Scanner
            </Typography>
            <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }}>
              On-demand threat intelligence using DuckDuckGo open-source search +
              local Llama behavioural reasoning. Six-stage pipeline, fully transparent.
            </Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            <Chip icon={<DDGIcon sx={{ fontSize: 16 }} />} label="DuckDuckGo" size="small"
                  sx={{ bgcolor: '#ff980022', color: '#ff9800', border: '1px solid #ff9800',
                        fontFamily: 'Share Tech Mono' }} />
            <Chip icon={<LLMIcon sx={{ fontSize: 16 }} />} label="Llama" size="small"
                  sx={{ bgcolor: '#ffd60022', color: '#ffd600', border: '1px solid #ffd600',
                        fontFamily: 'Share Tech Mono' }} />
          </Stack>
        </Stack>

        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 2fr' }, gap: 2, mb: 3 }}>
          {/* INPUT FORM */}
          <Glass>
            <Typography sx={{ color: '#ff9800', fontFamily: 'Share Tech Mono',
                              fontWeight: 'bold', fontSize: '1rem', mb: 2 }}>
              Scan target
            </Typography>
            <Stack spacing={2}>
              <TextField
                label="Destination port"
                size="small" type="number"
                value={form.port}
                onChange={e => setForm(f => ({ ...f, port: e.target.value }))}
                inputProps={{ min: 1, max: 65535 }}
                sx={textFieldSx}
              />
              <Box>
                <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono',
                                  fontSize: '0.75rem', mb: 0.5 }}>
                  Protocol
                </Typography>
                <ToggleButtonGroup
                  exclusive size="small"
                  value={form.protocol}
                  onChange={(_, v) => v && setForm(f => ({ ...f, protocol: v }))}
                  sx={toggleSx}
                >
                  <ToggleButton value="TCP">TCP</ToggleButton>
                  <ToggleButton value="UDP">UDP</ToggleButton>
                </ToggleButtonGroup>
              </Box>
              <TextField
                label="Source IP (optional)"
                size="small"
                value={form.src_ip}
                placeholder="e.g. 192.168.1.50"
                onChange={e => setForm(f => ({ ...f, src_ip: e.target.value }))}
                sx={textFieldSx}
              />
              <TextField
                label="Destination IP (optional)"
                size="small"
                value={form.dst_ip}
                placeholder="e.g. 10.0.0.10"
                onChange={e => setForm(f => ({ ...f, dst_ip: e.target.value }))}
                sx={textFieldSx}
              />
              <TextField
                label="Features JSON (optional)"
                size="small" multiline minRows={3}
                value={form.features_json}
                placeholder='{"Fwd Pkts/s": 5000, "SYN Flag Cnt": 2000}'
                onChange={e => setForm(f => ({ ...f, features_json: e.target.value }))}
                sx={textFieldSx}
              />

              <Stack direction="row" spacing={1}>
                <Button
                  fullWidth variant="contained"
                  startIcon={scanning ? <CircularProgress size={16} sx={{ color: '#000' }} /> : <SearchIcon />}
                  onClick={handleScan} disabled={scanning}
                  sx={{ bgcolor: '#ff9800', color: '#000', fontFamily: 'Share Tech Mono',
                        fontWeight: 'bold', '&:hover': { bgcolor: '#ffac33' } }}
                >
                  {scanning ? 'Scanning…' : 'Run scan'}
                </Button>
                <Tooltip title="Reset">
                  <IconButton onClick={() => { setResponse(null); setError(''); }}
                              sx={{ color: '#888', border: '1px solid #333' }}>
                    <ResetIcon />
                  </IconButton>
                </Tooltip>
              </Stack>

              {error && <Alert severity="error" sx={{ fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>{error}</Alert>}

              {/* Quick-pick buttons for demo convenience */}
              <Divider sx={{ borderColor: '#1a1a1a' }} />
              <Typography sx={{ color: '#666', fontFamily: 'Share Tech Mono',
                                fontSize: '0.7rem' }}>
                Quick demo targets:
              </Typography>
              <Stack direction="row" flexWrap="wrap" gap={0.5}>
                {[
                  { port: '4444', proto: 'TCP', label: '4444 (Metasploit)' },
                  { port: '1337', proto: 'TCP', label: '1337 (Backdoor)' },
                  { port: '6667', proto: 'TCP', label: '6667 (IRC C2)' },
                  { port: '5353', proto: 'UDP', label: '5353 (mDNS)' },
                  { port: '443',  proto: 'TCP', label: '443 (HTTPS)' },
                ].map(q => (
                  <Chip key={q.port + q.proto} label={q.label} size="small"
                        clickable
                        onClick={() => setForm(f => ({ ...f, port: q.port, protocol: q.proto }))}
                        sx={{ bgcolor: '#1a1a1a', color: '#aaa', border: '1px solid #333',
                              fontFamily: 'Share Tech Mono', fontSize: '0.65rem',
                              '&:hover': { bgcolor: '#222', color: '#ff9800', borderColor: '#ff9800' } }} />
                ))}
              </Stack>
            </Stack>
          </Glass>

          {/* WORKFLOW TIMELINE */}
          <Box>
            <Glass sx={{ minHeight: 540 }}>
              <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
                <Typography sx={{ color: '#ff9800', fontFamily: 'Share Tech Mono',
                                  fontWeight: 'bold', fontSize: '1rem' }}>
                  Workflow trace
                </Typography>
                {response && (
                  <Chip
                    size="small"
                    icon={response.ollama_available ? <OkIcon sx={{ fontSize: 14 }} /> : <BadIcon sx={{ fontSize: 14 }} />}
                    label={response.ollama_available ? 'Ollama online' : 'Ollama offline'}
                    sx={{
                      bgcolor: response.ollama_available ? 'rgba(0,255,65,0.10)' : 'rgba(255,59,59,0.10)',
                      color:   response.ollama_available ? '#00d4ff' : '#ff3b3b',
                      border:  `1px solid ${response.ollama_available ? '#00d4ff' : '#ff3b3b'}`,
                      fontFamily: 'Share Tech Mono',
                    }}
                  />
                )}
              </Stack>

              {!response && !scanning && (
                <Box sx={{ textAlign: 'center', color: '#666', py: 6 }}>
                  <SearchIcon sx={{ fontSize: 48, color: '#222', mb: 1 }} />
                  <Typography sx={{ fontFamily: 'Share Tech Mono', fontSize: '0.85rem' }}>
                    Configure a target on the left and press <b>Run scan</b>.
                    The pipeline will execute the six stages and stream the trace here.
                  </Typography>
                </Box>
              )}

              {scanning && (
                <Box sx={{ textAlign: 'center', py: 6 }}>
                  <CircularProgress sx={{ color: '#ff9800' }} />
                  <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono',
                                    mt: 2, fontSize: '0.85rem' }}>
                    Querying DuckDuckGo + Llama…
                  </Typography>
                </Box>
              )}

              {response?.steps && (
                <AnimatePresence>
                  {response.steps.map((s, i) => (
                    <StepCard key={`${s.step}-${i}`} step={s} revealed={i < revealedSteps} />
                  ))}
                </AnimatePresence>
              )}
            </Glass>

            {/* FINAL VERDICT */}
            {response && revealedSteps >= response.steps.length && verdict && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                <Glass sx={{
                  mt: 2,
                  bgcolor: verdict.is_attack ? 'rgba(255,59,59,0.08)' : 'rgba(0,255,65,0.05)',
                  borderColor: verdict.is_attack ? '#ff3b3b' : '#00d4ff',
                }}>
                  <Stack direction="row" alignItems="center" spacing={2}>
                    {verdict.is_attack
                      ? <BadIcon sx={{ color: '#ff3b3b', fontSize: 32 }} />
                      : <OkIcon sx={{ color: '#00d4ff', fontSize: 32 }} />}
                    <Box sx={{ flex: 1 }}>
                      <Typography sx={{
                        color: verdict.is_attack ? '#ff3b3b' : '#00d4ff',
                        fontFamily: 'Share Tech Mono', fontSize: '1.4rem', fontWeight: 'bold',
                      }}>
                        {verdict.attack_category}
                      </Typography>
                      <Typography sx={{ color: '#aaa', fontFamily: 'Share Tech Mono',
                                        fontSize: '0.85rem', mt: 0.5 }}>
                        {verdict.reasoning}
                      </Typography>
                    </Box>
                    <Chip
                      label={`${(verdict.confidence * 100).toFixed(0)}% confidence`}
                      sx={{
                        bgcolor: verdict.is_attack ? '#ff3b3b22' : '#00d4ff22',
                        color:   verdict.is_attack ? '#ff3b3b' : '#00d4ff',
                        border: `1px solid ${verdict.is_attack ? '#ff3b3b' : '#00d4ff'}`,
                        fontFamily: 'Share Tech Mono', fontWeight: 'bold',
                      }}
                    />
                  </Stack>
                </Glass>
              </motion.div>
            )}
          </Box>
        </Box>

        {/* RECENT ZERO-DAY DISCOVERIES */}
        <Glass>
          <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
            <Typography sx={{ color: '#ff9800', fontFamily: 'Share Tech Mono',
                              fontWeight: 'bold', fontSize: '1rem' }}>
              Recent zero-day candidates (live pipeline)
            </Typography>
            <IconButton onClick={fetchRecent} disabled={recentLoading}
                        sx={{ color: '#888', border: '1px solid #333' }}>
              <RefreshIcon />
            </IconButton>
          </Stack>
          {recent.length === 0 && (
            <Typography sx={{ color: '#666', fontFamily: 'Share Tech Mono',
                              fontSize: '0.85rem', py: 2, textAlign: 'center' }}>
              {recentLoading ? 'Loading…' : 'No LLM-flagged flows yet.'}
            </Typography>
          )}
          {recent.length > 0 && (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    {['Time', 'Source', 'Destination', 'Port', 'Verdict', 'Conf', 'Reasoning'].map(h => (
                      <TableCell key={h} sx={{ color: '#aaa', fontFamily: 'Share Tech Mono',
                                                borderColor: '#222', fontSize: '0.75rem' }}>{h}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {recent.map(r => {
                    const reasoning = (r.llm_result?.reasoning || '').slice(0, 100);
                    const isAttack = (r.status || '').toLowerCase() === 'attack';
                    return (
                      <TableRow key={r.id} sx={{ '& td': {
                        borderColor: '#222',
                        color: isAttack ? '#ff3b3b' : '#ddd',
                        fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
                      } }}>
                        <TableCell>{r.timestamp?.slice(11, 19)}</TableCell>
                        <TableCell>{r.src_ip}:{r.src_port}</TableCell>
                        <TableCell>{r.dst_ip}:{r.dst_port}</TableCell>
                        <TableCell>{r.dst_port}</TableCell>
                        <TableCell sx={{ fontWeight: 'bold' }}>{r.attack_type || r.prediction || '—'}</TableCell>
                        <TableCell>{r.confidence != null ? (r.confidence * 100).toFixed(0) + '%' : '—'}</TableCell>
                        <TableCell sx={{ color: '#888 !important', maxWidth: 380 }}>
                          {reasoning}{(r.llm_result?.reasoning || '').length > 100 ? '…' : ''}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Glass>
      </Container>
    </Box>
  );
};


// ----- Shared MUI sx ----------------------------------------------------
const textFieldSx = {
  '& .MuiOutlinedInput-root': {
    color: '#ddd', fontFamily: 'Share Tech Mono',
    '& fieldset': { borderColor: '#333' },
    '&:hover fieldset': { borderColor: '#ff9800' },
    '&.Mui-focused fieldset': { borderColor: '#ff9800' },
  },
  '& .MuiInputLabel-root': { color: '#888', fontFamily: 'Share Tech Mono' },
};
const toggleSx = {
  '& .MuiToggleButton-root': {
    color: '#888', borderColor: '#333', fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
    '&.Mui-selected': { color: '#000', bgcolor: '#ff9800' },
  },
};


export default ZeroDayScan;

/**
 * EngineSelector — admin-only widget for choosing the active detection
 * engine (ML or DL) at runtime.
 *
 * Talks to:
 *   GET  /api/engine/status  -> {available, active, engines:{ml:{...}, dl:{...}}}
 *   GET  /api/engine/info    -> per-engine details (file paths, class counts, ...)
 *   POST /api/engine/select  -> {engine: 'ml'|'dl'}   (admin)
 *
 * Behaviour:
 *   - Shows a card per engine with availability chips and a "switch" button.
 *   - Renders nothing for non-admin users (defensive — backend also enforces).
 *   - Shows MUI Snackbar on success / failure of a switch.
 */
import React, { useEffect, useState, useCallback } from 'react';
import {
  Box, Card, CardContent, Typography, Button, Chip, Stack, Divider,
  Tooltip, CircularProgress, Snackbar, Alert,
} from '@mui/material';
import {
  CheckCircle as OkIcon,
  Cancel as BadIcon,
  Memory as ChipIcon,
  Bolt as DLIcon,
  Functions as MLIcon,
  Hub as GNNIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import axios from 'axios';
import { API_BASE } from '../config';
import { useAuth } from '../context/AuthContext';


// ---------- Static metadata used only for presentation ----------
const ENGINE_META = {
  ml: {
    label: 'ML Engine',
    sublabel: 'XGBoost (Stage 1) + LightGBM (Stage 2)',
    icon: MLIcon,
    accent: '#00d4ff',
  },
  dl: {
    label: 'DL Engine',
    sublabel: 'Two-Stage Deep Neural Network (Keras)',
    icon: DLIcon,
    accent: '#aa66ff',
  },
  gnn: {
    label: 'GNN Engine',
    sublabel: 'Two-Stage Graph Neural Network (E-GraphSAGE+GATv2 / GIN+GATv2)',
    icon: GNNIcon,
    accent: '#4d9d7e',
  },
};


/**
 * Format a possibly-undefined boolean as a green/red chip.
 */
function BoolChip({ value, trueLabel = 'Yes', falseLabel = 'No' }) {
  return (
    <Chip
      size="small"
      icon={value ? <OkIcon sx={{ fontSize: 14 }} /> : <BadIcon sx={{ fontSize: 14 }} />}
      label={value ? trueLabel : falseLabel}
      sx={{
        bgcolor: value ? 'rgba(0,255,65,0.10)' : 'rgba(255,59,59,0.10)',
        color:   value ? '#00d4ff' : '#ff3b3b',
        border:  `1px solid ${value ? '#00d4ff' : '#ff3b3b'}`,
        fontFamily: 'Share Tech Mono',
        fontSize: '0.7rem',
      }}
    />
  );
}


/**
 * One engine card. Shows availability + class count + Switch button.
 */
function EngineCard({ name, isActive, status, info, onSelect, switching, statusLoaded }) {
  const meta = ENGINE_META[name] || { label: name, sublabel: '', accent: '#888' };
  const Icon = meta.icon;
  // statusLoaded === false means we haven't heard from the backend yet —
  // render an "unknown" state instead of falsely claiming files are missing.
  const unknown = !statusLoaded || status === undefined || status === null;
  const available = !!status?.available;
  const loaded = !!status?.loaded;
  const loadError = status?.load_error;
  const classCount = info?.n_attack_classes;

  return (
    <Card
      sx={{
        flex: 1,
        minWidth: 280,
        // glass-morphic — translucent dark with a subtle blur so the
        // global Cyber3DBackground reads through and the card sits
        // visually on top of the scene without a hard black fill.
        bgcolor: 'rgba(10, 18, 36, 0.55)',
        backdropFilter: 'blur(12px) saturate(1.05)',
        WebkitBackdropFilter: 'blur(12px) saturate(1.05)',
        border: `1px solid ${isActive ? meta.accent : 'rgba(255,255,255,0.10)'}`,
        boxShadow: isActive ? `0 0 18px ${meta.accent}40, 0 8px 30px rgba(0,0,0,0.35)` : '0 8px 30px rgba(0,0,0,0.25)',
        transition: 'border-color 0.15s, box-shadow 0.15s',
      }}
    >
      <CardContent>
        <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
          <Stack direction="row" alignItems="center" spacing={1}>
            <Icon sx={{ color: meta.accent }} />
            <Typography sx={{ color: '#fff', fontFamily: 'Share Tech Mono', fontSize: '1rem', fontWeight: 'bold' }}>
              {meta.label}
            </Typography>
          </Stack>
          {isActive && (
            <Chip
              size="small"
              label="ACTIVE"
              sx={{
                bgcolor: meta.accent, color: '#000', fontFamily: 'Share Tech Mono',
                fontWeight: 'bold', fontSize: '0.65rem',
              }}
            />
          )}
        </Stack>

        <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.75rem', mb: 2 }}>
          {meta.sublabel}
        </Typography>

        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap mb={2}>
          {unknown ? (
            <Chip size="small" label="Checking…"
                  sx={{ bgcolor: '#1a1a1a', color: '#888', border: '1px solid #333',
                        fontFamily: 'Share Tech Mono', fontSize: '0.7rem' }} />
          ) : (
            <>
              <BoolChip value={available} trueLabel="On disk" falseLabel="Missing files" />
              {available && <BoolChip value={loaded} trueLabel="Loaded" falseLabel="Not loaded" />}
              {classCount != null && (
                <Chip
                  size="small"
                  icon={<ChipIcon sx={{ fontSize: 14 }} />}
                  label={`${classCount} classes`}
                  sx={{ bgcolor: '#1a1a1a', color: '#ccc', border: '1px solid #333',
                        fontFamily: 'Share Tech Mono', fontSize: '0.7rem' }}
                />
              )}
            </>
          )}
        </Stack>

        {loadError && (
          <Tooltip title={loadError} arrow>
            <Alert severity="warning" sx={{ mb: 2, fontFamily: 'Share Tech Mono', fontSize: '0.7rem' }}>
              Load error — {loadError.length > 60 ? loadError.slice(0, 60) + '...' : loadError}
            </Alert>
          </Tooltip>
        )}

        <Button
          fullWidth
          variant={isActive ? 'outlined' : 'contained'}
          disabled={isActive || unknown || !available || switching}
          onClick={() => onSelect(name)}
          sx={{
            fontFamily: 'Share Tech Mono', fontWeight: 'bold',
            ...(isActive
              ? { color: meta.accent, borderColor: meta.accent }
              : { bgcolor: meta.accent, color: '#000', '&:hover': { bgcolor: meta.accent, opacity: 0.85 } }),
          }}
        >
          {isActive
            ? 'Currently active'
            : unknown
              ? 'Checking…'
              : !available
                ? 'Unavailable'
                : switching
                  ? 'Switching...'
                  : `Switch to ${meta.label}`}
        </Button>
      </CardContent>
    </Card>
  );
}


/**
 * Main component. Owns the status + info fetch, selection mutation,
 * and snackbar feedback.
 */
const EngineSelector = () => {
  const { user, isAdmin } = useAuth();
  const [status, setStatus] = useState(null);   // {available, active, engines}
  const [info, setInfo] = useState(null);       // {active, engines:{ml,dl}, ...}
  const [loading, setLoading] = useState(true);
  const [switching, setSwitching] = useState(false);
  const [fetchError, setFetchError] = useState('');   // shown inline if /status fails
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  const showSnackbar = (message, severity = 'success') =>
    setSnackbar({ open: true, message, severity });

  const fetchAll = useCallback(async () => {
    setLoading(true);
    setFetchError('');
    try {
      const [statusRes, infoRes] = await Promise.all([
        axios.get(`${API_BASE}/engine/status/`),
        axios.get(`${API_BASE}/engine/info/`),
      ]);
      setStatus(statusRes.data);
      setInfo(infoRes.data);
    } catch (err) {
      const detail = err?.response?.data?.error || err.message || 'Unknown error';
      setFetchError(detail);
      showSnackbar(`Failed to load engine state: ${detail}`, 'error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAdmin) fetchAll();
  }, [isAdmin, fetchAll]);

  const handleSelect = async (engineName) => {
    setSwitching(true);
    try {
      const res = await axios.post(`${API_BASE}/engine/select/`, { engine: engineName });
      const newActive = res?.data?.active || engineName;
      showSnackbar(`Active engine switched to ${ENGINE_META[newActive]?.label || newActive}`);
      await fetchAll();
    } catch (err) {
      const detail = err?.response?.data?.error || err.message || 'Unknown error';
      showSnackbar(`Switch failed: ${detail}`, 'error');
    } finally {
      setSwitching(false);
    }
  };

  if (!isAdmin) return null;  // backend also enforces; this hides UI for non-admins

  // Render the ML and DL cards. GNN is disabled until a trained model
  // ships — add 'gnn' back here to re-enable its card.
  const engineNames = ['ml', 'dl'];

  return (
    <Box sx={{ mb: 3 }}>
      <Card sx={{ bgcolor: '#0a0a0a', border: '1px solid #222' }}>
        <CardContent>
          <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
            <Box>
              <Typography sx={{
                color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '1.2rem', fontWeight: 'bold',
              }}>
                Detection Engine
              </Typography>
              <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>
                Choose which classifier processes live traffic.
                Active engine: {' '}
                <Box component="span" sx={{
                  color: ENGINE_META[status?.active]?.accent || '#fff', fontWeight: 'bold',
                }}>
                  {status?.active ? (ENGINE_META[status.active]?.label || status.active.toUpperCase()) : '...'}
                </Box>
              </Typography>
            </Box>
            <Button
              startIcon={<RefreshIcon />}
              onClick={fetchAll}
              disabled={loading || switching}
              variant="outlined"
              size="small"
              sx={{ color: '#888', borderColor: '#333', fontFamily: 'Share Tech Mono',
                    '&:hover': { color: '#00d4ff', borderColor: '#00d4ff' } }}
            >
              Refresh
            </Button>
          </Stack>
          <Divider sx={{ borderColor: '#1a1a1a', mb: 2 }} />

          {fetchError && !status && (
            <Alert severity="error" sx={{ mb: 2, fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>
              Couldn't reach <code>/api/engine/status</code>: {fetchError}.
              The Detection Engine card can't determine availability — most likely
              the backend is down, the dev server needs restarting after model
              files were placed on disk, or your auth token expired.
            </Alert>
          )}

          {loading && !status ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress size={24} sx={{ color: '#00d4ff' }} />
            </Box>
          ) : (
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
              {engineNames.map((name) => (
                <EngineCard
                  statusLoaded={!!status}
                  key={name}
                  name={name}
                  isActive={status?.active === name}
                  status={status?.engines?.[name]}
                  info={info?.engines?.[name]}
                  onSelect={handleSelect}
                  switching={switching}
                />
              ))}
            </Stack>
          )}
        </CardContent>
      </Card>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
          severity={snackbar.severity}
          variant="filled"
          sx={{ fontFamily: 'Share Tech Mono' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default EngineSelector;

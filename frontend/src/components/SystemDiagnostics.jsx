import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Container, Typography, Paper, Grid,
  Button, Chip, Alert, Accordion, AccordionSummary,
  AccordionDetails, IconButton, Tooltip, CircularProgress, LinearProgress
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Storage as DatabaseIcon,
  Memory as MemoryIcon,
  Psychology as AIIcon,
  Router as NetworkIcon,
  Code as CodeIcon,
  Computer as SystemIcon,
  Security as SecurityIcon,
  Speed as CpuIcon,
  SdStorage as DiskIcon,
  Dns as ServerIcon,
  AccessTime as TimeIcon,
  DataUsage as DataIcon,
  Layers as LayersIcon,
  BugReport as BugIcon,
  Delete as DeleteIcon,
  Dashboard as DashboardIcon
} from '@mui/icons-material';
import { API_BASE } from '../config';
import axios from 'axios';

// Status Badge Component
const StatusBadge = ({ status, size = 'medium' }) => {
  const getStatusConfig = () => {
    switch (status) {
      case 'healthy':
        return { color: '#4d9d7e', icon: <CheckIcon sx={{ fontSize: size === 'small' ? 14 : 18 }} />, label: 'Healthy' };
      case 'warning':
        return { color: '#ff9800', icon: <WarningIcon sx={{ fontSize: size === 'small' ? 14 : 18 }} />, label: 'Warning' };
      case 'error':
        return { color: '#ff3b6b', icon: <ErrorIcon sx={{ fontSize: size === 'small' ? 14 : 18 }} />, label: 'Error' };
      default:
        return { color: '#888', icon: null, label: 'Unknown' };
    }
  };
  const config = getStatusConfig();
  return (
    <Chip
      icon={config.icon}
      label={config.label}
      size={size}
      sx={{
        bgcolor: `${config.color}20`,
        color: config.color,
        border: `1px solid ${config.color}`,
        fontWeight: 'bold',
        '& .MuiChip-icon': { color: config.color }
      }}
    />
  );
};

// Progress Bar with Label
const ProgressWithLabel = ({ value, label, color = '#00d4ff' }) => {
  const progressColor = value > 80 ? '#ff3b6b' : value > 60 ? '#ff9800' : color;
  return (
    <Box sx={{ width: '100%', mt: 1 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
        <Typography variant="caption" sx={{ color: '#888' }}>{label}</Typography>
        <Typography variant="caption" sx={{ color: progressColor, fontWeight: 'bold' }}>{value}%</Typography>
      </Box>
      <LinearProgress
        variant="determinate"
        value={value}
        sx={{
          height: 8,
          borderRadius: 4,
          bgcolor: 'rgba(255,255,255,0.1)',
          '& .MuiLinearProgress-bar': { bgcolor: progressColor, borderRadius: 4 }
        }}
      />
    </Box>
  );
};

// Detail Row Component
const DetailRow = ({ label, value, icon, color = '#00d4ff' }) => (
  <Box sx={{ 
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    py: 1, px: 2, borderBottom: '1px solid rgba(255,255,255,0.05)',
  }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      {icon && <Box sx={{ color: color, display: 'flex' }}>{icon}</Box>}
      <Typography variant="body2" sx={{ color: '#888' }}>{label}</Typography>
    </Box>
    <Typography variant="body2" sx={{ color: color, fontFamily: 'monospace', fontWeight: 'bold' }}>
      {value}
    </Typography>
  </Box>
);

// Section Card Component
const SectionCard = ({ title, icon, children, color = '#00d4ff', status }) => (
  <Paper sx={{ 
    bgcolor: 'rgba(0,0,0,0.6)', 
    border: `1px solid ${status === 'error' ? '#ff3b6b' : status === 'warning' ? '#ff9800' : '#333'}`,
    borderRadius: 2, overflow: 'hidden',
  }}>
    <Box sx={{ 
      p: 2, bgcolor: `${color}10`, borderBottom: `1px solid ${color}30`,
      display: 'flex', justifyContent: 'space-between', alignItems: 'center'
    }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Box sx={{ color: color }}>{icon}</Box>
        <Typography variant="h6" sx={{ color: '#fff', fontSize: '1rem', fontFamily: 'Share Tech Mono' }}>
          {title}
        </Typography>
      </Box>
      {status && <StatusBadge status={status} size="small" />}
    </Box>
    <Box>{children}</Box>
  </Paper>
);

// Circular Gauge Component
const CircularGauge = ({ value, label, sublabel, color = '#00d4ff', size = 100 }) => {
  const gaugeColor = value > 80 ? '#ff3b6b' : value > 60 ? '#ff9800' : color;
  return (
    <Box sx={{ textAlign: 'center' }}>
      <Box sx={{ position: 'relative', display: 'inline-flex' }}>
        <CircularProgress variant="determinate" value={100} size={size} thickness={4} sx={{ color: 'rgba(255,255,255,0.1)' }} />
        <CircularProgress
          variant="determinate" value={value || 0} size={size} thickness={4}
          sx={{ color: gaugeColor, position: 'absolute', left: 0 }}
        />
        <Box sx={{ top: 0, left: 0, bottom: 0, right: 0, position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <Typography variant="h6" sx={{ color: gaugeColor, fontWeight: 'bold', fontFamily: 'Share Tech Mono' }}>
            {value || 0}%
          </Typography>
        </Box>
      </Box>
      <Typography variant="body2" sx={{ color: '#fff', mt: 1, fontWeight: 'bold' }}>{label}</Typography>
      {sublabel && <Typography variant="caption" sx={{ color: '#666' }}>{sublabel}</Typography>}
    </Box>
  );
};

// Main Component
const SystemDiagnostics = () => {
  const [health, setHealth] = useState(null);
  const [errors, setErrors] = useState({ errors: [], stats: {} });
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchHealth = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/diagnostics/health/`);
      setHealth(response.data);
      setLastUpdate(new Date());
    } catch (error) {
      console.error('Failed to fetch health:', error);
      setHealth({
        overall_status: 'error',
        issues: [{ component: 'API', message: 'Failed to connect to backend API', severity: 'critical' }],
        warnings: [],
        components: {}
      });
    }
    setLoading(false);
  }, []);

  const fetchErrors = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/errors/`);
      setErrors(response.data);
    } catch (error) {
      console.error('Failed to fetch errors:', error);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    fetchErrors();
    let interval;
    if (autoRefresh) {
      interval = setInterval(() => {
        fetchHealth();
        fetchErrors();
      }, 10000);
    }
    return () => clearInterval(interval);
  }, [fetchHealth, fetchErrors, autoRefresh]);

  const resolveError = async (errorId) => {
    try {
      await axios.post(`${API_BASE}/errors/resolve/`, { error_id: errorId });
      fetchErrors();
    } catch (error) {
      console.error('Failed to resolve error:', error);
    }
  };

  const clearAllErrors = async (source = null) => {
    try {
      await axios.post(`${API_BASE}/errors/clear/`, { source });
      fetchErrors();
    } catch (error) {
      console.error('Failed to clear errors:', error);
    }
  };

  const getOverallStatusConfig = () => {
    if (!health) return { color: '#888', icon: <CircularProgress size={40} />, label: 'Loading...' };
    switch (health.overall_status) {
      case 'healthy':
        return { color: '#4d9d7e', icon: <CheckIcon sx={{ fontSize: 80 }} />, label: 'All Systems Operational', emoji: '✅' };
      case 'warning':
        return { color: '#ff9800', icon: <WarningIcon sx={{ fontSize: 80 }} />, label: 'Some Issues Detected', emoji: '⚠️' };
      case 'critical':
        return { color: '#ff3b6b', icon: <ErrorIcon sx={{ fontSize: 80 }} />, label: 'Critical Issues Found', emoji: '🚨' };
      default:
        return { color: '#888', icon: <WarningIcon sx={{ fontSize: 80 }} />, label: 'Unknown Status', emoji: '❓' };
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', bgcolor: 'transparent' }}>
        <Box sx={{ textAlign: 'center' }}>
          <CircularProgress sx={{ color: '#00d4ff', mb: 2 }} size={60} />
          <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono' }}>Running System Diagnostics...</Typography>
        </Box>
      </Box>
    );
  }

  const overallConfig = getOverallStatusConfig();
  const sysRes = health?.components?.system_resources?.details || {};
  const dbDetails = health?.components?.database?.details || {};
  const mlDetails = health?.components?.ml_models?.details || {};
  const ollamaDetails = health?.components?.ollama?.details || {};
  const djangoDetails = health?.components?.django?.details || {};
  const trafficDetails = health?.components?.traffic_capture?.details || {};

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent', py: 4 }}>
      <Container maxWidth="xl">
        {/* Header */}
        <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
          <Box>
            <Typography variant="h4" sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono' }}>
              🔧 System Diagnostics
            </Typography>
            <Typography variant="body2" sx={{ color: '#888', mt: 1 }}>
              Real-time health monitoring for all system components
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip
              icon={<TimeIcon />}
              label={lastUpdate ? `Updated: ${lastUpdate.toLocaleTimeString()}` : 'Never'}
              sx={{ bgcolor: 'rgba(255,255,255,0.05)', color: '#888', border: '1px solid #333' }}
            />
            <Chip
              label={autoRefresh ? '🔄 Auto ON' : '⏸️ Auto OFF'}
              onClick={() => setAutoRefresh(!autoRefresh)}
              sx={{
                bgcolor: autoRefresh ? 'rgba(0,255,65,0.1)' : 'rgba(255,255,255,0.05)',
                color: autoRefresh ? '#00d4ff' : '#888',
                border: `1px solid ${autoRefresh ? '#00d4ff' : '#444'}`,
                cursor: 'pointer',
              }}
            />
            <IconButton onClick={() => { fetchHealth(); fetchErrors(); }} sx={{ color: '#00d4ff', border: '1px solid #00d4ff' }}>
              <RefreshIcon />
            </IconButton>
          </Box>
        </Box>

        {/* Overall Status Card */}
        <Paper sx={{ p: 4, mb: 4, bgcolor: 'rgba(0,0,0,0.6)', border: `2px solid ${overallConfig.color}`, borderRadius: 3, textAlign: 'center' }}>
          <Box sx={{ color: overallConfig.color, mb: 2 }}>{overallConfig.icon}</Box>
          <Typography variant="h4" sx={{ color: overallConfig.color, fontFamily: 'Share Tech Mono', mb: 1 }}>
            {overallConfig.emoji} {overallConfig.label}
          </Typography>
          <Box sx={{ display: 'flex', justifyContent: 'center', gap: 4, mt: 3, flexWrap: 'wrap' }}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#4d9d7e', fontWeight: 'bold' }}>
                {Object.values(health?.components || {}).filter(c => c.status === 'healthy').length}
              </Typography>
              <Typography variant="caption" sx={{ color: '#888' }}>Healthy</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#ff9800', fontWeight: 'bold' }}>
                {Object.values(health?.components || {}).filter(c => c.status === 'warning').length}
              </Typography>
              <Typography variant="caption" sx={{ color: '#888' }}>Warnings</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#ff3b6b', fontWeight: 'bold' }}>
                {Object.values(health?.components || {}).filter(c => c.status === 'error').length}
              </Typography>
              <Typography variant="caption" sx={{ color: '#888' }}>Errors</Typography>
            </Box>
          </Box>
          {health?.issues?.length > 0 && (
            <Box sx={{ mt: 3, textAlign: 'left' }}>
              {health.issues.map((issue, i) => (
                <Alert key={i} severity="error" sx={{ mb: 1, bgcolor: 'rgba(244,67,54,0.1)' }}>
                  <strong>{issue.component}:</strong> {issue.message}
                </Alert>
              ))}
            </Box>
          )}
          {health?.warnings?.length > 0 && (
            <Box sx={{ mt: 2, textAlign: 'left' }}>
              {health.warnings.map((warning, i) => (
                <Alert key={i} severity="warning" sx={{ mb: 1, bgcolor: 'rgba(255,152,0,0.1)' }}>
                  <strong>{warning.component}:</strong> {warning.message}
                </Alert>
              ))}
            </Box>
          )}
        </Paper>

        {/* System Resources */}
        <Paper sx={{ p: 3, mb: 4, bgcolor: 'rgba(0,0,0,0.6)', border: '1px solid #333', borderRadius: 2 }}>
          <Typography variant="h6" sx={{ color: '#ff9800', mb: 3, fontFamily: 'Share Tech Mono', display: 'flex', alignItems: 'center', gap: 1 }}>
            <SystemIcon /> System Resources
          </Typography>
          <Grid container spacing={4} justifyContent="center">
            <Grid item xs={6} sm={4} md={2}>
              <CircularGauge value={sysRes.cpu?.percent || 0} label="CPU" sublabel={`${sysRes.cpu?.cores || 0} Cores`} color="#4d9d7e" />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <CircularGauge value={sysRes.memory?.percent || 0} label="Memory" sublabel={`${sysRes.memory?.available_gb || 0} GB Free`} color="#2196f3" />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <CircularGauge value={sysRes.disk?.percent || 0} label="Disk" sublabel={`${sysRes.disk?.free_gb || 0} GB Free`} color="#9c27b0" />
            </Grid>
          </Grid>
          <Grid container spacing={3} sx={{ mt: 3 }}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, bgcolor: 'rgba(76,175,80,0.05)', borderRadius: 2, border: '1px solid rgba(76,175,80,0.2)' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <CpuIcon sx={{ color: '#4d9d7e' }} />
                  <Typography variant="subtitle2" sx={{ color: '#4d9d7e' }}>CPU Details</Typography>
                </Box>
                <DetailRow label="Usage" value={`${sysRes.cpu?.percent || 0}%`} color="#4d9d7e" />
                <DetailRow label="Cores" value={sysRes.cpu?.cores || 'N/A'} color="#4d9d7e" />
                <ProgressWithLabel value={sysRes.cpu?.percent || 0} label="Utilization" color="#4d9d7e" />
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, bgcolor: 'rgba(33,150,243,0.05)', borderRadius: 2, border: '1px solid rgba(33,150,243,0.2)' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <MemoryIcon sx={{ color: '#2196f3' }} />
                  <Typography variant="subtitle2" sx={{ color: '#2196f3' }}>Memory Details</Typography>
                </Box>
                <DetailRow label="Total" value={`${sysRes.memory?.total_gb || 0} GB`} color="#2196f3" />
                <DetailRow label="Available" value={`${sysRes.memory?.available_gb || 0} GB`} color="#2196f3" />
                <DetailRow label="Used" value={`${((sysRes.memory?.total_gb || 0) - (sysRes.memory?.available_gb || 0)).toFixed(2)} GB`} color="#2196f3" />
                <ProgressWithLabel value={sysRes.memory?.percent || 0} label="Usage" color="#2196f3" />
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, bgcolor: 'rgba(156,39,176,0.05)', borderRadius: 2, border: '1px solid rgba(156,39,176,0.2)' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <DiskIcon sx={{ color: '#9c27b0' }} />
                  <Typography variant="subtitle2" sx={{ color: '#9c27b0' }}>Disk Details</Typography>
                </Box>
                <DetailRow label="Total" value={`${sysRes.disk?.total_gb || 0} GB`} color="#9c27b0" />
                <DetailRow label="Free" value={`${sysRes.disk?.free_gb || 0} GB`} color="#9c27b0" />
                <DetailRow label="Used" value={`${((sysRes.disk?.total_gb || 0) - (sysRes.disk?.free_gb || 0)).toFixed(2)} GB`} color="#9c27b0" />
                <ProgressWithLabel value={sysRes.disk?.percent || 0} label="Usage" color="#9c27b0" />
              </Box>
            </Grid>
          </Grid>
          <Box sx={{ mt: 3, p: 2, bgcolor: 'rgba(255,255,255,0.02)', borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ color: '#888', mb: 2 }}>Platform Information</Typography>
            <Grid container spacing={2}>
              <Grid item xs={6} sm={3}>
                <DetailRow label="OS" value={sysRes.platform?.system || 'N/A'} icon={<SystemIcon sx={{ fontSize: 18 }} />} color="#00d4ff" />
              </Grid>
              <Grid item xs={6} sm={3}>
                <DetailRow label="Version" value={sysRes.platform?.release || 'N/A'} icon={<LayersIcon sx={{ fontSize: 18 }} />} color="#00d4ff" />
              </Grid>
              <Grid item xs={6} sm={3}>
                <DetailRow label="Python" value={sysRes.platform?.python_version || 'N/A'} icon={<CodeIcon sx={{ fontSize: 18 }} />} color="#00d4ff" />
              </Grid>
              <Grid item xs={6} sm={3}>
                <DetailRow label="Status" value="Running" icon={<CheckIcon sx={{ fontSize: 18 }} />} color="#4d9d7e" />
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {/* Component Details Grid */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <SectionCard title="Database" icon={<DatabaseIcon />} color="#2196f3" status={health?.components?.database?.status}>
              <DetailRow label="Type" value={dbDetails.type || 'N/A'} icon={<DatabaseIcon sx={{ fontSize: 18 }} />} color="#2196f3" />
              <DetailRow label="Latency" value={`${dbDetails.latency_ms || 0} ms`} icon={<CpuIcon sx={{ fontSize: 18 }} />} color="#2196f3" />
              <DetailRow label="Total Records" value={(dbDetails.total_records || 0).toLocaleString()} icon={<DataIcon sx={{ fontSize: 18 }} />} color="#2196f3" />
              <DetailRow label="Records (Last Hour)" value={(dbDetails.records_last_hour || 0).toLocaleString()} icon={<TimeIcon sx={{ fontSize: 18 }} />} color="#2196f3" />
              <Box sx={{ p: 2 }}>
                <Typography variant="caption" sx={{ color: health?.components?.database?.status === 'healthy' ? '#4d9d7e' : '#ff3b6b' }}>
                  {health?.components?.database?.message}
                </Typography>
              </Box>
            </SectionCard>
          </Grid>
          <Grid item xs={12} md={6}>
            <SectionCard title="ML Models" icon={<AIIcon />} color="#9c27b0" status={health?.components?.ml_models?.status}>
              <DetailRow label="XGBoost (Stage 1)" value={mlDetails['stage1_xgboost.pkl']?.exists ? `✅ ${mlDetails['stage1_xgboost.pkl']?.size_mb || 0} MB` : '❌ Missing'} color={mlDetails['stage1_xgboost.pkl']?.exists ? '#4d9d7e' : '#ff3b6b'} />
              <DetailRow label="LightGBM (Stage 2)" value={mlDetails['stage2_lightgbm.pkl']?.exists ? `✅ ${mlDetails['stage2_lightgbm.pkl']?.size_mb || 0} MB` : '❌ Missing'} color={mlDetails['stage2_lightgbm.pkl']?.exists ? '#4d9d7e' : '#ff3b6b'} />
              <DetailRow label="Label Encoder" value={mlDetails['label_encoder.pkl']?.exists ? `✅ ${mlDetails['label_encoder.pkl']?.size_mb || 0} MB` : '❌ Missing'} color={mlDetails['label_encoder.pkl']?.exists ? '#4d9d7e' : '#ff3b6b'} />
              <Box sx={{ p: 2 }}>
                <Typography variant="caption" sx={{ color: health?.components?.ml_models?.status === 'healthy' ? '#4d9d7e' : '#ff3b6b' }}>
                  {health?.components?.ml_models?.message}
                </Typography>
              </Box>
            </SectionCard>
          </Grid>
          <Grid item xs={12} md={6}>
            <SectionCard title="Ollama LLM" icon={<AIIcon />} color="#e91e63" status={health?.components?.ollama?.status}>
              <DetailRow label="Host" value={ollamaDetails.host || 'N/A'} icon={<ServerIcon sx={{ fontSize: 18 }} />} color="#e91e63" />
              <DetailRow label="Latency" value={ollamaDetails.latency_ms ? `${ollamaDetails.latency_ms} ms` : 'N/A'} icon={<CpuIcon sx={{ fontSize: 18 }} />} color="#e91e63" />
              <DetailRow label="Active Model" value={ollamaDetails.active_model || ollamaDetails.required_model || 'N/A'} icon={<AIIcon sx={{ fontSize: 18 }} />} color="#e91e63" />
              {ollamaDetails.suggestion && (
                <Box sx={{ p: 2, bgcolor: 'rgba(233,30,99,0.1)', m: 1, borderRadius: 1 }}>
                  <Typography variant="caption" sx={{ color: '#e91e63' }}>💡 {ollamaDetails.suggestion}</Typography>
                </Box>
              )}
              <Box sx={{ p: 2 }}>
                <Typography variant="caption" sx={{ color: health?.components?.ollama?.status === 'healthy' ? '#4d9d7e' : '#ff9800' }}>
                  {health?.components?.ollama?.message}
                </Typography>
              </Box>
            </SectionCard>
          </Grid>
          <Grid item xs={12} md={6}>
            <SectionCard title="Django Backend" icon={<CodeIcon />} color="#4d9d7e" status={health?.components?.django?.status}>
              <DetailRow label="Debug Mode" value={djangoDetails.debug_mode ? '🟡 ON' : '🟢 OFF'} icon={<BugIcon sx={{ fontSize: 18 }} />} color={djangoDetails.debug_mode ? '#ff9800' : '#4d9d7e'} />
              <DetailRow label="Timezone" value={djangoDetails.timezone || 'N/A'} icon={<TimeIcon sx={{ fontSize: 18 }} />} color="#4d9d7e" />
              <DetailRow label="Database Engine" value={djangoDetails.database_engine || 'N/A'} icon={<DatabaseIcon sx={{ fontSize: 18 }} />} color="#4d9d7e" />
              <DetailRow label="Installed Apps" value={djangoDetails.installed_apps || 0} icon={<LayersIcon sx={{ fontSize: 18 }} />} color="#4d9d7e" />
              <Box sx={{ p: 2 }}>
                <Typography variant="caption" sx={{ color: '#4d9d7e' }}>{health?.components?.django?.message}</Typography>
              </Box>
            </SectionCard>
          </Grid>
          <Grid item xs={12}>
            <SectionCard title="Traffic Capture" icon={<NetworkIcon />} color="#00bcd4" status={health?.components?.traffic_capture?.status}>
              <Grid container>
                <Grid item xs={12} sm={6} md={3}>
                  <DetailRow label="Status" value={trafficDetails.capture_active ? '🟢 Active' : '🔴 Inactive'} icon={<NetworkIcon sx={{ fontSize: 18 }} />} color={trafficDetails.capture_active ? '#4d9d7e' : '#ff3b6b'} />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <DetailRow label="Records (5 min)" value={(trafficDetails.records_last_5min || 0).toLocaleString()} icon={<DataIcon sx={{ fontSize: 18 }} />} color="#00bcd4" />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <DetailRow label="Last Record" value={trafficDetails.last_record ? new Date(trafficDetails.last_record).toLocaleTimeString() : 'N/A'} icon={<TimeIcon sx={{ fontSize: 18 }} />} color="#00bcd4" />
                </Grid>
                <Grid item xs={12} sm={6} md={3}>
                  <Box sx={{ p: 2 }}>
                    <Typography variant="caption" sx={{ color: health?.components?.traffic_capture?.status === 'healthy' ? '#4d9d7e' : '#ff9800' }}>
                      {health?.components?.traffic_capture?.message}
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </SectionCard>
          </Grid>
        </Grid>

        {/* Error Monitor */}
        <Paper sx={{ p: 3, mt: 4, bgcolor: 'rgba(0,0,0,0.6)', border: '1px solid #333', borderRadius: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, flexWrap: 'wrap', gap: 2 }}>
            <Typography variant="h6" sx={{ color: '#ff3b6b', fontFamily: 'Share Tech Mono', display: 'flex', alignItems: 'center', gap: 1 }}>
              <BugIcon /> Error Monitor
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip label={`Total: ${errors.stats?.total || 0}`} size="small" sx={{ bgcolor: 'rgba(255,255,255,0.1)', color: '#fff' }} />
              <Chip label={`Backend: ${errors.stats?.backend || 0}`} size="small" sx={{ bgcolor: 'rgba(156,39,176,0.2)', color: '#9c27b0' }} />
              <Chip label={`Frontend: ${errors.stats?.frontend || 0}`} size="small" sx={{ bgcolor: 'rgba(33,150,243,0.2)', color: '#2196f3' }} />
              <Chip label={`Unresolved: ${errors.stats?.unresolved || 0}`} size="small" sx={{ bgcolor: 'rgba(244,67,54,0.2)', color: '#ff3b6b' }} />
            </Box>
          </Box>

          {errors.errors?.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <CheckIcon sx={{ fontSize: 60, color: '#4d9d7e', mb: 2 }} />
              <Typography sx={{ color: '#4d9d7e' }}>No errors logged! 🎉</Typography>
              <Typography variant="caption" sx={{ color: '#666' }}>System is running smoothly</Typography>
            </Box>
          ) : (
            <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
              {errors.errors?.map((error, index) => (
                <Box 
                  key={error.id || index}
                  sx={{ 
                    p: 2, mb: 1, 
                    bgcolor: error.resolved ? 'rgba(76,175,80,0.05)' : 'rgba(244,67,54,0.05)',
                    border: `1px solid ${error.resolved ? '#4d9d7e30' : '#ff3b6b30'}`,
                    borderRadius: 1,
                    borderLeft: `4px solid ${error.source === 'frontend' ? '#2196f3' : '#9c27b0'}`
                  }}
                >
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <Box sx={{ flex: 1 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                        <Chip label={error.source} size="small" sx={{ bgcolor: error.source === 'frontend' ? 'rgba(33,150,243,0.2)' : 'rgba(156,39,176,0.2)', color: error.source === 'frontend' ? '#2196f3' : '#9c27b0', fontSize: '0.7rem' }} />
                        <Chip label={error.type} size="small" sx={{ bgcolor: 'rgba(244,67,54,0.2)', color: '#ff3b6b', fontSize: '0.7rem' }} />
                        {error.resolved && <Chip label="Resolved" size="small" sx={{ bgcolor: 'rgba(76,175,80,0.2)', color: '#4d9d7e', fontSize: '0.7rem' }} />}
                        <Typography variant="caption" sx={{ color: '#666' }}>{new Date(error.timestamp).toLocaleString()}</Typography>
                      </Box>
                      <Typography variant="body2" sx={{ color: '#fff', mb: 1, fontFamily: 'monospace', fontSize: '0.85rem' }}>{error.message}</Typography>
                      {error.file_path && <Typography variant="caption" sx={{ color: '#888' }}>📁 {error.file_path}{error.line_number ? `:${error.line_number}` : ''}</Typography>}
                      {error.details?.path && <Typography variant="caption" sx={{ color: '#888', display: 'block' }}>🔗 {error.details.method} {error.details.path}</Typography>}
                    </Box>
                    {!error.resolved && (
                      <Tooltip title="Mark as resolved">
                        <IconButton size="small" onClick={() => resolveError(error.id)} sx={{ color: '#4d9d7e' }}>
                          <CheckIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                  </Box>
                  {error.details?.traceback && (
                    <Accordion sx={{ mt: 1, bgcolor: 'transparent', boxShadow: 'none' }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#888' }} />}>
                        <Typography variant="caption" sx={{ color: '#888' }}>View Traceback</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Box sx={{ bgcolor: '#000', p: 1, borderRadius: 1, maxHeight: 200, overflow: 'auto', fontFamily: 'monospace', fontSize: '0.7rem', color: '#ff3b6b', whiteSpace: 'pre-wrap' }}>
                          {error.details.traceback}
                        </Box>
                      </AccordionDetails>
                    </Accordion>
                  )}
                </Box>
              ))}
            </Box>
          )}
          
          {errors.errors?.length > 0 && (
            <Box sx={{ mt: 2, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button size="small" startIcon={<DeleteIcon />} onClick={() => clearAllErrors()} variant="outlined" sx={{ color: '#ff3b6b', borderColor: '#ff3b6b' }}>Clear All</Button>
              <Button size="small" onClick={() => clearAllErrors('frontend')} variant="outlined" sx={{ color: '#2196f3', borderColor: '#2196f3' }}>Clear Frontend</Button>
              <Button size="small" onClick={() => clearAllErrors('backend')} variant="outlined" sx={{ color: '#9c27b0', borderColor: '#9c27b0' }}>Clear Backend</Button>
            </Box>
          )}
        </Paper>

        {/* Quick Actions */}
        <Paper sx={{ p: 3, mt: 4, bgcolor: 'rgba(0,0,0,0.6)', border: '1px solid #333', borderRadius: 2 }}>
          <Typography variant="h6" sx={{ color: '#00d4ff', mb: 2, fontFamily: 'Share Tech Mono' }}>🚀 Quick Actions</Typography>
          <Grid container spacing={2}>
            <Grid item>
              <Button variant="outlined" startIcon={<RefreshIcon />} onClick={() => { fetchHealth(); fetchErrors(); }} sx={{ borderColor: '#00d4ff', color: '#00d4ff' }}>Refresh All</Button>
            </Grid>
            <Grid item>
              <Button variant="outlined" startIcon={<DatabaseIcon />} href="/traffic" sx={{ borderColor: '#2196f3', color: '#2196f3' }}>Traffic Logs</Button>
            </Grid>
            <Grid item>
              <Button variant="outlined" startIcon={<AIIcon />} href="/retraining" sx={{ borderColor: '#9c27b0', color: '#9c27b0' }}>Model Retraining</Button>
            </Grid>
            <Grid item>
              <Button variant="outlined" startIcon={<SecurityIcon />} href="/attacks" sx={{ borderColor: '#ff3b6b', color: '#ff3b6b' }}>Threat Database</Button>
            </Grid>
            <Grid item>
              <Button variant="outlined" startIcon={<DashboardIcon />} href="/dashboard" sx={{ borderColor: '#ff9800', color: '#ff9800' }}>Dashboard</Button>
            </Grid>
          </Grid>
        </Paper>
      </Container>
    </Box>
  );
};

export default SystemDiagnostics;
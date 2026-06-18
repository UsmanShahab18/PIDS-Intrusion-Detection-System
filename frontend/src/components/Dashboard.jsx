import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { 
  Box, Paper, Typography, Grid, Card, CardContent,
  LinearProgress, CircularProgress, Alert, Button, Chip, IconButton,
  Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Tooltip, Switch, FormControlLabel,
  Menu, MenuItem, ListItemIcon, ListItemText,
  Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Radio, RadioGroup, FormControl, FormLabel,
  Snackbar
} from '@mui/material';
import {
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  PictureAsPdf as PdfIcon,
  TableChart as CsvIcon,
  Code as JsonIcon
} from '@mui/icons-material';

import { API_BASE } from '../config';

const Dashboard = () => {
  // ==========================================================================
  // STATE
  // ==========================================================================
  const [stats, setStats] = useState({
    total_traffic: 0,
    attacks: 0,
    suspicious: 0,
    normal: 0,
    attack_percentage: 0,
    // LLM Stats
    llm_analyzed: 0,
    llm_attacks: 0,
    llm_normal: 0,
    zero_day: 0
  });
  const [recentTraffic, setRecentTraffic] = useState([]);
  const [trafficLimit, setTrafficLimit] = useState(20);
  const [alerts, setAlerts] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(5); // seconds
  const [lastUpdated, setLastUpdated] = useState(null);
  const [downloadMenuAnchor, setDownloadMenuAnchor] = useState(null);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [exportType, setExportType] = useState('csv');
  const [exportLimit, setExportLimit] = useState('1000');
  const [customLimit, setCustomLimit] = useState('');
  const [expandedAlert, setExpandedAlert] = useState(null);
  const [confirmDialog, setConfirmDialog] = useState({ open: false, type: '', alertId: null, alertName: '' });
  const [snackbar, setSnackbar] = useState({ open: false, message: '', color: '#00d4ff' });
  const [recheckLoading, setRecheckLoading] = useState(null);
  const [trafficCount, setTrafficCount] = useState({ total: 0, attacks: 0, suspicious: 0, normal: 0 });
  const [showLLMStats, setShowLLMStats] = useState(true);

  // ==========================================================================
  // DATA FETCHING
  // ==========================================================================
  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/stats/`);
      if (response.data && response.data.total_traffic !== undefined) {
        setStats(response.data);
        setLastUpdated(new Date());
      }
    } catch (error) {
      console.error('Error fetching stats:', error);
      // Retry once after 2 seconds (handles token race condition on mobile)
      if (error.response?.status === 401) {
        setTimeout(async () => {
          try {
            const retry = await axios.get(`${API_BASE}/stats/`);
            if (retry.data && retry.data.total_traffic !== undefined) {
              setStats(retry.data);
              setLastUpdated(new Date());
            }
          } catch (e) { /* silent */ }
        }, 2000);
      }
    }
  }, []);

  const fetchRecentTraffic = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/traffic/?limit=${trafficLimit}`);
      setRecentTraffic(response.data);
    } catch (error) {
      console.error('Error fetching traffic:', error);
    }
  }, [trafficLimit]);

  const fetchAlerts = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/diverse-alerts/?per_type=5`);
      if (Array.isArray(response.data)) {
        setAlerts(response.data);
      } else if (response.data && Array.isArray(response.data.results)) {
        setAlerts(response.data.results);
      } else {
        setAlerts([]);
      }
    } catch (error) {
      console.error('fetchAlerts error:', error?.response?.status, error?.response?.data || error.message);
      // Fallback: fetch recent attacks from traffic endpoint
      try {
        const fallback = await axios.get(`${API_BASE}/traffic/?limit=30`);
        const data = Array.isArray(fallback.data) ? fallback.data : (fallback.data?.results || []);
        const threatsOnly = data.filter(t => t.status === 'Attack' || t.status === 'Suspicious');
        setAlerts(threatsOnly.slice(0, 20));
      } catch (e2) {
        console.error('fetchAlerts fallback also failed:', e2.message);
      }
    }
  }, []);

  const refreshAllData = useCallback(() => {
    fetchStats();
    fetchRecentTraffic();
    fetchAlerts();
  }, [fetchStats, fetchRecentTraffic, fetchAlerts]);

  // ==========================================================================
  // EFFECTS
  // ==========================================================================
  
  // Initial load
  useEffect(() => {
    refreshAllData();
  }, [refreshAllData]);

  // Auto-refresh interval
  useEffect(() => {
    let intervalId = null;
    
    if (autoRefresh) {
      intervalId = setInterval(() => {
        refreshAllData();
      }, refreshInterval * 1000);
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [autoRefresh, refreshInterval, refreshAllData]);

  // Re-fetch when tab becomes visible (mobile browser resumes from background)
  useEffect(() => {
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        refreshAllData();
      }
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, [refreshAllData]);

  // WebSocket connection
  useEffect(() => {
    let ws = null;
    let reconnectTimeout = null;

    const connectWebSocket = () => {
      // Get JWT token for authenticated WebSocket
      const hostname = window.location.hostname;
      let wsUrl = `ws://${hostname}:8000/ws/traffic/`;
      try {
        const saved = sessionStorage.getItem('pids_tokens');
        if (saved) {
          const tokens = JSON.parse(saved);
          if (tokens?.access) {
            wsUrl += `?token=${tokens.access}`;
          }
        }
      } catch (e) { /* no token available */ }
      
      ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
        console.log('✅ WebSocket Connected');
        setIsConnected(true);
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'packet' || data.type === 'update') {
            const pkt = data.data;
            // Add new packet to the top of the list
            setRecentTraffic(prev => {
              const newTraffic = [pkt, ...prev];
              return newTraffic.slice(0, 50); // Keep only last 50
            });
            // Update stats
            fetchStats();
            // If the new packet is an attack, refresh the alerts panel
            if (pkt && pkt.status === 'Attack') {
              fetchAlerts();
            }
          }
        } catch (error) {
          console.error('WebSocket message error:', error);
        }
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setIsConnected(false);
      };
      
      ws.onclose = () => {
        console.log('❌ WebSocket Disconnected');
        setIsConnected(false);
        // Try to reconnect after 5 seconds
        reconnectTimeout = setTimeout(connectWebSocket, 5000);
      };
    };

    connectWebSocket();

    return () => {
      if (ws) {
        ws.close();
      }
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
    };
  }, [fetchStats, fetchAlerts]);

  // ==========================================================================
  // HANDLERS
  // ==========================================================================
  const clearAlerts = async () => {
    try {
      await axios.post(`${API_BASE}/clear-alerts/`);
      setAlerts([]);
    } catch (error) {
      console.error('Error clearing alerts:', error);
    }
  };

  const [downloadProgress, setDownloadProgress] = useState({ open: false, message: '', done: false, error: false, percent: 0 });

  const _doDownload = async (url, filename, mime, label) => {
    // The backend can't stream real progress (single blob request), so we show
    // an estimated bar that eases toward ~95% over the expected time, then snaps
    // to 100% the moment the download lands. PDFs take longest (LLM summary).
    const expectedMs = /PDF/i.test(label) ? 60000 : 8000;
    const startTime = Date.now();
    setDownloadProgress({ open: true, message: `Generating ${label}…`, done: false, error: false, percent: 2 });
    const timer = setInterval(() => {
      const pct = Math.min(95, 2 + ((Date.now() - startTime) / expectedMs) * 93);
      setDownloadProgress(p => (p.open && !p.done && !p.error ? { ...p, percent: pct } : p));
    }, 250);
    try {
      const response = await axios.get(url, { responseType: 'blob' });
      const blobUrl = window.URL.createObjectURL(new Blob([response.data], { type: mime }));
      const link = document.createElement('a');
      link.href = blobUrl;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
      clearInterval(timer);
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      setDownloadProgress({ open: true, message: `${label} ready · ${elapsed}s`, done: true, error: false, percent: 100 });
      setTimeout(() => setDownloadProgress(p => ({ ...p, open: false })), 3500);
    } catch (error) {
      console.error(`Error downloading ${label}:`, error);
      clearInterval(timer);
      setDownloadProgress({ open: true, message: `Failed to generate ${label}`, done: false, error: true, percent: 0 });
      setTimeout(() => setDownloadProgress(p => ({ ...p, open: false })), 4000);
    }
  };

  const downloadReport = () => _doDownload(
    `${API_BASE}/report/`,
    `PIDS_Report_${new Date().toISOString().slice(0,10)}.pdf`,
    'application/pdf', 'PDF Report'
  );

  // The PDF download now goes through the same export dialog the CSV /
  // JSON paths use, so the user can pick how many recent-incident rows
  // the AI report should include before downloading.
  const downloadPDF = () => openExportDialog('pdf');

  const fetchTrafficCount = async () => {
    try {
      const response = await axios.get(`${API_BASE}/traffic/count/`);
      setTrafficCount(response.data);
    } catch (error) {
      console.error('Error fetching traffic count:', error);
    }
  };

  const openExportDialog = (type) => {
    setExportType(type);
    fetchTrafficCount();
    setExportDialogOpen(true);
    handleDownloadClose();
  };

  const handleExport = () => {
    let limit = exportLimit;
    if (exportLimit === 'custom' && customLimit) limit = customLimit;
    setExportDialogOpen(false);

    // PDF uses a separate endpoint + query-param name (`rows` instead
    // of `limit`) because the row count caps the *Recent Incidents*
    // table inside the AI-generated report, not a raw export size.
    if (exportType === 'pdf') {
      // Backend clamps to [5, 200]; the UI may pass any positive integer.
      _doDownload(
        `${API_BASE}/reports/pdf/?rows=${limit}`,
        `PIDS_Report_${new Date().toISOString().slice(0,10)}.pdf`,
        'application/pdf', 'PDF Report',
      );
      return;
    }

    const ext = exportType === 'csv' ? 'csv' : 'json';
    const mime = exportType === 'csv' ? 'text/csv' : 'application/json';
    _doDownload(
      `${API_BASE}/reports/${ext}/?limit=${limit}`,
      `PIDS_Report_${new Date().toISOString().slice(0,10)}.${ext}`,
      mime, `${ext.toUpperCase()} Report`
    );
  };

  const handleDownloadClick = (event) => {
    setDownloadMenuAnchor(event.currentTarget);
  };
  
  const handleDownloadClose = () => {
    setDownloadMenuAnchor(null);
  };

  const toggleAutoRefresh = () => {
    setAutoRefresh(prev => !prev);
  };

  // ==========================================================================
  // HELPERS
  // ==========================================================================
  const getStatusIcon = (status) => {
    switch (status) {
      case 'Attack': return <ErrorIcon sx={{ color: '#ff3b3b' }} />;
      case 'Suspicious': return <WarningIcon sx={{ color: '#ff9800' }} />;
      case 'Normal': return <CheckCircleIcon sx={{ color: '#4d9d7e' }} />;
      default: return <CheckCircleIcon />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'Attack': return '#ff3b3b';
      case 'Suspicious': return '#ff9800';
      case 'Normal': return '#4d9d7e';
      default: return '#9e9e9e';
    }
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return '--:--:--';
    
    try {
      // Handle string timestamp like "2026-02-16 06:15:00.157"
      if (typeof timestamp === 'string') {
        // If it contains space, split and get time part
        if (timestamp.includes(' ')) {
          const timePart = timestamp.split(' ')[1];
          // Return time with milliseconds (HH:MM:SS.mmm)
          return timePart || timestamp;
        }
        // If it's ISO format or other, parse it
        const date = new Date(timestamp);
        if (!isNaN(date.getTime())) {
          return date.toLocaleTimeString('en-US', { 
            hour12: false, 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            fractionalSecondDigits: 3 
          });
        }
        return timestamp;
      }
      
      // Handle Date object or number
      const date = new Date(timestamp);
      return date.toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit'
      });
    } catch (e) {
      return '--:--:--';
    }
  };

  // Calculate distribution percentages
  const total = stats.total_traffic || 1;
  const normalPercent = (stats.normal / total) * 100;
  const suspiciousPercent = (stats.suspicious / total) * 100;
  const attackPercent = (stats.attacks / total) * 100;

  // ==========================================================================
  // RENDER
  // ==========================================================================
  return (
    <Box sx={{ flexGrow: 1, p: { xs: 1.5, sm: 2, md: 3 }, maxWidth: '100%', overflowX: 'hidden' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3, flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ color: '#00d4ff' }}>
            🛡️ PIDS Dashboard
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <Typography variant="subtitle1" color="textSecondary">
              Predictive Intrusion Detection System
            </Typography>
            <Chip
              size="small"
              icon={<Box sx={{ width: 8, height: 8, borderRadius: '50%', 
                bgcolor: stats.sniffer_active ? '#00d4ff' : '#ff3b3b',
                animation: stats.sniffer_active ? 'pulse 2s infinite' : 'none',
                ml: 0.5 }} />}
              label={stats.sniffer_active ? `Sniffer Active (${stats.sniffer_pps || 0} pkt/30s)` : 'Sniffer Offline'}
              sx={{ 
                bgcolor: stats.sniffer_active ? 'rgba(0,255,65,0.1)' : 'rgba(255,59,59,0.1)',
                color: stats.sniffer_active ? '#00d4ff' : '#ff3b3b',
                border: `1px solid ${stats.sniffer_active ? 'rgba(0,255,65,0.3)' : 'rgba(255,59,59,0.3)'}`,
                fontFamily: 'Share Tech Mono',
                fontSize: '0.7rem',
                height: 24,
              }}
            />
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Manual refresh */}
          <Tooltip title="Refresh Now">
            <IconButton onClick={refreshAllData} color="primary">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          
          {/* Download report */}
          <Tooltip title="Download Report">
            <IconButton onClick={handleDownloadClick} color="primary">
              <DownloadIcon />
            </IconButton>
          </Tooltip>
          <Menu
            anchorEl={downloadMenuAnchor}
            open={Boolean(downloadMenuAnchor)}
            onClose={handleDownloadClose}
            PaperProps={{
              sx: {
                bgcolor: '#1a1a2e',
                border: '1px solid #00d4ff',
              }
            }}
          >
            <MenuItem onClick={() => { downloadPDF(); handleDownloadClose(); }}>
              <ListItemIcon>
                <PdfIcon sx={{ color: '#ff3b3b' }} />
              </ListItemIcon>
              <ListItemText primary="PDF Report" secondary="With AI Summary" />
            </MenuItem>
            <MenuItem onClick={() => openExportDialog('csv')}>
              <ListItemIcon>
                <CsvIcon sx={{ color: '#00d4ff' }} />
              </ListItemIcon>
              <ListItemText primary="CSV Export" secondary="With 31 ML Features" />
            </MenuItem>
            <MenuItem onClick={() => openExportDialog('json')}>
              <ListItemIcon>
                <JsonIcon sx={{ color: '#2196f3' }} />
              </ListItemIcon>
              <ListItemText primary="JSON Export" secondary="With 31 ML Features" />
            </MenuItem>
          </Menu>
        </Box>
      </Box>

      {/* Stats Cards - 3 Main Cards with staggered animation */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                📊 Total Traffic
              </Typography>
              <Typography variant="h4" sx={{ color: '#00d4ff' }}>
                {stats.total_traffic.toLocaleString()}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                Packets Analyzed
              </Typography>
              {stats.llm_analyzed > 0 && (
                <Typography variant="caption" display="block" sx={{ color: '#9c27b0', mt: 0.5 }}>
                  🔮 {stats.llm_analyzed.toLocaleString()} analyzed by LLM
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ borderLeft: '4px solid #ff3b6b', background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                🚨 Attacks Detected
              </Typography>
              <Typography variant="h4" color="error">
                {stats.attacks.toLocaleString()}
              </Typography>
              <LinearProgress 
                variant="determinate" 
                value={attackPercent} 
                color="error"
                sx={{ mt: 1, height: 6, borderRadius: 3 }}
              />
              <Typography variant="caption" color="textSecondary">
                {attackPercent.toFixed(1)}% of total
              </Typography>
              {stats.llm_attacks > 0 && (
                <Typography variant="caption" display="block" sx={{ color: '#9c27b0', mt: 0.5 }}>
                  🔮 {stats.llm_attacks.toLocaleString()} by LLM ({stats.zero_day.toLocaleString()} Threat Intel)
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} sm={6} md={4}>
          <Card sx={{ borderLeft: '4px solid #4d9d7e', background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)' }}>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                ✅ Normal Traffic
              </Typography>
              <Typography variant="h4" color="success.main">
                {stats.normal.toLocaleString()}
              </Typography>
              <LinearProgress 
                variant="determinate" 
                value={normalPercent} 
                color="success"
                sx={{ mt: 1, height: 6, borderRadius: 3 }}
              />
              <Typography variant="caption" color="textSecondary">
                {normalPercent.toFixed(1)}% of total
              </Typography>
              {stats.llm_normal > 0 && (
                <Typography variant="caption" display="block" sx={{ color: '#9c27b0', mt: 0.5 }}>
                  🔮 {stats.llm_normal.toLocaleString()} cleared by LLM
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* LLM Analysis Stats - Always show */}
      <Paper sx={{ p: 2, mb: 3, background: 'linear-gradient(135deg, #1a1a2e 0%, #2d1b4e 100%)', border: '1px solid #9c27b0' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" sx={{ color: '#ce93d8' }}>
            🔮 LLM Threat Intelligence
          </Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {stats.llm_analyzed > 0 && (
              <Chip 
                label={`${stats.llm_analyzed} Analyzed`} 
                size="small" 
                sx={{ bgcolor: '#9c27b0', color: 'white' }} 
              />
            )}
            {stats.zero_day > 0 && (
              <Chip 
                label={`${stats.zero_day} LLM Detected!`} 
                size="small" 
                sx={{ bgcolor: '#ff5722', color: 'white', animation: 'pulse 1s infinite' }} 
              />
            )}
          </Box>
        </Box>
        
        {stats.llm_analyzed > 0 ? (
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center', p: 1.5, bgcolor: 'rgba(156, 39, 176, 0.15)', borderRadius: 2, border: '1px solid rgba(156, 39, 176, 0.3)' }}>
                <Typography variant="h5" sx={{ color: '#ce93d8', fontWeight: 'bold' }}>
                  {stats.llm_analyzed}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  Total LLM Analyzed
                </Typography>
                <Typography variant="caption" display="block" sx={{ color: '#9c27b0', fontSize: '0.7rem' }}>
                  ({((stats.llm_analyzed / Math.max(stats.total_traffic, 1)) * 100).toFixed(1)}% of traffic)
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center', p: 1.5, bgcolor: 'rgba(244, 67, 54, 0.15)', borderRadius: 2, border: '1px solid rgba(244, 67, 54, 0.3)' }}>
                <Typography variant="h5" sx={{ color: '#ff3b3b', fontWeight: 'bold' }}>
                  {stats.llm_attacks}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  LLM → Attack
                </Typography>
                <Typography variant="caption" display="block" sx={{ color: '#ff3b3b', fontSize: '0.7rem' }}>
                  (Threats Detected)
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center', p: 1.5, bgcolor: 'rgba(76, 175, 80, 0.15)', borderRadius: 2, border: '1px solid rgba(76, 175, 80, 0.3)' }}>
                <Typography variant="h5" sx={{ color: '#00d4ff', fontWeight: 'bold' }}>
                  {stats.llm_normal}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  LLM → Normal
                </Typography>
                <Typography variant="caption" display="block" sx={{ color: '#00d4ff', fontSize: '0.7rem' }}>
                  (False Positives Cleared)
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center', p: 1.5, bgcolor: 'rgba(255, 152, 0, 0.15)', borderRadius: 2, border: '1px solid rgba(255, 152, 0, 0.3)' }}>
                <Typography variant="h5" sx={{ color: '#ff9800', fontWeight: 'bold' }}>
                  {stats.zero_day}
                </Typography>
                <Typography variant="caption" color="textSecondary">
                  🔍 LLM Detected
                </Typography>
                <Typography variant="caption" display="block" sx={{ color: '#ff9800', fontSize: '0.7rem' }}>
                  (Threat Intel Based)
                </Typography>
              </Box>
            </Grid>
          </Grid>
        ) : (
          <Box sx={{ textAlign: 'center', py: 3, color: 'rgba(255,255,255,0.5)' }}>
            <Typography variant="body2">
              No LLM analysis yet. Run the sniffer to analyze suspicious traffic.
            </Typography>
          </Box>
        )}
      </Paper>

      {/* Traffic Distribution Bar - Only Normal vs Attacks */}
      <Paper sx={{ p: 2, mb: 4, background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)' }}>
        <Typography variant="h6" gutterBottom>
          📈 Traffic Distribution
        </Typography>
        <Box sx={{ display: 'flex', height: 40, borderRadius: 1, overflow: 'hidden' }}>
          <Tooltip title={`Normal: ${stats.normal.toLocaleString()} (${normalPercent.toFixed(1)}%)`}>
            <Box 
              sx={{ 
                width: `${normalPercent}%`, 
                backgroundColor: '#4d9d7e',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                fontWeight: 'bold',
                transition: 'width 0.5s ease-in-out'
              }}
            >
              {normalPercent > 10 && `${normalPercent.toFixed(0)}%`}
            </Box>
          </Tooltip>
          <Tooltip title={`Attacks: ${stats.attacks.toLocaleString()} (${attackPercent.toFixed(1)}%)`}>
            <Box 
              sx={{ 
                width: `${attackPercent}%`, 
                backgroundColor: '#ff3b6b',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'white',
                fontWeight: 'bold',
                transition: 'width 0.5s ease-in-out'
              }}
            >
              {attackPercent > 5 && `${attackPercent.toFixed(0)}%`}
            </Box>
          </Tooltip>
        </Box>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
          <Chip label={`✅ Normal: ${stats.normal.toLocaleString()}`} size="small" sx={{ bgcolor: '#4d9d7e', color: 'white' }} />
          <Chip label={`🚨 Attacks: ${stats.attacks.toLocaleString()}`} size="small" sx={{ bgcolor: '#ff3b6b', color: 'white' }} />
        </Box>
      </Paper>

      {/* Recent Traffic Table */}
      <Paper sx={{ p: 2, mb: 4, background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
          <Typography variant="h6">
            🔍 Recent Traffic {isConnected && <Chip label="LIVE" size="small" color="success" sx={{ ml: 1, animation: 'pulse 1s infinite' }} />}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
            {/* Entries limit control */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Typography sx={{ color: '#888', fontSize: '0.7rem', fontFamily: 'Share Tech Mono' }}>Show:</Typography>
              {[20, 50, 100, 200].map(n => (
                <Chip key={n} label={n} size="small" variant={trafficLimit === n ? 'filled' : 'outlined'}
                  onClick={() => setTrafficLimit(n)}
                  sx={{ cursor: 'pointer', fontFamily: 'Share Tech Mono', fontSize: '0.65rem', height: 22,
                    bgcolor: trafficLimit === n ? '#00d4ff' : 'transparent',
                    color: trafficLimit === n ? '#0a0a0a' : '#888',
                    borderColor: '#333',
                    '&:hover': { bgcolor: trafficLimit === n ? '#00a8cc' : 'rgba(0,255,65,0.1)' } }} />
              ))}
            </Box>
            {/* Refresh interval control */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Typography sx={{ color: '#888', fontSize: '0.7rem', fontFamily: 'Share Tech Mono' }}>Refresh:</Typography>
              {[3, 5, 10, 30].map(s => (
                <Chip key={s} label={`${s}s`} size="small" variant={refreshInterval === s && autoRefresh ? 'filled' : 'outlined'}
                  onClick={() => { setRefreshInterval(s); setAutoRefresh(true); }}
                  sx={{ cursor: 'pointer', fontFamily: 'Share Tech Mono', fontSize: '0.65rem', height: 22,
                    bgcolor: refreshInterval === s && autoRefresh ? '#00d4ff' : 'transparent',
                    color: refreshInterval === s && autoRefresh ? '#0a0a0a' : '#888',
                    borderColor: '#333',
                    '&:hover': { bgcolor: refreshInterval === s && autoRefresh ? '#00b8d4' : 'rgba(0,212,255,0.1)' } }} />
              ))}
              <Chip label={autoRefresh ? '⏸ Stop' : '▶ Start'} size="small"
                onClick={() => setAutoRefresh(!autoRefresh)}
                sx={{ cursor: 'pointer', fontFamily: 'Share Tech Mono', fontSize: '0.65rem', height: 22,
                  bgcolor: autoRefresh ? 'rgba(255,59,59,0.15)' : 'rgba(0,255,65,0.15)',
                  color: autoRefresh ? '#ff3b3b' : '#00d4ff',
                  borderColor: autoRefresh ? '#ff3b3b' : '#00d4ff',
                  border: '1px solid',
                  '&:hover': { bgcolor: autoRefresh ? 'rgba(255,59,59,0.25)' : 'rgba(0,255,65,0.25)' } }} />
            </Box>
            <Chip label={`${recentTraffic.length} entries`} size="small" color="primary" variant="outlined" sx={{ height: 22, fontSize: '0.65rem' }} />
          </Box>
        </Box>
        
        <TableContainer sx={{ maxHeight: 400, overflowX: 'auto' }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell sx={{ bgcolor: '#0a0a0a' }}>Time</TableCell>
                <TableCell sx={{ bgcolor: '#0a0a0a' }}>Source</TableCell>
                <TableCell sx={{ bgcolor: '#0a0a0a' }}>Destination</TableCell>
                <TableCell sx={{ bgcolor: '#0a0a0a' }}>Protocol</TableCell>
                <TableCell sx={{ bgcolor: '#0a0a0a' }}>Status</TableCell>
                <TableCell sx={{ bgcolor: '#0a0a0a' }}>Prediction</TableCell>
                <TableCell sx={{ bgcolor: '#0a0a0a' }} align="right">Confidence</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {recentTraffic.map((traffic, index) => (
                <TableRow 
                  key={traffic.id || index}
                  sx={{ 
                    backgroundColor: traffic.status === 'Attack' ? 'rgba(244, 67, 54, 0.15)' : 
                                   traffic.status === 'Suspicious' ? 'rgba(255, 152, 0, 0.15)' : 
                                   'transparent',
                    '&:hover': { backgroundColor: 'rgba(255,255,255,0.05)' },
                    animation: index === 0 ? 'fadeIn 0.5s ease-in' : 'none'
                  }}
                >
                  <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {formatTime(traffic.timestamp)}
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={`${traffic.source_ip || traffic.src_ip || 'Unknown'}:${traffic.src_port || ''}`} 
                      size="small" 
                      variant="outlined"
                      sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={`${traffic.destination_ip || traffic.dst_ip || 'Unknown'}:${traffic.dst_port || ''}`} 
                      size="small" 
                      variant="outlined"
                      sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip 
                      label={traffic.protocol || 'Unknown'} 
                      size="small"
                      color={traffic.protocol === 'TCP' ? 'primary' : 'secondary'}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getStatusIcon(traffic.status)}
                      <Typography variant="body2">
                        {traffic.status || 'Unknown'}
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Chip 
                        label={traffic.prediction || traffic.attack_type || 'Unknown'} 
                        size="small"
                        sx={{ 
                          backgroundColor: getStatusColor(traffic.status),
                          color: 'white',
                          fontWeight: 'bold'
                        }}
                      />
                      {traffic.llm_analyzed && (
                        <Chip 
                          label="LLM" 
                          size="small"
                          sx={{ 
                            backgroundColor: '#9c27b0',
                            color: 'white',
                            fontSize: '0.6rem',
                            height: 18
                          }}
                        />
                      )}
                    </Box>
                  </TableCell>
                  <TableCell align="right">
                    <Typography 
                      variant="body2" 
                      fontWeight="bold"
                      sx={{ 
                        color: traffic.confidence > 0.8 ? '#4d9d7e' : 
                               traffic.confidence > 0.5 ? '#ff9800' : '#ff3b3b'
                      }}
                    >
                      {traffic.confidence ? `${(traffic.confidence * 100).toFixed(1)}%` : 'N/A'}
                    </Typography>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      {/* Recent Threat Alerts — Individual, Scrollable */}
      <Paper sx={{ p: 2, background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">🔔 Recent Threat Alerts</Typography>
          {alerts.length > 0 && (
            <Typography variant="caption" sx={{ color: '#888' }}>
              {alerts.length} recent attacks
            </Typography>
          )}
        </Box>
        
        {alerts.length > 0 ? (
          <Box sx={{ maxHeight: 600, overflow: 'auto', pr: 0.5 }}>
          {alerts.map((alert, index) => {
            const pred = (alert.prediction || '').toLowerCase();
            const severity = (pred.includes('ddos') || pred.includes('dos') || pred.includes('hulk') || pred.includes('hoic') || pred.includes('botnet') || pred.includes('c2'))
              ? 'Critical' : (pred.includes('exfil') || pred.includes('infiltr') || pred.includes('shell') || pred.includes('backdoor'))
              ? 'High' : (pred.includes('brute') || pred.includes('scan'))
              ? 'Medium' : 'Low';
            return (
            <Box key={alert.id || index} sx={{ mb: 1 }}>
              <Alert
                severity={severity === 'Critical' || severity === 'High' ? 'error' :
                         severity === 'Medium' ? 'warning' : 'info'}
                sx={{ cursor: 'pointer', '&:hover': { opacity: 0.9 } }}
                onClick={() => setExpandedAlert(expandedAlert === (alert.id || index) ? null : (alert.id || index))}
                action={
                  <Typography sx={{ fontSize: '0.7rem', color: '#888', mr: 1, mt: 0.5 }}>
                    {expandedAlert === (alert.id || index) ? '▲' : '▼'}
                  </Typography>
                }
              >
                <strong>[{severity}]</strong> {alert.prediction || 'Attack'} from {alert.src_ip} → {alert.dst_ip}:{alert.dst_port}
                {alert.confidence && <span style={{ color: '#888', marginLeft: 8 }}>({(alert.confidence * 100).toFixed(0)}%)</span>}
                {alert.llm_analyzed && <span style={{ color: '#aa66ff', marginLeft: 6, fontSize: '0.8em' }}>LLM</span>}
                {alert.acknowledged && <span style={{ color: '#00d4ff', marginLeft: 6, fontSize: '0.8em' }}>👁️</span>}
              </Alert>
              
              {expandedAlert === (alert.id || index) && (
                <Box sx={{ position: 'relative', mx: 2, mt: 0, p: 2, bgcolor: '#0a1410', borderRadius: '0 0 8px 8px',
                  border: '1px solid #1a3a2a', borderTop: 'none' }}>

                  {/* Full-card LLM loading overlay — covers the WHOLE detail panel */}
                  {recheckLoading === (alert.id || index) && (
                    <Box sx={{ position: 'absolute', inset: 0, zIndex: 20,
                      bgcolor: 'rgba(0,0,0,0.78)', borderRadius: '0 0 8px 8px',
                      display: 'flex', flexDirection: 'column',
                      alignItems: 'center', justifyContent: 'center' }}>
                      <Box sx={{ width: 48, height: 48, border: '4px solid #2a1a3a', borderTop: '4px solid #aa66ff',
                        borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
                      <Typography sx={{ color: '#aa66ff', fontFamily: 'Share Tech Mono', fontSize: '0.95rem', mt: 2 }}>
                        🧠 LLM Analysing…
                      </Typography>
                      <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.75rem', mt: 0.5 }}>
                        querying Llama + behaviour engine
                      </Typography>
                    </Box>
                  )}

                  <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', mb: 1 }}>
                    📡 {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port} | {alert.protocol}
                  </Typography>
                  <Typography sx={{ color: '#888', fontSize: '0.75rem', mb: 1.5 }}>
                    {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : ''}
                  </Typography>

                  <Box sx={{ mb: 1.5, p: 1.5, bgcolor: 'rgba(0,0,0,0.3)', borderRadius: 1, border: '1px solid #1a3a2a' }}>
                    <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mb: alert.llm_result ? 1 : 0 }}>
                      <Typography sx={{ color: '#888', fontSize: '0.8rem', fontFamily: 'Share Tech Mono' }}>
                        🎯 Detection: <span style={{ color: alert.llm_analyzed ? '#aa66ff' : '#00d4ff' }}>
                          {alert.llm_analyzed ? 'ML + LLM' : 'ML Model'}
                        </span>
                      </Typography>
                      <Typography sx={{ color: '#888', fontSize: '0.8rem', fontFamily: 'Share Tech Mono' }}>
                        📋 Type: <span style={{ color: '#ff9800' }}>{alert.prediction || alert.attack_type || 'Unknown'}</span>
                      </Typography>
                      <Typography sx={{ color: '#888', fontSize: '0.8rem', fontFamily: 'Share Tech Mono' }}>
                        📊 Confidence: <span style={{ color: alert.confidence > 0.9 ? '#ff3b3b' : '#ff9800' }}>
                          {alert.confidence ? `${(alert.confidence * 100).toFixed(1)}%` : 'N/A'}
                        </span>
                      </Typography>
                    </Box>
                    {alert.llm_result && (
                      <Typography sx={{ color: '#aa66ff', fontSize: '0.8rem', fontFamily: 'Share Tech Mono', mt: 0.5 }}>
                        🧠 LLM: <span style={{ color: '#e0e0e0' }}>{
                          (() => {
                            try {
                              const parsed = typeof alert.llm_result === 'string' ? JSON.parse(alert.llm_result) : alert.llm_result;
                              return parsed.reasoning || parsed.reason || JSON.stringify(parsed);
                            } catch { return alert.llm_result; }
                          })()
                        }</span>
                      </Typography>
                    )}
                    {!alert.llm_result && alert.llm_analyzed && (
                      <Typography sx={{ color: '#aa66ff', fontSize: '0.8rem', fontFamily: 'Share Tech Mono', mt: 0.5 }}>
                        🧠 LLM confirmed ML prediction
                      </Typography>
                    )}
                    {!alert.llm_analyzed && (
                      <Typography sx={{ color: '#00d4ff', fontSize: '0.8rem', fontFamily: 'Share Tech Mono', mt: 0.5 }}>
                        🤖 ML detected directly
                      </Typography>
                    )}
                  </Box>
                  
                  {alert.features ? (
                    <>
                      <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.8rem', mb: 1 }}>
                        📊 {Object.keys(alert.features).length} Network Features:
                      </Typography>
                      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 0.5 }}>
                        {Object.entries(alert.features).map(([key, value]) => (
                          <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', px: 1, py: 0.3,
                            bgcolor: 'rgba(0,255,65,0.03)', borderRadius: 0.5 }}>
                            <Typography sx={{ color: '#888', fontSize: '0.7rem', fontFamily: 'Share Tech Mono' }}>{key}</Typography>
                            <Typography sx={{ color: '#e0e0e0', fontSize: '0.7rem', fontFamily: 'Share Tech Mono', fontWeight: 'bold' }}>
                              {typeof value === 'number' ? (value > 1000 ? value.toFixed(0) : value.toFixed(2)) : value}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </>
                  ) : (
                    <Button size="small" variant="text"
                      onClick={async () => {
                        try {
                          const res = await axios.get(`${API_BASE}/traffic/${alert.id}/features/`);
                          if (res.data.features) {
                            setAlerts(prev => prev.map(a => a.id === alert.id ? {...a, features: res.data.features} : a));
                          }
                        } catch (e) { console.log('Features not available'); }
                      }}
                      sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }}>
                      📊 Load Network Features
                    </Button>
                  )}
                  
                  <Box sx={{ display: 'flex', gap: 1, mt: 2, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
                    <Button size="small" variant="outlined"
                      disabled={recheckLoading !== null}
                      onClick={async () => {
                        setRecheckLoading(alert.id || index);
                        try {
                          const res = await axios.post(`${API_BASE}/traffic/${alert.id}/recheck-llm/`);
                          const data = res.data;
                          setSnackbar({
                            open: true,
                            message: `🧠 LLM: ${data.new_prediction} (${(data.new_confidence * 100).toFixed(0)}%) — ${data.reasoning || 'Done'}`,
                            color: data.new_status === 'Attack' ? '#ff3b3b' : '#00d4ff'
                          });
                          fetchAlerts();
                        } catch (e) {
                          const detail = e.response?.data?.error
                            || (e.code === 'ECONNABORTED' ? 'LLM timed out (model may be cold-loading — try again)' : e.message);
                          setSnackbar({ open: true, message: `❌ LLM recheck failed: ${detail}`, color: '#ff3b3b' });
                        } finally { setRecheckLoading(null); }
                      }}
                      sx={{ color: '#aa66ff', borderColor: '#2a1a3a', fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
                        '&:hover': { borderColor: '#aa66ff', bgcolor: 'rgba(170,102,255,0.05)' },
                        '&.Mui-disabled': { color: '#555', borderColor: '#1a1a2a' } }}>
                      {recheckLoading === (alert.id || index) ? '⏳ Analysing...' : '🧠 Recheck with LLM'}
                    </Button>
                    <Button size="small" variant="outlined"
                      disabled={alert.acknowledged}
                      onClick={async () => {
                        try {
                          await axios.put(`${API_BASE}/traffic/${alert.id}/acknowledge/`);
                          setSnackbar({ open: true, message: `👁️ Alert #${alert.id} acknowledged`, color: '#00d4ff' });
                          fetchAlerts();
                        } catch (e) { setSnackbar({ open: true, message: '❌ Failed', color: '#ff3b3b' }); }
                      }}
                      sx={{ color: '#00d4ff', borderColor: '#1a2a3a', fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
                        '&:hover': { borderColor: '#00d4ff', bgcolor: 'rgba(0,212,255,0.05)' },
                        '&.Mui-disabled': { color: '#555', borderColor: '#1a1a2a' } }}>
                      {alert.acknowledged ? '👁️ Ack' : '👁️ Acknowledge'}
                    </Button>
                    <Button size="small" variant="outlined"
                      onClick={() => setConfirmDialog({ open: true, type: 'reclassify', alertId: alert.id,
                        alertName: alert.prediction || 'this alert' })}
                      sx={{ color: '#00d4ff', borderColor: '#1a3a2a', fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
                        '&:hover': { borderColor: '#00d4ff', bgcolor: 'rgba(0,255,65,0.05)' } }}>
                      ✓ Normal
                    </Button>
                    <Button size="small" variant="outlined"
                      onClick={() => setConfirmDialog({ open: true, type: 'delete', alertId: alert.id,
                        alertName: alert.prediction || 'this alert' })}
                      sx={{ color: '#ff3b3b', borderColor: '#3a1a1a', fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
                        '&:hover': { borderColor: '#ff3b3b', bgcolor: 'rgba(255,59,59,0.05)' } }}>
                      🗑 Delete
                    </Button>
                  </Box>
                </Box>
              )}
            </Box>
            );
          })}
          </Box>
        ) : (
          <Alert severity="success" icon={<CheckCircleIcon />}>
            ✅ No active alerts. System is running normally.
          </Alert>
        )}
      </Paper>

      {/* Styled Confirmation Dialog */}
      <Dialog open={confirmDialog.open} onClose={() => setConfirmDialog({ ...confirmDialog, open: false })}
        PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2, minWidth: 400 } }}>
        <DialogTitle sx={{ fontFamily: 'Share Tech Mono', borderBottom: '1px solid #1a3a2a',
          color: confirmDialog.type === 'delete' ? '#ff3b3b' : '#00d4ff' }}>
          {confirmDialog.type === 'delete' ? '🗑 Delete Traffic Log' : '✓ Reclassify as Normal'}
        </DialogTitle>
        <DialogContent sx={{ pt: '20px !important' }}>
          <Typography sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono', fontSize: '0.9rem', mb: 1 }}>
            {confirmDialog.type === 'delete'
              ? 'This will permanently remove this traffic log from the database.'
              : 'This will reclassify the traffic as Normal. The corrected label will be used in future model retraining.'}
          </Typography>
          <Box sx={{ p: 1.5, bgcolor: 'rgba(0,0,0,0.3)', borderRadius: 1, border: '1px solid #1a3a2a', mt: 1 }}>
            <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>
              Alert: <span style={{ color: '#e0e0e0' }}>{confirmDialog.alertName}</span>
            </Typography>
            <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>
              ID: <span style={{ color: '#e0e0e0' }}>#{confirmDialog.alertId}</span>
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions sx={{ borderTop: '1px solid #1a3a2a', p: 2, gap: 1 }}>
          <Button onClick={() => setConfirmDialog({ ...confirmDialog, open: false })}
            sx={{ color: '#888', fontFamily: 'Share Tech Mono' }}>
            Cancel
          </Button>
          <Button variant="contained"
            onClick={async () => {
              try {
                if (confirmDialog.type === 'delete') {
                  await axios.delete(`${API_BASE}/traffic/${confirmDialog.alertId}/delete/`);
                  setSnackbar({ open: true, message: '🗑 Traffic log deleted successfully', color: '#ff3b3b' });
                } else {
                  await axios.put(`${API_BASE}/traffic/${confirmDialog.alertId}/reclassify/`);
                  setSnackbar({ open: true, message: '✓ Reclassified as Normal — will improve future training', color: '#00d4ff' });
                }
                setConfirmDialog({ ...confirmDialog, open: false });
                setExpandedAlert(null);
                fetchAlerts();
              } catch (e) {
                setSnackbar({ open: true, message: '❌ Action failed', color: '#ff3b3b' });
              }
            }}
            sx={{
              bgcolor: confirmDialog.type === 'delete' ? '#ff3b3b' : '#00d4ff',
              color: confirmDialog.type === 'delete' ? '#fff' : '#0a0a0a',
              fontFamily: 'Share Tech Mono', fontWeight: 'bold',
              '&:hover': { bgcolor: confirmDialog.type === 'delete' ? '#cc2222' : '#00a8cc' }
            }}>
            {confirmDialog.type === 'delete' ? 'Delete Permanently' : 'Mark as Normal'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success/Error Snackbar */}
      <Snackbar open={snackbar.open} autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })}
          sx={{ bgcolor: '#0d1117', color: snackbar.color, border: `1px solid ${snackbar.color}`,
            fontFamily: 'Share Tech Mono', '& .MuiAlert-icon': { color: snackbar.color } }}
          severity={snackbar.color === '#ff3b3b' ? 'error' : 'success'}>
          {snackbar.message}
        </Alert>
      </Snackbar>

      {/* Download Progress Notification — animated % bar (non-blocking) */}
      <Snackbar open={downloadProgress.open} autoHideDuration={downloadProgress.done || downloadProgress.error ? 4000 : null}
        onClose={() => setDownloadProgress(p => ({ ...p, open: false }))}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}>
        {(() => {
          const err = downloadProgress.error, done = downloadProgress.done;
          const edge = err ? '#ff3b3b' : done ? '#00ff88' : '#00d4ff';
          const fill = err
            ? 'linear-gradient(90deg,#ff3b3b,#ff7b6b)'
            : done
              ? 'linear-gradient(90deg,#00ff88,#00d4ff)'
              : 'linear-gradient(90deg,#00d4ff,#7a5cff,#aa66ff)';
          return (
            <Box sx={{
              minWidth: 360, maxWidth: 420, p: 1.8, borderRadius: 2,
              bgcolor: 'rgba(13,17,23,0.97)', border: `1px solid ${edge}`,
              boxShadow: `0 8px 32px ${edge}44, inset 0 0 0 1px rgba(255,255,255,0.03)`,
              fontFamily: 'Share Tech Mono', animation: 'fadeIn 0.3s ease',
            }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Typography sx={{ color: edge, fontSize: '0.82rem', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: 0.8 }}>
                  <span>{err ? '⚠️' : done ? '✅' : '📄'}</span>{downloadProgress.message}
                </Typography>
                <Typography sx={{ color: edge, fontSize: '0.95rem', fontWeight: 'bold', fontVariantNumeric: 'tabular-nums', minWidth: 44, textAlign: 'right' }}>
                  {Math.round(downloadProgress.percent)}%
                </Typography>
              </Box>
              <Box sx={{ position: 'relative', height: 10, borderRadius: 6, bgcolor: 'rgba(255,255,255,0.07)', overflow: 'hidden' }}>
                <Box sx={{
                  height: '100%', width: `${downloadProgress.percent}%`, borderRadius: 6,
                  background: fill, backgroundSize: '200% 100%',
                  transition: 'width 0.35s cubic-bezier(0.4,0,0.2,1)',
                  boxShadow: `0 0 12px ${edge}`,
                  animation: (!done && !err) ? 'barShimmer 1.4s linear infinite' : 'none',
                }} />
              </Box>
            </Box>
          );
        })()}
      </Snackbar>

      {/* CSS for animations */}
      <style>
        {`
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
          }
          @keyframes barShimmer {
            0% { background-position: 0% 0; }
            100% { background-position: 200% 0; }
          }
        `}
      </style>

      {/* Export Dialog */}
      <Dialog 
        open={exportDialogOpen} 
        onClose={() => setExportDialogOpen(false)}
        PaperProps={{
          sx: {
            bgcolor: '#1a1a2e',
            border: '1px solid #00d4ff',
            minWidth: 400
          }
        }}
      >
        <DialogTitle sx={{ color: '#00d4ff' }}>
          📊 Export Traffic Data ({exportType.toUpperCase()})
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mb: 2, mt: 1 }}>
            <Typography variant="body2" color="textSecondary" gutterBottom>
              Total Records Available: <strong style={{ color: '#00d4ff' }}>{trafficCount.total.toLocaleString()}</strong>
            </Typography>
            <Typography variant="caption" color="textSecondary">
              (Attacks: {trafficCount.attacks.toLocaleString()} | Suspicious: {trafficCount.suspicious.toLocaleString()} | Normal: {trafficCount.normal.toLocaleString()})
            </Typography>
          </Box>
          
          <FormControl component="fieldset" sx={{ width: '100%' }}>
            <FormLabel sx={{ color: '#00d4ff', mb: 1 }}>How many records to export?</FormLabel>
            <RadioGroup
              value={exportLimit}
              onChange={(e) => setExportLimit(e.target.value)}
            >
              <FormControlLabel 
                value="100" 
                control={<Radio sx={{ color: '#00d4ff', '&.Mui-checked': { color: '#00d4ff' } }} />} 
                label="Recent 100 records" 
              />
              <FormControlLabel 
                value="1000" 
                control={<Radio sx={{ color: '#00d4ff', '&.Mui-checked': { color: '#00d4ff' } }} />} 
                label="Recent 1,000 records" 
              />
              <FormControlLabel 
                value="5000" 
                control={<Radio sx={{ color: '#00d4ff', '&.Mui-checked': { color: '#00d4ff' } }} />} 
                label="Recent 5,000 records" 
              />
              <FormControlLabel 
                value="10000" 
                control={<Radio sx={{ color: '#00d4ff', '&.Mui-checked': { color: '#00d4ff' } }} />} 
                label="Recent 10,000 records" 
              />
              <FormControlLabel 
                value="all" 
                control={<Radio sx={{ color: '#00d4ff', '&.Mui-checked': { color: '#00d4ff' } }} />} 
                label={`All records (${trafficCount.total.toLocaleString()})`}
              />
              <FormControlLabel 
                value="custom" 
                control={<Radio sx={{ color: '#00d4ff', '&.Mui-checked': { color: '#00d4ff' } }} />} 
                label="Custom amount" 
              />
            </RadioGroup>
            
            {exportLimit === 'custom' && (
              <TextField
                type="number"
                label="Number of records"
                value={customLimit}
                onChange={(e) => setCustomLimit(e.target.value)}
                size="small"
                sx={{ 
                  mt: 1,
                  '& .MuiOutlinedInput-root': {
                    '& fieldset': { borderColor: '#00d4ff' },
                    '&:hover fieldset': { borderColor: '#00d4ff' },
                  },
                  '& .MuiInputLabel-root': { color: '#00d4ff' },
                  '& .MuiInputBase-input': { color: '#fff' }
                }}
              />
            )}
          </FormControl>
          
          <Alert severity="info" sx={{ mt: 2 }}>
            <Typography variant="caption">
              {exportType === 'csv' ? (
                <>📋 CSV includes all <strong>31 ML features</strong> for model retraining</>
              ) : (
                <>📋 JSON includes all <strong>31 ML features</strong> with metadata</>
              )}
            </Typography>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportDialogOpen(false)} color="inherit">
            Cancel
          </Button>
          <Button 
            onClick={handleExport} 
            variant="contained" 
            sx={{ bgcolor: '#00d4ff', color: '#000', '&:hover': { bgcolor: '#00a8cc' } }}
          >
            Export {exportType.toUpperCase()}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Dashboard;
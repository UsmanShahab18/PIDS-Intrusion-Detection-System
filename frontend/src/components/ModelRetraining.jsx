import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Container, Typography, Paper, Grid, Card, CardContent,
  Button, Switch, FormControlLabel, Slider, TextField,
  LinearProgress, Alert, Accordion, AccordionSummary, AccordionDetails,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  IconButton, Tooltip, CircularProgress,
  Dialog, DialogTitle, DialogContent, DialogActions, Fade, Chip,
  ToggleButton, ToggleButtonGroup, Stack
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Memory as MemoryIcon,
  Speed as SpeedIcon,
  History as HistoryIcon,
  Backup as BackupIcon,
  Restore as RestoreIcon,
  Settings as SettingsIcon,
  Analytics as AnalyticsIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  DataUsage as DataIcon,
  Security as SecurityIcon
} from '@mui/icons-material';
import axios from 'axios';
import '../App.css';

import { API_BASE } from '../config';

// Custom Confirmation Dialog Component
const ConfirmDialog = ({ open, onClose, onConfirm, title, message, type = 'warning', confirmText = 'Confirm', cancelText = 'Cancel' }) => {
  const getIcon = () => {
    switch (type) {
      case 'warning': return <WarningIcon sx={{ fontSize: 60, color: '#ff9800' }} />;
      case 'danger': return <ErrorIcon sx={{ fontSize: 60, color: '#ff3b6b' }} />;
      case 'success': return <CheckIcon sx={{ fontSize: 60, color: '#4d9d7e' }} />;
      case 'info': return <InfoIcon sx={{ fontSize: 60, color: '#2196f3' }} />;
      default: return <WarningIcon sx={{ fontSize: 60, color: '#ff9800' }} />;
    }
  };

  const getColor = () => {
    switch (type) {
      case 'warning': return '#ff9800';
      case 'danger': return '#ff3b6b';
      case 'success': return '#4d9d7e';
      case 'info': return '#2196f3';
      default: return '#ff9800';
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      TransitionComponent={Fade}
      transitionDuration={300}
      PaperProps={{
        sx: {
          bgcolor: 'rgba(10, 10, 10, 0.95)',
          border: `2px solid ${getColor()}`,
          borderRadius: 3,
          minWidth: 450,
          maxWidth: 550,
          boxShadow: `0 0 30px ${getColor()}40`
        }
      }}
    >
      <DialogTitle sx={{ textAlign: 'center', pt: 4 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
          {getIcon()}
          <Typography variant="h5" sx={{ color: '#fff', fontFamily: 'Share Tech Mono' }}>
            {title}
          </Typography>
        </Box>
      </DialogTitle>
      <DialogContent>
        <Typography variant="body1" sx={{ color: '#aaa', textAlign: 'center', px: 2, whiteSpace: 'pre-line' }}>
          {message}
        </Typography>
      </DialogContent>
      <DialogActions sx={{ justifyContent: 'center', pb: 3, gap: 2 }}>
        <Button
          variant="outlined"
          onClick={onClose}
          sx={{
            color: '#888',
            borderColor: '#444',
            px: 4,
            '&:hover': { borderColor: '#888', bgcolor: 'rgba(255,255,255,0.05)' }
          }}
        >
          {cancelText}
        </Button>
        <Button
          variant="contained"
          onClick={() => { onConfirm(); onClose(); }}
          sx={{
            bgcolor: getColor(),
            color: type === 'warning' ? '#000' : '#fff',
            px: 4,
            fontWeight: 'bold',
            '&:hover': { bgcolor: getColor(), filter: 'brightness(0.9)' }
          }}
        >
          {confirmText}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// Result Dialog Component
const ResultDialog = ({ open, onClose, title, message, type = 'success', details = null }) => {
  const getIcon = () => {
    switch (type) {
      case 'success': return <CheckIcon sx={{ fontSize: 60, color: '#4d9d7e' }} />;
      case 'error': return <CancelIcon sx={{ fontSize: 60, color: '#ff3b6b' }} />;
      case 'info': return <InfoIcon sx={{ fontSize: 60, color: '#2196f3' }} />;
      default: return <CheckIcon sx={{ fontSize: 60, color: '#4d9d7e' }} />;
    }
  };

  const getColor = () => {
    switch (type) {
      case 'success': return '#4d9d7e';
      case 'error': return '#ff3b6b';
      case 'info': return '#2196f3';
      default: return '#4d9d7e';
    }
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      TransitionComponent={Fade}
      transitionDuration={300}
      PaperProps={{
        sx: {
          bgcolor: 'rgba(10, 10, 10, 0.95)',
          border: `2px solid ${getColor()}`,
          borderRadius: 3,
          minWidth: 400,
          boxShadow: `0 0 30px ${getColor()}40`
        }
      }}
    >
      <DialogTitle sx={{ textAlign: 'center', pt: 4 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
          {getIcon()}
          <Typography variant="h5" sx={{ color: '#fff', fontFamily: 'Share Tech Mono' }}>
            {title}
          </Typography>
        </Box>
      </DialogTitle>
      <DialogContent>
        <Typography variant="body1" sx={{ color: '#888', textAlign: 'center', px: 2 }}>
          {message}
        </Typography>
        {details && (
          <Box sx={{ mt: 2, p: 2, bgcolor: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
            <Typography variant="body2" sx={{ color: '#00d4ff', fontFamily: 'monospace', whiteSpace: 'pre-line' }}>
              {details}
            </Typography>
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ justifyContent: 'center', pb: 3 }}>
        <Button
          variant="contained"
          onClick={onClose}
          sx={{
            bgcolor: getColor(),
            color: '#fff',
            px: 6,
            fontWeight: 'bold',
            '&:hover': { bgcolor: getColor(), filter: 'brightness(0.9)' }
          }}
        >
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
};

// Data Quality Indicator Component
const DataQualityIndicator = ({ dataStats, onShowDetails }) => {
  const available = dataStats?.available_for_training || 0;
  const attacks = dataStats?.available_attacks || 0;
  const normal = dataStats?.available_normal || 0;
  
  // Calculate quality metrics
  const ratio = normal > 0 && attacks > 0 ? (normal / attacks) : 999;
  const isBalanced = ratio >= 0.5 && ratio <= 10;
  const hasEnoughAttacks = attacks >= 1000;
  const hasEnoughData = available >= 10000;
  
  // Quality score (0-100)
  let qualityScore = 0;
  if (hasEnoughData) qualityScore += 30;
  if (hasEnoughAttacks) qualityScore += 40;
  if (isBalanced) qualityScore += 30;
  
  const getQualityColor = () => {
    if (qualityScore >= 70) return '#4d9d7e';
    if (qualityScore >= 40) return '#ff9800';
    return '#ff3b6b';
  };
  
  const getQualityLabel = () => {
    if (qualityScore >= 70) return 'Good';
    if (qualityScore >= 40) return 'Fair';
    return 'Poor';
  };

  return (
    <Paper sx={{ p: 3, mb: 3, background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: `2px solid ${getQualityColor()}` }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6" sx={{ color: '#fff', display: 'flex', alignItems: 'center', gap: 1 }}>
          <DataIcon sx={{ color: getQualityColor() }} />
          Data Quality Assessment
        </Typography>
        <Chip 
          label={`${getQualityLabel()} (${qualityScore}/100)`}
          sx={{ 
            bgcolor: `${getQualityColor()}20`, 
            color: getQualityColor(),
            fontWeight: 'bold',
            border: `1px solid ${getQualityColor()}`
          }}
        />
      </Box>
      
      <Grid container spacing={2}>
        <Grid item xs={12} sm={4}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {hasEnoughData ? <CheckIcon sx={{ color: '#4d9d7e' }} /> : <WarningIcon sx={{ color: '#ff3b6b' }} />}
            <Typography variant="body2" sx={{ color: '#aaa' }}>
              Data Volume: {available.toLocaleString()}
              {!hasEnoughData && <span style={{ color: '#ff3b6b' }}> (need 10k+)</span>}
            </Typography>
          </Box>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {hasEnoughAttacks ? <CheckIcon sx={{ color: '#4d9d7e' }} /> : <WarningIcon sx={{ color: '#ff3b6b' }} />}
            <Typography variant="body2" sx={{ color: '#aaa' }}>
              Attack Samples: {attacks.toLocaleString()}
              {!hasEnoughAttacks && <span style={{ color: '#ff3b6b' }}> (need 1k+)</span>}
            </Typography>
          </Box>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {isBalanced ? <CheckIcon sx={{ color: '#4d9d7e' }} /> : <WarningIcon sx={{ color: '#ff9800' }} />}
            <Typography variant="body2" sx={{ color: '#aaa' }}>
              Balance Ratio: 1:{ratio.toFixed(0)}
              {!isBalanced && <span style={{ color: '#ff9800' }}> (imbalanced)</span>}
            </Typography>
          </Box>
        </Grid>
      </Grid>
      
      {qualityScore < 70 && (
        <Alert 
          severity="warning" 
          sx={{ 
            mt: 2, 
            bgcolor: 'rgba(255,152,0,0.1)',
            '& .MuiAlert-icon': { color: '#ff9800' }
          }}
        >
          <Typography variant="body2">
            <strong>Recommendation:</strong> Your captured traffic data may not produce optimal results. 
            The original CICIDS-trained models (98%/95% accuracy) are recommended for production use.
            Retraining is best when you have a balanced, properly-labeled attack dataset.
          </Typography>
        </Alert>
      )}
    </Paper>
  );
};

const ModelRetraining = () => {
  // State
  const [dataStats, setDataStats] = useState(null);
  const [trainingStatus, setTrainingStatus] = useState({ is_training: false, progress: 0, stage: '', log: [] });
  const [history, setHistory] = useState([]);
  const [backups, setBackups] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // Dialog states
  const [confirmDialog, setConfirmDialog] = useState({ open: false, title: '', message: '', type: 'warning', onConfirm: () => {} });
  const [resultDialog, setResultDialog] = useState({ open: false, title: '', message: '', type: 'success', details: null });
  
  // Configuration state - defaults match original notebook
  const [config, setConfig] = useState({
    engine: 'ml',             // which engine to retrain: 'ml' | 'dl'
    use_gpu: false,
    test_size: 0.2,
    min_samples: 100,
    max_samples: 0,           // 0 = no cap
    max_percentage: 100,      // 1-100%
    xgb_n_estimators: 200,   // Original: 200
    xgb_max_depth: 6,
    xgb_learning_rate: 0.1,
    lgb_n_estimators: 200,   // Original: 200
    lgb_max_depth: 6,
    lgb_learning_rate: 0.1,
    lgb_num_leaves: 31,
    // DL (Keras) hyperparameters — used when engine === 'dl'
    dl_epochs: 15,
    dl_batch_size: 512,
    dl_learning_rate: 0.001,
    early_stopping: false,
    early_stopping_rounds: 10,
    cross_validation: false,
    cv_folds: 5
  });

  // Fetch data
  const fetchData = useCallback(async () => {
    try {
      const [statsRes, statusRes, historyRes, backupsRes] = await Promise.all([
        axios.get(`${API_BASE}/retraining/data-stats/`),
        axios.get(`${API_BASE}/retraining/status/`),
        axios.get(`${API_BASE}/retraining/history/`),
        axios.get(`${API_BASE}/retraining/backups/`)
      ]);
      setDataStats(statsRes.data);
      setTrainingStatus(statusRes.data);
      setHistory(historyRes.data);
      setBackups(backupsRes.data);
    } catch (error) {
      console.error('Error fetching data:', error);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
    // Poll faster during training (3s), slower when idle (10s)
    const interval = setInterval(fetchData, trainingStatus.is_training ? 3000 : 10000);
    return () => clearInterval(interval);
  }, [fetchData, trainingStatus.is_training]);

  // Calculate data quality
  const getDataQuality = () => {
    const available = dataStats?.available_for_training || 0;
    const attacks = dataStats?.available_attacks || 0;
    const normal = dataStats?.available_normal || 0;
    const ratio = normal > 0 && attacks > 0 ? (normal / attacks) : 999;
    
    return {
      isBalanced: ratio >= 0.5 && ratio <= 10,
      hasEnoughAttacks: attacks >= 1000,
      hasEnoughData: available >= 10000,
      ratio: ratio,
      score: (attacks >= 1000 ? 40 : 0) + (available >= 10000 ? 30 : 0) + (ratio <= 10 ? 30 : 0)
    };
  };

  // Show confirmation dialog
  const showConfirm = (title, message, type, onConfirm, confirmText = 'Confirm') => {
    setConfirmDialog({ open: true, title, message, type, onConfirm, confirmText });
  };

  // Show result dialog
  const showResult = (title, message, type, details = null) => {
    setResultDialog({ open: true, title, message, type, details });
  };

  // Start training with quality warning
  const startTraining = () => {
    const quality = getDataQuality();
    const bp = dataStats?.balanced_preview || {};
    
    // Calculate effective counts with user limits applied
    let effAttacks = bp.attacks || 0;
    let effNormal = bp.normal || 0;
    if (config.max_percentage < 100) {
      effAttacks = Math.max(10, Math.floor(effAttacks * config.max_percentage / 100));
      effNormal = Math.min(bp.normal || 0, effAttacks * 2);
    }
    if (config.max_samples > 0 && (effAttacks + effNormal) > config.max_samples) {
      const capA = Math.floor(config.max_samples / 3);
      effAttacks = Math.min(effAttacks, capA);
      effNormal = Math.min(effNormal, config.max_samples - effAttacks);
    }
    const effTotal = effAttacks + effNormal;
    
    let warningMessage = `⚖️ 1/3 ATTACK BALANCING APPLIED:\n`;
    warningMessage += `• ${effAttacks.toLocaleString()} attacks + ${effNormal.toLocaleString()} normal = ${effTotal.toLocaleString()} total\n`;
    if (config.max_samples > 0) warningMessage += `• Max samples cap: ${config.max_samples.toLocaleString()}\n`;
    if (config.max_percentage < 100) warningMessage += `• Using ${config.max_percentage}% of available data\n`;
    warningMessage += `\n`;
    
    if (quality.score < 70) {
      warningMessage += `⚠️ DATA QUALITY WARNINGS:\n`;
      if (!quality.hasEnoughAttacks) {
        warningMessage += `• Only ${dataStats?.available_attacks?.toLocaleString()} attack samples (recommended: 1,000+)\n`;
      }
      if (!quality.isBalanced) {
        warningMessage += `• Raw data is imbalanced (1:${quality.ratio.toFixed(0)} ratio) — balancing will fix this\n`;
      }
      warningMessage += `\nResults may differ from original CICIDS-trained models.\nContinue anyway?`;
    } else {
      warningMessage += `Used data will be marked and excluded from future runs.\nThe training may take several minutes.`;
    }
    
    showConfirm(
      quality.score < 70 ? '⚠️ Data Quality Warning' : 'Start Model Training?',
      warningMessage,
      quality.score < 70 ? 'warning' : 'info',
      async () => {
        try {
          await axios.post(`${API_BASE}/retraining/start/`, config);
          // Immediately show training panel — don't wait for next poll
          setTrainingStatus(prev => ({
            ...prev,
            is_training: true,
            progress: 0,
            stage: 'Initialising training pipeline...',
            log: [{ time: new Date().toLocaleTimeString('en-GB', { hour12: false }), message: 'Training started...', level: 'info' }]
          }));
          fetchData();
        } catch (error) {
          showResult('Failed to Start', error.response?.data?.error || 'Failed to start training', 'error');
        }
      },
      quality.score < 70 ? 'Train Anyway' : 'Start Training'
    );
  };

  // Restore backup
  const restoreBackup = (backupName) => {
    showConfirm(
      'Restore Backup?',
      `Are you sure you want to restore "${backupName}"?\n\nThis will replace the current models with the backup version.`,
      'warning',
      async () => {
        try {
          await axios.post(`${API_BASE}/retraining/restore/`, { backup_name: backupName });
          showResult('Backup Restored', `Successfully restored models from ${backupName}`, 'success');
          fetchData();
        } catch (error) {
          showResult('Restore Failed', error.response?.data?.error || 'Failed to restore backup', 'error');
        }
      },
      'Restore'
    );
  };

  // Reset training flags
  const resetFlags = () => {
    showConfirm(
      'Reset Training Flags?',
      'This will mark all previously used training data as available again.\n\nUse this if you want to retrain on the same data.',
      'warning',
      async () => {
        try {
          const res = await axios.post(`${API_BASE}/retraining/reset-flags/`);
          showResult('Flags Reset', `Successfully reset ${res.data.count?.toLocaleString() || 0} records for retraining`, 'success');
          fetchData();
        } catch (error) {
          showResult('Reset Failed', 'Failed to reset training flags', 'error');
        }
      },
      'Reset'
    );
  };

  const updateConfig = (key, value) => {
    setConfig(prev => ({ ...prev, [key]: value }));
  };

  // Cancel training
  const cancelTraining = () => {
    showConfirm(
      'Cancel Training?',
      'Are you sure you want to cancel the current training run?\n\nThis will stop the pipeline at the next checkpoint. Models will NOT be updated.',
      'danger',
      async () => {
        try {
          await axios.post(`${API_BASE}/retraining/cancel/`);
          showResult('Training Cancelled', 'Training has been cancelled. Your previous models remain unchanged.', 'info');
          fetchData();
        } catch (error) {
          showResult('Cancel Failed', error.response?.data?.error || 'Failed to cancel training', 'error');
        }
      },
      'Yes, Cancel'
    );
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', bgcolor: 'transparent' }}>
        <CircularProgress sx={{ color: '#00d4ff' }} />
      </Box>
    );
  }

  const quality = getDataQuality();

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent', py: 4 }}>
      {/* Confirmation Dialog */}
      <ConfirmDialog
        open={confirmDialog.open}
        onClose={() => setConfirmDialog({ ...confirmDialog, open: false })}
        onConfirm={confirmDialog.onConfirm}
        title={confirmDialog.title}
        message={confirmDialog.message}
        type={confirmDialog.type}
        confirmText={confirmDialog.confirmText}
      />

      {/* Result Dialog */}
      <ResultDialog
        open={resultDialog.open}
        onClose={() => setResultDialog({ ...resultDialog, open: false })}
        title={resultDialog.title}
        message={resultDialog.message}
        type={resultDialog.type}
        details={resultDialog.details}
      />

      <Container maxWidth="xl">
        {/* Header */}
        <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h4" sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono' }}>
              🧠 Model Retraining
            </Typography>
            <Typography variant="body2" sx={{ color: '#888', mt: 1 }}>
              Retrain models using captured traffic data
            </Typography>
          </Box>
          <Stack direction="row" spacing={2} alignItems="center">
            {/* Engine selector — picks which retrainer the API will run. */}
            <Box>
              <Typography variant="caption" sx={{ color: '#888', display: 'block', mb: 0.5, fontFamily: 'Share Tech Mono' }}>
                Engine to retrain
              </Typography>
              <ToggleButtonGroup
                exclusive
                size="small"
                value={config.engine}
                onChange={(_, v) => v && updateConfig('engine', v)}
                disabled={trainingStatus?.is_training}
                sx={{
                  '& .MuiToggleButton-root': {
                    color: '#888', borderColor: '#333', fontFamily: 'Share Tech Mono', fontSize: '0.75rem',
                    '&.Mui-selected': { color: '#0a0a0a', bgcolor: '#00d4ff', '&:hover': { bgcolor: '#00bce6' } },
                  },
                  '& .MuiToggleButton-root[value="dl"].Mui-selected': { bgcolor: '#aa66ff', color: '#0a0a0a',
                    '&:hover': { bgcolor: '#9955ee' } },
                }}
              >
                <ToggleButton value="ml">ML (XGB+LGB)</ToggleButton>
                <ToggleButton value="dl">DL (Keras)</ToggleButton>
              </ToggleButtonGroup>
            </Box>
            <IconButton onClick={fetchData} sx={{ color: '#00d4ff' }}>
              <RefreshIcon />
            </IconButton>
          </Stack>
        </Box>

        {/* DL-specific notice — Stage 2 now includes Infiltration (notebook parity). */}
        {config.engine === 'dl' && (
          <Alert
            severity="info"
            sx={{ mb: 2, bgcolor: 'rgba(170,102,255,0.1)', border: '1px solid #aa66ff',
                  '& .MuiAlert-icon': { color: '#aa66ff' } }}
          >
            <Typography variant="body2">
              <strong>DL retraining:</strong> Stage&nbsp;2 is trained on all attack classes &mdash;
              <em> Infiltration is included</em> (matches the original training notebook).
              Memory-efficient <code>tf.data</code> pipelines + GPU memory growth + balanced class weights.
            </Typography>
          </Alert>
        )}

        {/* Important Notice */}
        <Alert 
          severity="info" 
          sx={{ 
            mb: 3, 
            bgcolor: 'rgba(33,150,243,0.1)',
            border: '1px solid #2196f3',
            '& .MuiAlert-icon': { color: '#2196f3' }
          }}
        >
          <Typography variant="body2">
            <strong>ℹ️ Note:</strong> Your original models were trained on the CICIDS2017/2018 dataset with 
            <strong> 98% (Stage 1)</strong> and <strong>95% (Stage 2)</strong> accuracy. 
            Retraining on captured traffic may produce different results depending on data quality.
            Use the backup/restore feature to switch between model versions.
          </Typography>
        </Alert>

        {/* Data Statistics */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={6} sm={4} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, rgba(0,255,65,0.12) 0%, rgba(0,255,65,0.04) 100%)', border: '1px solid rgba(0,255,65,0.4)' }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" sx={{ color: '#00d4ff', fontWeight: 'bold' }}>
                  {dataStats?.available_for_training?.toLocaleString() || 0}
                </Typography>
                <Typography variant="caption" sx={{ color: '#888' }}>Available Samples</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={4} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, rgba(244,67,54,0.12) 0%, rgba(244,67,54,0.04) 100%)', border: '1px solid rgba(244,67,54,0.4)' }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" sx={{ color: '#ff3b6b', fontWeight: 'bold' }}>
                  {dataStats?.available_attacks?.toLocaleString() || 0}
                </Typography>
                <Typography variant="caption" sx={{ color: '#888' }}>Attack Samples</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={4} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, rgba(76,175,80,0.12) 0%, rgba(76,175,80,0.04) 100%)', border: '1px solid rgba(76,175,80,0.4)' }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" sx={{ color: '#4d9d7e', fontWeight: 'bold' }}>
                  {dataStats?.available_normal?.toLocaleString() || 0}
                </Typography>
                <Typography variant="caption" sx={{ color: '#888' }}>Normal Samples</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={4} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, rgba(156,39,176,0.12) 0%, rgba(156,39,176,0.04) 100%)', border: '1px solid rgba(156,39,176,0.4)' }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" sx={{ color: '#9c27b0', fontWeight: 'bold' }}>
                  {dataStats?.used_for_training?.toLocaleString() || 0}
                </Typography>
                <Typography variant="caption" sx={{ color: '#888' }}>Already Used</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={6} sm={4} md={2.4}>
            <Card sx={{ background: 'linear-gradient(135deg, rgba(255,152,0,0.12) 0%, rgba(255,152,0,0.04) 100%)', border: '1px solid rgba(255,152,0,0.4)' }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" sx={{ color: '#ff9800', fontWeight: 'bold' }}>
                  {history.length}
                </Typography>
                <Typography variant="caption" sx={{ color: '#888' }}>Training Runs</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Data Quality Assessment */}
        <DataQualityIndicator dataStats={dataStats} />

        <Grid container spacing={3}>
          {/* Left Column - Configuration */}
          <Grid item xs={12} md={6}>
            {/* Training Status Panel — always visible */}
            <Paper sx={{ 
              p: 3, mb: 3, 
              background: trainingStatus.is_training 
                ? 'linear-gradient(135deg, #1a1a2e 0%, #0a2a1a 100%)' 
                : 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)',
              border: trainingStatus.is_training ? '2px solid #00d4ff' : '1px solid rgba(255,255,255,0.08)',
              transition: 'all 0.3s ease'
            }}>
              {trainingStatus.is_training ? (
                <>
                  <Typography variant="h6" sx={{ color: '#00d4ff', mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                    <CircularProgress size={20} sx={{ color: '#00d4ff' }} />
                    Training in Progress
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#fff', mb: 1 }}>
                    {trainingStatus.stage || 'Initialising...'}
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={trainingStatus.progress} 
                    sx={{ 
                      height: 10, 
                      borderRadius: 5,
                      bgcolor: '#333',
                      '& .MuiLinearProgress-bar': { bgcolor: '#00d4ff' }
                    }}
                  />
                  <Typography variant="caption" sx={{ color: '#888', mt: 1, display: 'block' }}>
                    {trainingStatus.progress}% complete
                  </Typography>
                  
                  {/* Training Log */}
                  <Box sx={{ mt: 2, maxHeight: 200, overflow: 'auto', bgcolor: '#000', p: 1, borderRadius: 1 }}>
                    {trainingStatus.log?.slice(-15).map((entry, i) => (
                      <Typography 
                        key={i} 
                        variant="caption" 
                        sx={{ 
                          color: entry.level === 'error' ? '#ff3b6b' : entry.level === 'warning' ? '#ff9800' : '#00d4ff',
                          fontFamily: 'monospace',
                          display: 'block',
                          fontSize: '0.7rem'
                        }}
                      >
                        [{entry.time}] {entry.message}
                      </Typography>
                    ))}
                  </Box>

                  {/* Cancel Button */}
                  <Box sx={{ mt: 2, textAlign: 'center' }}>
                    <Button
                      variant="contained"
                      size="large"
                      startIcon={<CancelIcon />}
                      onClick={cancelTraining}
                      sx={{
                        bgcolor: '#ff3b6b',
                        color: '#fff',
                        fontWeight: 'bold',
                        fontFamily: 'Share Tech Mono',
                        px: 5,
                        py: 1.2,
                        '&:hover': { bgcolor: '#d32f2f' }
                      }}
                    >
                      Cancel Training
                    </Button>
                  </Box>
                </>
              ) : (
                <Box sx={{ textAlign: 'center', py: 2 }}>
                  <Typography variant="h6" sx={{ color: '#888', mb: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 1 }}>
                    <MemoryIcon sx={{ color: '#555' }} />
                    Training Status
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#666' }}>
                    {trainingStatus.stage === 'cancelled' || trainingStatus.stage === 'cancelling'
                      ? '⛔ Last training was cancelled'
                      : trainingStatus.stage === 'error'
                        ? '❌ Last training failed — check logs'
                        : trainingStatus.stage === 'complete'
                          ? '✅ Last training completed successfully'
                          : 'Ready to train — configure settings below and press Start'}
                  </Typography>
                  {/* Show last log entries if any */}
                  {trainingStatus.log?.length > 0 && (
                    <Box sx={{ mt: 2, maxHeight: 120, overflow: 'auto', bgcolor: '#000', p: 1, borderRadius: 1, textAlign: 'left' }}>
                      {trainingStatus.log.slice(-8).map((entry, i) => (
                        <Typography 
                          key={i} 
                          variant="caption" 
                          sx={{ 
                            color: entry.level === 'error' ? '#ff3b6b' : entry.level === 'warning' ? '#ff9800' : '#00d4ff',
                            fontFamily: 'monospace',
                            display: 'block',
                            fontSize: '0.7rem'
                          }}
                        >
                          [{entry.time}] {entry.message}
                        </Typography>
                      ))}
                    </Box>
                  )}
                </Box>
              )}
            </Paper>

            {/* ───────── ML (XGBoost + LightGBM) hyperparameters ───────── */}
            {config.engine === 'ml' && (<>
            {/* XGBoost Settings */}
            <Accordion defaultExpanded sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)', mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#ff3b6b' }} />}>
                <SpeedIcon sx={{ color: '#ff3b6b', mr: 2 }} />
                <Typography sx={{ color: '#fff' }}>Stage 1: XGBoost (Binary Classification)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>N Estimators: {config.xgb_n_estimators}</Typography>
                    <Slider
                      value={config.xgb_n_estimators}
                      onChange={(e, v) => updateConfig('xgb_n_estimators', v)}
                      min={50} max={500} step={50}
                      valueLabelDisplay="auto"
                      sx={{ color: '#ff3b6b' }}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Max Depth: {config.xgb_max_depth}</Typography>
                    <Slider
                      value={config.xgb_max_depth}
                      onChange={(e, v) => updateConfig('xgb_max_depth', v)}
                      min={3} max={15} step={1}
                      valueLabelDisplay="auto"
                      sx={{ color: '#ff3b6b' }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Learning Rate: {config.xgb_learning_rate}</Typography>
                    <Slider
                      value={config.xgb_learning_rate}
                      onChange={(e, v) => updateConfig('xgb_learning_rate', v)}
                      min={0.01} max={0.3} step={0.01}
                      valueLabelDisplay="auto"
                      sx={{ color: '#ff3b6b' }}
                    />
                  </Grid>
                </Grid>
                <Alert severity="info" sx={{ mt: 2, bgcolor: 'rgba(33,150,243,0.05)', fontSize: '0.75rem' }}>
                  Original settings: n_estimators=200, max_depth=6, learning_rate=0.1, scale_pos_weight=auto
                </Alert>
              </AccordionDetails>
            </Accordion>

            {/* LightGBM Settings */}
            <Accordion sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)', mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#9c27b0' }} />}>
                <AnalyticsIcon sx={{ color: '#9c27b0', mr: 2 }} />
                <Typography sx={{ color: '#fff' }}>Stage 2: LightGBM (Multi-class Classification)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>N Estimators: {config.lgb_n_estimators}</Typography>
                    <Slider
                      value={config.lgb_n_estimators}
                      onChange={(e, v) => updateConfig('lgb_n_estimators', v)}
                      min={50} max={500} step={50}
                      valueLabelDisplay="auto"
                      sx={{ color: '#9c27b0' }}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Max Depth: {config.lgb_max_depth}</Typography>
                    <Slider
                      value={config.lgb_max_depth}
                      onChange={(e, v) => updateConfig('lgb_max_depth', v)}
                      min={3} max={15} step={1}
                      valueLabelDisplay="auto"
                      sx={{ color: '#9c27b0' }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Learning Rate: {config.lgb_learning_rate}</Typography>
                    <Slider
                      value={config.lgb_learning_rate}
                      onChange={(e, v) => updateConfig('lgb_learning_rate', v)}
                      min={0.01} max={0.3} step={0.01}
                      valueLabelDisplay="auto"
                      sx={{ color: '#9c27b0' }}
                    />
                  </Grid>
                </Grid>
                <Alert severity="info" sx={{ mt: 2, bgcolor: 'rgba(33,150,243,0.05)', fontSize: '0.75rem' }}>
                  Original settings: n_estimators=200, learning_rate=0.1, class_weight='balanced'
                </Alert>
              </AccordionDetails>
            </Accordion>
            </>)}

            {/* ───────── DL (Keras two-stage DNN) hyperparameters ───────── */}
            {config.engine === 'dl' && (<>
            {/* Stage 1: Binary DNN */}
            <Accordion defaultExpanded sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)', mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#aa66ff' }} />}>
                <SpeedIcon sx={{ color: '#aa66ff', mr: 2 }} />
                <Typography sx={{ color: '#fff' }}>Stage 1: Binary DNN (sigmoid)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="info" sx={{ bgcolor: 'rgba(170,102,255,0.06)', fontSize: '0.75rem' }}>
                  Architecture: Dense 256 → 128 → 64 → 32 → 1, BatchNorm + Dropout,
                  Adam optimizer, binary_crossentropy. EarlyStopping + ReduceLROnPlateau on.
                </Alert>
              </AccordionDetails>
            </Accordion>

            {/* Stage 2: Multi-class DNN */}
            <Accordion sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)', mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#9c27b0' }} />}>
                <AnalyticsIcon sx={{ color: '#9c27b0', mr: 2 }} />
                <Typography sx={{ color: '#fff' }}>Stage 2: Multi-class DNN (softmax, 14 classes)</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Alert severity="info" sx={{ bgcolor: 'rgba(156,39,176,0.06)', fontSize: '0.75rem' }}>
                  Architecture: Dense 512 → 256 → 128 → 64 → 32 → softmax, sparse_categorical_crossentropy,
                  balanced class weights. Infiltration IS included in Stage 2 (matches training notebook).
                </Alert>
              </AccordionDetails>
            </Accordion>

            {/* DL training hyperparameters (apply to both stages) */}
            <Accordion defaultExpanded sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)', mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#00d4ff' }} />}>
                <SettingsIcon sx={{ color: '#00d4ff', mr: 2 }} />
                <Typography sx={{ color: '#fff' }}>DL Training Hyperparameters</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Epochs: {config.dl_epochs}</Typography>
                    <Slider
                      value={config.dl_epochs}
                      onChange={(e, v) => updateConfig('dl_epochs', v)}
                      min={5} max={50} step={5}
                      valueLabelDisplay="auto"
                      sx={{ color: '#00d4ff' }}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Batch Size: {config.dl_batch_size}</Typography>
                    <Slider
                      value={config.dl_batch_size}
                      onChange={(e, v) => updateConfig('dl_batch_size', v)}
                      min={64} max={1024} step={64}
                      valueLabelDisplay="auto"
                      sx={{ color: '#00d4ff' }}
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Learning Rate: {config.dl_learning_rate}</Typography>
                    <Slider
                      value={config.dl_learning_rate}
                      onChange={(e, v) => updateConfig('dl_learning_rate', v)}
                      min={0.0001} max={0.01} step={0.0001}
                      valueLabelDisplay="auto"
                      sx={{ color: '#00d4ff' }}
                    />
                  </Grid>
                </Grid>
                <Alert severity="info" sx={{ mt: 2, bgcolor: 'rgba(33,150,243,0.05)', fontSize: '0.75rem' }}>
                  Original settings: epochs=15, batch_size=512, learning_rate=0.001 (Adam)
                </Alert>
              </AccordionDetails>
            </Accordion>
            </>)}

            {/* Dataset Limits & Training Options */}
            <Accordion sx={{ background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)', mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#ff9800' }} />}>
                <SettingsIcon sx={{ color: '#ff9800', mr: 2 }} />
                <Typography sx={{ color: '#fff' }}>Dataset Limits & Training Options</Typography>
              </AccordionSummary>
              <AccordionDetails>
                {/* Dataset Limit Controls */}
                <Typography variant="subtitle2" sx={{ color: '#ff9800', mb: 1.5, fontFamily: 'Share Tech Mono' }}>
                  📊 Dataset Limits
                </Typography>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>
                      Max Samples: {config.max_samples > 0 ? config.max_samples.toLocaleString() : 'No Limit'}
                    </Typography>
                    <TextField
                      type="number"
                      value={config.max_samples || ''}
                      onChange={(e) => updateConfig('max_samples', parseInt(e.target.value) || 0)}
                      placeholder="0 = no limit"
                      size="small"
                      fullWidth
                      sx={{ 
                        mt: 1,
                        '& .MuiOutlinedInput-root': { color: '#fff' },
                        '& .MuiOutlinedInput-notchedOutline': { borderColor: '#444' }
                      }}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>
                      Use {config.max_percentage}% of Available Data
                    </Typography>
                    <Slider
                      value={config.max_percentage}
                      onChange={(e, v) => updateConfig('max_percentage', v)}
                      min={10} max={100} step={5}
                      valueLabelDisplay="auto"
                      valueLabelFormat={(v) => `${v}%`}
                      sx={{ color: '#ff9800' }}
                    />
                  </Grid>
                </Grid>

                {/* Balanced Preview */}
                {dataStats?.balanced_preview && (
                  <Alert severity="info" sx={{ mb: 2, bgcolor: 'rgba(33,150,243,0.05)', fontSize: '0.75rem' }}>
                    <Typography variant="body2" sx={{ fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>
                      <strong>⚖️ 1/3 Attack Balancing Rule Active</strong><br/>
                      Estimated: {(() => {
                        const bp = dataStats.balanced_preview;
                        let attacks = bp.attacks;
                        let normal = bp.normal;
                        if (config.max_percentage < 100) {
                          attacks = Math.max(10, Math.floor(attacks * config.max_percentage / 100));
                          normal = Math.min(bp.normal, attacks * 2);
                        }
                        if (config.max_samples > 0 && (attacks + normal) > config.max_samples) {
                          const capAttacks = Math.floor(config.max_samples / 3);
                          attacks = Math.min(attacks, capAttacks);
                          normal = Math.min(normal, config.max_samples - attacks);
                        }
                        const total = attacks + normal;
                        return `${attacks.toLocaleString()} attacks + ${normal.toLocaleString()} normal = ${total.toLocaleString()} total (${total > 0 ? (attacks/total*100).toFixed(1) : 0}% attacks)`;
                      })()}
                    </Typography>
                  </Alert>
                )}

                {/* Train/Test Split */}
                <Typography variant="subtitle2" sx={{ color: '#ff9800', mb: 1.5, fontFamily: 'Share Tech Mono' }}>
                  ⚙️ Train/Test Split
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Test Split: {(config.test_size * 100).toFixed(0)}%</Typography>
                    <Slider
                      value={config.test_size}
                      onChange={(e, v) => updateConfig('test_size', v)}
                      min={0.1} max={0.4} step={0.05}
                      valueLabelDisplay="auto"
                      valueLabelFormat={(v) => `${(v * 100).toFixed(0)}%`}
                      sx={{ color: '#ff9800' }}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="caption" sx={{ color: '#888' }}>Min Samples</Typography>
                    <TextField
                      type="number"
                      value={config.min_samples}
                      onChange={(e) => updateConfig('min_samples', parseInt(e.target.value) || 100)}
                      size="small"
                      fullWidth
                      sx={{ 
                        mt: 1,
                        '& .MuiOutlinedInput-root': { color: '#fff' },
                        '& .MuiOutlinedInput-notchedOutline': { borderColor: '#444' }
                      }}
                    />
                  </Grid>
                </Grid>

                <Alert severity="info" sx={{ mt: 2, bgcolor: 'rgba(33,150,243,0.05)', fontSize: '0.75rem' }}>
                  ℹ️ Trained data is automatically marked as used and won't be selected again in future runs. Use "Reset Flags" to make all data available again.
                </Alert>
              </AccordionDetails>
            </Accordion>

            {/* Action Buttons */}
            <Box sx={{ display: 'flex', gap: 2, mt: 3, flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                size="large"
                startIcon={trainingStatus.is_training ? <CircularProgress size={20} sx={{ color: '#000' }} /> : <PlayIcon />}
                onClick={startTraining}
                disabled={trainingStatus.is_training || (dataStats?.available_for_training || 0) < config.min_samples}
                sx={{
                  bgcolor: quality.score >= 70 ? '#00d4ff' : '#ff9800',
                  color: '#000',
                  flex: 1,
                  py: 1.5,
                  fontWeight: 'bold',
                  fontFamily: 'Share Tech Mono',
                  '&:hover': { bgcolor: quality.score >= 70 ? '#00a8cc' : '#f57c00' },
                  '&:disabled': { bgcolor: '#333', color: '#666' }
                }}
              >
                {trainingStatus.is_training ? 'Training...' : quality.score >= 70 ? 'Start Training' : 'Train (Low Quality Data)'}
              </Button>
              <Button
                variant="outlined"
                onClick={resetFlags}
                disabled={trainingStatus.is_training}
                sx={{ 
                  borderColor: '#ff9800', 
                  color: '#ff9800',
                  fontFamily: 'Share Tech Mono',
                  '&:hover': { borderColor: '#ff9800', bgcolor: 'rgba(255,152,0,0.1)' }
                }}
              >
                Reset Flags
              </Button>
            </Box>

            {(dataStats?.available_for_training || 0) < config.min_samples && (
              <Alert severity="error" sx={{ mt: 2, bgcolor: 'rgba(244,67,54,0.1)' }}>
                Need at least {config.min_samples} samples. Available: {dataStats?.available_for_training || 0}
              </Alert>
            )}
          </Grid>

          {/* Right Column - History & Backups */}
          <Grid item xs={12} md={6}>
            {/* Training History */}
            <Paper sx={{ p: 3, mb: 3, background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)' }}>
              <Typography variant="h6" sx={{ color: '#00d4ff', mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <HistoryIcon /> Training History
              </Typography>
              
              {history.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 3 }}>
                  <Typography sx={{ color: '#888' }}>No training history yet</Typography>
                  <Typography variant="caption" sx={{ color: '#666' }}>
                    Original models trained on CICIDS dataset
                  </Typography>
                </Box>
              ) : (
                <TableContainer sx={{ maxHeight: 250 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }}>Date</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }}>Samples</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }}>S1 F1</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }}>S2 F1</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }}>Time</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {history.slice(-10).reverse().map((entry, i) => (
                        <TableRow key={i} sx={{ '&:hover': { bgcolor: 'rgba(0,255,65,0.05)' } }}>
                          <TableCell sx={{ color: '#fff', fontSize: '0.7rem' }}>
                            {new Date(entry.timestamp).toLocaleDateString()}
                          </TableCell>
                          <TableCell sx={{ color: '#fff', fontSize: '0.75rem' }}>{entry.samples?.toLocaleString()}</TableCell>
                          <TableCell sx={{ color: '#ff3b6b', fontWeight: 'bold', fontSize: '0.75rem' }}>
                            {entry.stage1_metrics?.f1_score?.toFixed(3) || 'N/A'}
                          </TableCell>
                          <TableCell sx={{ color: '#9c27b0', fontWeight: 'bold', fontSize: '0.75rem' }}>
                            {entry.stage2_metrics?.f1_score?.toFixed(3) || (entry.stage2_metrics?.skipped ? 'Skipped' : 'N/A')}
                          </TableCell>
                          <TableCell sx={{ color: '#888', fontSize: '0.7rem' }}>
                            {entry.duration_seconds?.toFixed(0)}s
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Paper>

            {/* Model Backups */}
            <Paper sx={{ p: 3, background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)', border: '1px solid rgba(255,255,255,0.08)' }}>
              <Typography variant="h6" sx={{ color: '#00d4ff', mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <BackupIcon /> Model Backups
              </Typography>
              
              <Alert severity="info" sx={{ mb: 2, bgcolor: 'rgba(33,150,243,0.05)', fontSize: '0.75rem' }}>
                💡 <strong>Tip:</strong> Restore a backup to switch to previously trained models. 
                Your original CICIDS-trained models can be restored if backed up.
              </Alert>
              
              {backups.length === 0 ? (
                <Typography sx={{ color: '#888', textAlign: 'center', py: 2 }}>
                  No backups available yet
                </Typography>
              ) : (
                <Box sx={{ maxHeight: 250, overflow: 'auto' }}>
                  {backups.slice(0, 10).map((backup, i) => (
                    <Box 
                      key={i}
                      sx={{ 
                        display: 'flex', 
                        justifyContent: 'space-between', 
                        alignItems: 'center',
                        p: 1.5,
                        mb: 1,
                        bgcolor: 'rgba(255,255,255,0.03)',
                        borderRadius: 1,
                        border: '1px solid #333',
                        transition: 'all 0.2s',
                        '&:hover': { border: '1px solid #00d4ff', bgcolor: 'rgba(0,255,65,0.05)' }
                      }}
                    >
                      <Box>
                        <Typography variant="body2" sx={{ color: '#fff', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                          📁 {backup.name}
                        </Typography>
                        <Typography variant="caption" sx={{ color: '#888' }}>
                          {backup.file_count || backup.files?.length || 0} files
                        </Typography>
                      </Box>
                      <Tooltip title="Restore this backup">
                        <IconButton 
                          onClick={() => restoreBackup(backup.name)}
                          disabled={trainingStatus.is_training}
                          sx={{ 
                            color: '#00d4ff',
                            '&:hover': { bgcolor: 'rgba(0,255,65,0.1)' }
                          }}
                        >
                          <RestoreIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  ))}
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
};

export default ModelRetraining;
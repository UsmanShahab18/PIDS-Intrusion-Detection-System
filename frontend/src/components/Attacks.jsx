import React, { useState, useEffect } from 'react';
import {
  Box, Container, Typography, Paper, Grid, Chip, Accordion, AccordionSummary,
  AccordionDetails, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, LinearProgress, Card, CardContent, Tooltip, IconButton, Badge
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  NetworkCheck as NetworkIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingIcon,
  Shield as ShieldIcon
} from '@mui/icons-material';
import axios from 'axios';
import '../App.css';

import { API_BASE } from '../config';

// Threat categories with detailed information
const THREAT_CATEGORIES = {
  'DoS/DDoS': {
    icon: '🌊',
    color: '#ff3b6b',
    description: 'Denial of Service attacks overwhelm systems with traffic to make them unavailable.',
    attacks: [
      { name: 'DDoS attack-HOIC', severity: 'Critical', description: 'High Orbit Ion Cannon - HTTP flood attack tool', mitigation: 'Rate limiting, CDN protection, traffic filtering' },
      { name: 'DDoS attack-LOIC-UDP', severity: 'Critical', description: 'Low Orbit Ion Cannon - UDP flood attack', mitigation: 'UDP traffic filtering, blackholing' },
      { name: 'DoS attacks-Hulk', severity: 'High', description: 'HTTP Unbearable Load King - Generates unique requests', mitigation: 'Web Application Firewall, request validation' },
      { name: 'DoS attacks-GoldenEye', severity: 'High', description: 'HTTP DoS using keep-alive connections', mitigation: 'Connection limits, timeout configuration' },
      { name: 'DoS attacks-Slowloris', severity: 'Medium', description: 'Slow HTTP headers to exhaust connections', mitigation: 'Minimum data rate requirements, timeouts' },
      { name: 'DoS attacks-SlowHTTPTest', severity: 'Medium', description: 'Application layer DoS testing tool', mitigation: 'Request rate limiting, WAF rules' },
    ]
  },
  'Brute Force': {
    icon: '🔓',
    color: '#ff9800',
    description: 'Automated attempts to guess passwords or encryption keys through trial and error.',
    attacks: [
      { name: 'SSH-Bruteforce', severity: 'High', description: 'Automated SSH login attempts', mitigation: 'Fail2ban, key-based auth, port change' },
      { name: 'FTP-BruteForce', severity: 'High', description: 'FTP credential guessing attacks', mitigation: 'Account lockout, SFTP migration' },
      { name: 'RDP-Bruteforce', severity: 'Critical', description: 'Remote Desktop brute force attacks', mitigation: 'NLA, account lockout, VPN requirement' },
    ]
  },
  'Web Attacks': {
    icon: '🌐',
    color: '#9c27b0',
    description: 'Attacks targeting web applications and services.',
    attacks: [
      { name: 'SQL Injection', severity: 'Critical', description: 'Malicious SQL code injection into queries', mitigation: 'Parameterized queries, input validation' },
      { name: 'XSS', severity: 'High', description: 'Cross-Site Scripting - malicious script injection', mitigation: 'Output encoding, CSP headers' },
      { name: 'Web Attack-Brute Force', severity: 'Medium', description: 'Web login brute force attempts', mitigation: 'CAPTCHA, rate limiting, MFA' },
    ]
  },
  'Botnet/C2': {
    icon: '🤖',
    color: '#2196f3',
    description: 'Compromised systems communicating with command and control servers.',
    attacks: [
      { name: 'Bot', severity: 'Critical', description: 'Botnet client activity detected', mitigation: 'Network segmentation, endpoint protection' },
      { name: 'IRC Botnet C2', severity: 'Critical', description: 'IRC-based botnet command channel', mitigation: 'Block IRC ports, network monitoring' },
      { name: 'Botnet C2 Communication', severity: 'Critical', description: 'C2 beacon traffic detected', mitigation: 'DNS filtering, traffic analysis' },
    ]
  },
  'Infiltration': {
    icon: '🕵️',
    color: '#ff5722',
    description: 'Unauthorized access and data exfiltration attempts.',
    attacks: [
      { name: 'Infilteration', severity: 'Critical', description: 'Network infiltration detected', mitigation: 'Network segmentation, IDS/IPS' },
      { name: 'Data Exfiltration', severity: 'Critical', description: 'Unauthorized data transfer out', mitigation: 'DLP, egress filtering' },
      { name: 'Heartbleed', severity: 'Critical', description: 'OpenSSL memory leak exploitation', mitigation: 'Patch OpenSSL, certificate rotation' },
    ]
  },
  'LLM-Detected Threats': {
    icon: '🔮',
    color: '#9c27b0',
    description: 'Advanced threats detected by LLM threat intelligence analysis.',
    attacks: [
      { name: 'Metasploit Reverse Shell', severity: 'Critical', description: 'Metasploit framework backdoor on port 4444', mitigation: 'Block port 4444, endpoint detection' },
      { name: 'Tor Hidden Service', severity: 'High', description: 'Tor anonymization network traffic', mitigation: 'Block Tor exit nodes, DPI' },
      { name: 'SMB EternalBlue', severity: 'Critical', description: 'MS17-010 SMB vulnerability exploit', mitigation: 'Patch systems, block SMB externally' },
      { name: 'Android Debug Exploit', severity: 'High', description: 'Exposed ADB on port 5555', mitigation: 'Disable ADB, network segmentation' },
      { name: 'Docker API Exploit', severity: 'Critical', description: 'Exposed Docker API on port 2375', mitigation: 'Enable TLS, restrict access' },
      { name: 'Redis RCE Attack', severity: 'Critical', description: 'Unauthorized Redis access', mitigation: 'Authentication, bind to localhost' },
    ]
  }
};

const Attacks = () => {
  const [stats, setStats] = useState({
    total_attacks: 0,
    attack_types: {},
    llm_detected: 0,
    recent_attacks: []
  });
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [timeFilter, setTimeFilter] = useState('today');
  const [dynamicThreats, setDynamicThreats] = useState([]);

  // Fetch attack statistics
  const fetchStats = async () => {
    try {
      const period = timeFilter === 'all' ? '' : timeFilter;
      const periodParam = period ? `&period=${period}` : '';
      const periodParamFirst = period ? `?period=${period}` : '';
      
      // Get totals from backend with time filter
      const statsRes = await axios.get(`${API_BASE}/stats/${periodParamFirst}`);
      
      // Get attack type distribution from backend with time filter
      let attackTypes = {};
      try {
        const typesRes = await axios.get(`${API_BASE}/stats/attack-types/${periodParamFirst}`);
        const typesData = typesRes.data;
        if (Array.isArray(typesData)) {
          typesData.forEach(t => {
            attackTypes[t.prediction || t.attack_type || 'Unknown'] = t.count;
          });
        } else if (typesData.attack_types) {
          typesData.attack_types.forEach(t => {
            attackTypes[t.attack_type || t.prediction || 'Unknown'] = t.count;
          });
        }
      } catch (e) {
        console.log('attack-types endpoint not available');
      }

      // Get recent attacks for the table + LLM threat discovery
      let recentAttacks = [];
      let llmNewThreats = [];
      
      try {
        const attacksRes = await axios.get(`${API_BASE}/traffic/?status=Attack&limit=500${periodParam}`);
        const allAttacks = attacksRes.data.results || attacksRes.data || [];
        
        // If attack-types endpoint didn't work, count from traffic data
        if (Object.keys(attackTypes).length === 0) {
          allAttacks.forEach(attack => {
            const type = attack.prediction || attack.attack_type || 'Unknown';
            attackTypes[type] = (attackTypes[type] || 0) + 1;
          });
        }
        
        // Find LLM-detected NEW attack types
        const mlKnownTypes = [
          'Bot', 'Brute Force -Web', 'Brute Force -XSS', 'DDOS attack-HOIC',
          'DDOS attack-LOIC-UDP', 'DDoS attacks-LOIC-HTTP', 'DoS attacks-GoldenEye',
          'DoS attacks-Hulk', 'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris',
          'FTP-BruteForce', 'Infilteration', 'SQL Injection', 'SSH-Bruteforce', 'Normal'
        ];
        const llmTypes = {};
        allAttacks.forEach(attack => {
          const pred = attack.prediction || '';
          if (pred.startsWith('LLM-Detected:')) {
            const type = pred.replace('LLM-Detected: ', '').trim();
            if (!llmTypes[type]) {
              llmTypes[type] = { name: type, count: 0, first_seen: attack.timestamp, severity: 'High' };
            }
            llmTypes[type].count += 1;
          }
        });
        allAttacks.forEach(attack => {
          const pred = attack.prediction || attack.attack_type || '';
          if (!pred.startsWith('LLM-Detected:') && pred !== 'Normal') {
            const isML = mlKnownTypes.some(ml => pred.toLowerCase().includes(ml.toLowerCase()));
            if (!isML && !llmTypes[pred]) {
              llmTypes[pred] = { name: pred, count: 0, first_seen: attack.timestamp, severity: 'High' };
            }
            if (llmTypes[pred]) llmTypes[pred].count += 1;
          }
        });
        
        llmNewThreats = Object.values(llmTypes).sort((a, b) => b.count - a.count);
        recentAttacks = allAttacks.slice(0, 10);
      } catch (e) {
        console.log('Could not fetch attack details');
      }

      setStats({
        total_attacks: statsRes.data.attacks || 0,
        llm_detected: statsRes.data.llm_attacks || 0,
        zero_day: statsRes.data.zero_day || 0,
        attack_types: attackTypes,
        recent_attacks: recentAttacks
      });
      setDynamicThreats(llmNewThreats);
      setLastUpdate(new Date());
      setLoading(false);
    } catch (error) {
      console.error('Error fetching stats:', error);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 10000);
    return () => clearInterval(interval);
  }, [timeFilter]);

  const handleAccordionChange = (panel) => (event, isExpanded) => {
    setExpanded(isExpanded ? panel : false);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return '#d32f2f';
      case 'High': return '#ff3b6b';
      case 'Medium': return '#ff9800';
      case 'Low': return '#4d9d7e';
      default: return '#888';
    }
  };

  // mode 'ml'  → count only known/ML attack types (exclude LLM-Detected zero-days)
  // mode 'llm' → count only LLM-Detected (zero-day) types
  // Sums ALL matching keys (not just the first) so counts are accurate.
  const getAttackCount = (attackName, mode = 'ml') => {
    const a = attackName.toLowerCase();
    let total = 0;
    for (const [key, count] of Object.entries(stats.attack_types)) {
      const isLLM = key.startsWith('LLM-Detected:');
      if (mode === 'ml' && isLLM) continue;     // zero-days belong to the LLM section only
      if (mode === 'llm' && !isLLM) continue;
      const k = key.replace('LLM-Detected:', '').trim().toLowerCase();
      if (k.includes(a) || a.includes(k)) total += count;
    }
    return total;
  };

  const getCategoryCount = (category) => {
    const mode = category === 'LLM-Detected Threats' ? 'llm' : 'ml';
    const attacks = THREAT_CATEGORIES[category]?.attacks || [];
    let total = 0;
    attacks.forEach(attack => {
      total += getAttackCount(attack.name, mode);
    });
    return total;
  };

  return (
    <div className="hacker-bg" style={{ minHeight: '100vh' }}>
      <Container maxWidth="xl" sx={{ pt: 10, pb: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h3" className="hacker-text" sx={{ fontFamily: 'Share Tech Mono' }}>
              THREAT DATABASE
            </Typography>
            <Typography variant="body1" sx={{ color: '#888', mt: 1 }}>
              Real-time threat intelligence and attack vector analysis
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {/* Time filter */}
            <Box sx={{ display: 'flex', gap: 0.5 }}>
              {[['today','Today'],['7d','7 Days'],['30d','30 Days'],['all','All Time']].map(([val, label]) => (
                <Chip key={val} label={label} size="small"
                  onClick={() => setTimeFilter(val)}
                  sx={{ cursor: 'pointer', fontFamily: 'Share Tech Mono', fontSize: '0.7rem',
                    bgcolor: timeFilter === val ? '#ff3b6b' : 'transparent',
                    color: timeFilter === val ? '#fff' : '#888',
                    borderColor: '#333', border: '1px solid',
                    '&:hover': { bgcolor: timeFilter === val ? '#d32f2f' : 'rgba(244,67,54,0.1)' } }} />
              ))}
            </Box>
            <Chip 
              label={`Last updated: ${lastUpdate.toLocaleTimeString()}`}
              size="small"
              sx={{ bgcolor: 'rgba(0,255,65,0.1)', color: '#00d4ff' }}
            />
            <IconButton onClick={fetchStats} sx={{ color: '#00d4ff' }}>
              <RefreshIcon />
            </IconButton>
          </Box>
        </Box>

        {loading && <LinearProgress sx={{ mb: 2, bgcolor: '#333', '& .MuiLinearProgress-bar': { bgcolor: '#00d4ff' } }} />}

        {/* Live Stats Cards */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={6} sm={3}>
            <Card sx={{ bgcolor: 'rgba(244,67,54,0.1)', border: '2px solid #ff3b6b' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Typography variant="h4" sx={{ color: '#ff3b6b', fontWeight: 'bold' }}>
                      {stats.total_attacks.toLocaleString()}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#888' }}>Total Attacks</Typography>
                  </Box>
                  <WarningIcon sx={{ color: '#ff3b6b', fontSize: 40, opacity: 0.5 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <Card sx={{ bgcolor: 'rgba(156,39,176,0.1)', border: '2px solid #9c27b0' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Typography variant="h4" sx={{ color: '#9c27b0', fontWeight: 'bold' }}>
                      {stats.llm_detected.toLocaleString()}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#888' }}>🔮 LLM Detected</Typography>
                  </Box>
                  <SecurityIcon sx={{ color: '#9c27b0', fontSize: 40, opacity: 0.5 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <Card sx={{ bgcolor: 'rgba(255,152,0,0.1)', border: '2px solid #ff9800' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Typography variant="h4" sx={{ color: '#ff9800', fontWeight: 'bold' }}>
                      {Object.keys(stats.attack_types).length}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#888' }}>Attack Types</Typography>
                  </Box>
                  <BugIcon sx={{ color: '#ff9800', fontSize: 40, opacity: 0.5 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={6} sm={3}>
            <Card sx={{ bgcolor: 'rgba(0,255,65,0.1)', border: '2px solid #00d4ff' }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Typography variant="h4" sx={{ color: '#00d4ff', fontWeight: 'bold' }}>
                      {Object.keys(THREAT_CATEGORIES).length}
                    </Typography>
                    <Typography variant="body2" sx={{ color: '#888' }}>Categories</Typography>
                  </Box>
                  <ShieldIcon sx={{ color: '#00d4ff', fontSize: 40, opacity: 0.5 }} />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Attack Type Distribution */}
        {Object.keys(stats.attack_types).length > 0 && (
          <Paper sx={{ p: 3, mb: 4, bgcolor: 'rgba(0,0,0,0.6)', border: '1px solid #333' }}>
            <Typography variant="h6" sx={{ color: '#00d4ff', mb: 2, fontFamily: 'Share Tech Mono' }}>
              📊 DETECTED ATTACK DISTRIBUTION
            </Typography>
            <Grid container spacing={2}>
              {Object.entries(stats.attack_types)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 12)
                .map(([type, count]) => (
                  <Grid item xs={6} sm={4} md={3} lg={2} key={type}>
                    <Paper sx={{ p: 2, bgcolor: 'rgba(244,67,54,0.1)', border: '1px solid #ff3b6b', textAlign: 'center' }}>
                      <Typography variant="h5" sx={{ color: '#ff3b6b', fontWeight: 'bold' }}>
                        {count}
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#fff', fontSize: '0.7rem', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {type}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
            </Grid>
          </Paper>
        )}

        {/* Recent Attacks */}
        {stats.recent_attacks.length > 0 && (
          <Paper sx={{ p: 3, mb: 4, bgcolor: 'rgba(0,0,0,0.6)', border: '1px solid #ff3b6b' }}>
            <Typography variant="h6" sx={{ color: '#ff3b6b', mb: 2, fontFamily: 'Share Tech Mono' }}>
              🚨 RECENT ATTACKS (Live)
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold' }}>Time</TableCell>
                    <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold' }}>Source IP</TableCell>
                    <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold' }}>Target</TableCell>
                    <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold' }}>Attack Type</TableCell>
                    <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold' }}>Confidence</TableCell>
                    <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold' }}>Detection</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {stats.recent_attacks.map((attack, index) => (
                    <TableRow key={index} sx={{ '&:hover': { bgcolor: 'rgba(244,67,54,0.1)' } }}>
                      <TableCell sx={{ color: '#888', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                        {new Date(attack.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <Chip label={attack.src_ip} size="small" variant="outlined" sx={{ color: '#fff', borderColor: '#444', fontFamily: 'monospace' }} />
                      </TableCell>
                      <TableCell sx={{ color: '#fff', fontFamily: 'monospace' }}>
                        {attack.dst_ip}:{attack.dst_port}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ color: '#ff3b6b' }}>
                          {attack.prediction || attack.attack_type}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress 
                            variant="determinate" 
                            value={(attack.confidence || 0) * 100}
                            sx={{ width: 50, height: 6, borderRadius: 3, bgcolor: '#333', '& .MuiLinearProgress-bar': { bgcolor: '#ff3b6b' } }}
                          />
                          <Typography variant="caption" sx={{ color: '#fff' }}>
                            {((attack.confidence || 0) * 100).toFixed(0)}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={attack.llm_analyzed ? '🔮 LLM' : '🤖 ML'}
                          size="small"
                          sx={{ 
                            bgcolor: attack.llm_analyzed ? '#9c27b0' : '#1976d2',
                            color: '#fff',
                            fontSize: '0.7rem'
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        )}

        {/* Threat Categories */}
        <Typography variant="h5" sx={{ color: '#00d4ff', mb: 3, fontFamily: 'Share Tech Mono' }}>
          📚 THREAT ENCYCLOPEDIA
        </Typography>

        {Object.entries(THREAT_CATEGORIES).map(([category, data]) => {
          const categoryCount = getCategoryCount(category);
          
          return (
            <Accordion 
              key={category}
              expanded={expanded === category}
              onChange={handleAccordionChange(category)}
              sx={{ 
                bgcolor: 'rgba(0,0,0,0.8)', 
                border: `1px solid ${data.color}`,
                mb: 2,
                '&:before': { display: 'none' }
              }}
            >
              <AccordionSummary
                expandIcon={<ExpandMoreIcon sx={{ color: data.color }} />}
                sx={{ '&:hover': { bgcolor: 'rgba(255,255,255,0.05)' } }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                  <Typography variant="h5">{data.icon}</Typography>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" sx={{ color: data.color, fontFamily: 'Share Tech Mono' }}>
                      {category}
                    </Typography>
                    <Typography variant="caption" sx={{ color: '#888' }}>
                      {data.description}
                    </Typography>
                  </Box>
                  {categoryCount > 0 && (
                    <Badge badgeContent={categoryCount} color="error" max={9999}>
                      <Chip 
                        label="DETECTED" 
                        size="small" 
                        sx={{ bgcolor: data.color, color: '#fff', fontWeight: 'bold' }}
                      />
                    </Badge>
                  )}
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ bgcolor: 'rgba(0,0,0,0.4)' }}>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold', width: '20%' }}>Attack Name</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold', width: '10%' }}>Severity</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold', width: '10%' }}>Detected</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold', width: '30%' }}>Description</TableCell>
                        <TableCell sx={{ color: '#00d4ff', fontWeight: 'bold', width: '30%' }}>Mitigation</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {data.attacks.map((attack, index) => {
                        const count = getAttackCount(attack.name, category === 'LLM-Detected Threats' ? 'llm' : 'ml');
                        return (
                          <TableRow 
                            key={index}
                            sx={{ 
                              bgcolor: count > 0 ? 'rgba(244,67,54,0.1)' : 'transparent',
                              '&:hover': { bgcolor: 'rgba(255,255,255,0.05)' }
                            }}
                          >
                            <TableCell>
                              <Typography variant="body2" sx={{ color: '#fff', fontWeight: count > 0 ? 'bold' : 'normal' }}>
                                {attack.name}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip 
                                label={attack.severity}
                                size="small"
                                sx={{ 
                                  bgcolor: getSeverityColor(attack.severity),
                                  color: '#fff',
                                  fontWeight: 'bold',
                                  fontSize: '0.7rem'
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              {count > 0 ? (
                                <Chip 
                                  label={count}
                                  size="small"
                                  sx={{ bgcolor: '#ff3b6b', color: '#fff', fontWeight: 'bold' }}
                                />
                              ) : (
                                <Typography variant="body2" sx={{ color: '#4d9d7e' }}>—</Typography>
                              )}
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ color: '#888', fontSize: '0.8rem' }}>
                                {attack.description}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ color: '#4d9d7e', fontSize: '0.8rem' }}>
                                {attack.mitigation}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </TableContainer>
              </AccordionDetails>
            </Accordion>
          );
        })}

        {/* Dynamic LLM-Discovered Threats */}
        {dynamicThreats.length > 0 && (
          <Paper sx={{ p: 3, mt: 3, mb: 3, bgcolor: 'rgba(0,0,0,0.6)', border: '2px solid #9c27b0' }}>
            <Typography variant="h6" sx={{ color: '#9c27b0', mb: 2, fontFamily: 'Share Tech Mono' }}>
              🔮 LLM-DISCOVERED THREATS (Auto-Detected)
            </Typography>
            <Typography variant="body2" sx={{ color: '#888', mb: 2 }}>
              New attack types discovered by the LLM that were not in the ML training data. These are automatically added when detected.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: '#9c27b0', fontWeight: 'bold' }}>Attack Type</TableCell>
                    <TableCell sx={{ color: '#9c27b0', fontWeight: 'bold' }}>Times Detected</TableCell>
                    <TableCell sx={{ color: '#9c27b0', fontWeight: 'bold' }}>First Seen</TableCell>
                    <TableCell sx={{ color: '#9c27b0', fontWeight: 'bold' }}>Detection Method</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dynamicThreats.map((threat, i) => (
                    <TableRow key={i} sx={{ bgcolor: 'rgba(156,39,176,0.08)', '&:hover': { bgcolor: 'rgba(156,39,176,0.15)' } }}>
                      <TableCell>
                        <Typography variant="body2" sx={{ color: '#fff', fontWeight: 'bold' }}>
                          🔮 {threat.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={threat.count} size="small"
                          sx={{ bgcolor: '#9c27b0', color: '#fff', fontWeight: 'bold' }} />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ color: '#888', fontSize: '0.8rem' }}>
                          {new Date(threat.first_seen).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label="LLM + Behaviour Analysis" size="small"
                          sx={{ bgcolor: 'rgba(156,39,176,0.2)', color: '#9c27b0', border: '1px solid #9c27b0', fontSize: '0.7rem' }} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        )}

        {/* Footer Info */}
        <Paper sx={{ p: 3, mt: 4, bgcolor: 'rgba(0,0,0,0.6)', border: '1px solid #333' }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="h6" sx={{ color: '#00d4ff', mb: 1 }}>🤖 ML Detection</Typography>
              <Typography variant="body2" sx={{ color: '#888' }}>
                XGBoost and LightGBM models trained on CICIDS2017/2018 datasets for known attack pattern recognition.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="h6" sx={{ color: '#9c27b0', mb: 1 }}>🔮 LLM Analysis</Typography>
              <Typography variant="body2" sx={{ color: '#888' }}>
                Ollama LLM with DuckDuckGo threat intelligence for advanced threat detection and zero-day identification.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="h6" sx={{ color: '#ff9800', mb: 1 }}>🛡️ Protection</Typography>
              <Typography variant="body2" sx={{ color: '#888' }}>
                Real-time monitoring with automatic threat classification. Review mitigation strategies for detected attacks.
              </Typography>
            </Grid>
          </Grid>
        </Paper>
      </Container>
    </div>
  );
};

export default Attacks;
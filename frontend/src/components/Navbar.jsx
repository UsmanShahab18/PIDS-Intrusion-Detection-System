import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate, Link } from 'react-router-dom';
import {
  AppBar, Toolbar, Typography, Button, Box, IconButton,
  Drawer, List, ListItem, ListItemIcon, ListItemText,
  useMediaQuery, Badge, Tooltip, Popover, Divider, Chip,
  Menu, MenuItem, Avatar
} from '@mui/material';
import {
  Home as HomeIcon, Dashboard as DashboardIcon,
  TableChart as TableIcon, Security as SecurityIcon,
  AccountTree as ArchitectureIcon,
  Notifications as NotificationIcon, Menu as MenuIcon,
  Memory as MemoryIcon, BugReport as DiagnosticsIcon,
  Warning as WarningIcon, CheckCircle as CheckIcon,
  OpenInNew as OpenIcon, Person as PersonIcon,
  Logout as LogoutIcon, Settings as SettingsIcon,
  School as SchoolIcon, Analytics as AnalyticsIcon,
  Search as ZeroDayIcon
} from '@mui/icons-material';
import axios from 'axios';
import { API_BASE } from '../config';
import { useAuth } from '../context/AuthContext';
import '../App.css';

import { PRESET_AVATARS } from './ProfileSettings';

function getNavAvatarSrc(user) {
  if (!user) return null;
  // Read from DB-backed user object (not localStorage)
  if (user.avatar_type === 'custom' && user.avatar_data) return user.avatar_data;
  if (user.avatar_type === 'preset' && user.avatar_data) {
    const preset = PRESET_AVATARS.find(a => a.id === user.avatar_data);
    if (preset) return `data:image/svg+xml,${encodeURIComponent(preset.svg)}`;
  }
  // Fallback: check old localStorage (migration support)
  const custom = localStorage.getItem('pids_custom_avatar');
  if (custom) return custom;
  const presetId = localStorage.getItem('pids_avatar');
  if (presetId) {
    const preset = PRESET_AVATARS.find(a => a.id === presetId);
    if (preset) return `data:image/svg+xml,${encodeURIComponent(preset.svg)}`;
  }
  return null;
}

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, hasPageAccess, isAdmin } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const isMobile = useMediaQuery('(max-width:900px)');
  const [attackCount, setAttackCount] = useState(0);
  const [recentThreats, setRecentThreats] = useState([]);
  const [bellAnchor, setBellAnchor] = useState(null);
  const [userMenuAnchor, setUserMenuAnchor] = useState(null);
  const [seenCount, setSeenCount] = useState(() => {
    const saved = sessionStorage.getItem('pids_seen_attacks');
    return saved ? parseInt(saved, 10) : 0;
  });

  const unreadCount = Math.max(0, attackCount - seenCount);

  const allNavItems = [
    { path: '/dashboard', label: 'DASHBOARD', icon: <DashboardIcon />, page: 'dashboard' },
    // Unified Learn experience — single nav item that opens the
    // scroll-driven /learn/<stack> sub-pages. Replaces the old
    // ARCHITECTURE + HOW IT LEARNS pair.
    { path: '/learn/classical', label: 'LEARN', icon: <SchoolIcon />, page: 'architecture' },
    { path: '/analysis', label: 'ANALYSIS', icon: <AnalyticsIcon />, page: null },
    { path: '/attacks', label: 'THREATS', icon: <SecurityIcon />, page: 'threats' },
    { path: '/retraining', label: 'RETRAIN', icon: <MemoryIcon />, page: 'retraining' },
    { path: '/diagnostics', label: 'DIAGNOSTICS', icon: <DiagnosticsIcon />, page: 'diagnostics' },
    { path: '/admin', label: 'ADMIN', icon: <PersonIcon />, page: 'admin_panel' },
  ];

  // Items with `page: null` are visible to every authenticated user.
  const navItems = allNavItems.filter(item => item.page == null || hasPageAccess(item.page));

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsRes, threatRes] = await Promise.all([
          axios.get(`${API_BASE}/stats/`),
          axios.get(`${API_BASE}/traffic/?limit=5&status=Attack`)
        ]);
        const data = statsRes.data;
        const threats = data.llm_attacks || 0;
        setAttackCount(threats > 0 ? threats : data.attacks || 0);
        setRecentThreats(threatRes.data || []);
      } catch (error) { /* silent */ }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleDrawerToggle = () => setMobileOpen(!mobileOpen);
  // Active-route check. Most items use exact match; the unified LEARN
  // entry (path: /learn/gnn) must light up on any /learn/* sub-route.
  const isActive = (path) => {
    if (path && path.startsWith('/learn')) return location.pathname.startsWith('/learn');
    return location.pathname === path;
  };

  const handleBellClick = (event) => {
    setBellAnchor(event.currentTarget);
    setSeenCount(attackCount);
    sessionStorage.setItem('pids_seen_attacks', String(attackCount));
  };

  const handleLogout = () => {
    setUserMenuAnchor(null);
    logout();
    navigate('/login');
  };

  const getSeverity = (prediction) => {
    if (!prediction) return { label: 'Low', color: '#888' };
    const p = prediction.toLowerCase();
    if (p.includes('ddos') || p.includes('dos')) return { label: 'Critical', color: '#ff3b3b' };
    if (p.includes('bot') || p.includes('llm') || p.includes('sql')) return { label: 'High', color: '#ff9800' };
    if (p.includes('brute') || p.includes('scan')) return { label: 'Medium', color: '#ffd600' };
    return { label: 'Low', color: '#888' };
  };

  const drawer = (
    <Box sx={{ width: 250, bgcolor: '#0a0a0a', height: '100%', pt: 2 }}>
      <Typography variant="h6" sx={{ color: '#00d4ff', px: 2, mb: 1, fontFamily: 'Share Tech Mono' }}>
        🛡️ PIDS SYSTEM
      </Typography>
      {user && (
        <Typography sx={{ color: '#888', px: 2, mb: 2, fontSize: '0.8rem', fontFamily: 'Share Tech Mono' }}>
          {user.role_display}
        </Typography>
      )}
      <List>
        {navItems.map((item) => (
          <ListItem key={item.path} component={Link} to={item.path} onClick={handleDrawerToggle}
            sx={{ color: isActive(item.path) ? '#00d4ff' : '#888',
              bgcolor: isActive(item.path) ? 'rgba(0,255,65,0.1)' : 'transparent',
              '&:hover': { bgcolor: 'rgba(0,255,65,0.05)', color: '#00d4ff' } }}>
            <ListItemIcon sx={{ color: 'inherit', minWidth: 40 }}>{item.icon}</ListItemIcon>
            <ListItemText primary={item.label}
              primaryTypographyProps={{ fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }} />
          </ListItem>
        ))}
        <Divider sx={{ borderColor: '#1a3a2a', my: 1 }} />
        <ListItem component={Link} to="/profile" onClick={handleDrawerToggle}
          sx={{ color: isActive('/profile') ? '#00d4ff' : '#888',
            '&:hover': { bgcolor: 'rgba(0,255,65,0.05)', color: '#00d4ff' } }}>
          <ListItemIcon sx={{ color: 'inherit', minWidth: 40 }}><SettingsIcon /></ListItemIcon>
          <ListItemText primary="PROFILE SETTINGS"
            primaryTypographyProps={{ fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }} />
        </ListItem>
        <ListItem onClick={handleLogout} sx={{ color: '#ff3b3b', cursor: 'pointer',
          '&:hover': { bgcolor: 'rgba(255,59,59,0.05)' } }}>
          <ListItemIcon sx={{ color: 'inherit', minWidth: 40 }}><LogoutIcon /></ListItemIcon>
          <ListItemText primary="LOGOUT"
            primaryTypographyProps={{ fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }} />
        </ListItem>
      </List>
    </Box>
  );

  return (
    <>
      <AppBar position="static" sx={{
        bgcolor: 'rgba(10,10,10,0.98)', borderBottom: '1px solid #00d4ff',
        boxShadow: '0 0 20px rgba(0,255,65,0.3)', zIndex: 1000
      }}>
        <Toolbar>
          {isMobile && (
            <IconButton color="inherit" edge="start" onClick={handleDrawerToggle}
              sx={{ mr: 2, color: '#00d4ff' }}><MenuIcon /></IconButton>
          )}

          <Typography variant="h6" component={Link} to="/"
            sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', textDecoration: 'none',
              display: 'flex', alignItems: 'center', gap: 1 }}>
            🛡️ PIDS <span style={{ color: '#888' }}>//</span> SYSTEM
          </Typography>

          {!isMobile && (
            <Box sx={{ display: 'flex', ml: 4, gap: 1 }}>
              {navItems.map((item) => (
                <Button key={item.path} component={Link} to={item.path} startIcon={item.icon}
                  sx={{ color: isActive(item.path) ? '#00d4ff' : '#888',
                    fontFamily: 'Share Tech Mono', fontSize: '0.85rem',
                    borderBottom: isActive(item.path) ? '2px solid #00d4ff' : '2px solid transparent',
                    borderRadius: 0, px: 2,
                    '&:hover': { color: '#00d4ff', bgcolor: 'rgba(0,255,65,0.05)' } }}>
                  {item.label}
                </Button>
              ))}
            </Box>
          )}

          <Box sx={{ flexGrow: 1 }} />

          {hasPageAccess('threats') && (
            <Tooltip title={unreadCount > 0 ? `${unreadCount} new threats` : 'No new threats'}>
              <IconButton onClick={handleBellClick}
                sx={{ color: unreadCount > 0 ? '#ff3b3b' : '#888',
                  '&:hover': { color: unreadCount > 0 ? '#ff6b6b' : '#00d4ff' },
                  animation: unreadCount > 0 ? 'pulse 2s infinite' : 'none' }}>
                <Badge badgeContent={unreadCount > 999 ? '999+' : unreadCount}
                  color="error" invisible={unreadCount === 0}>
                  <NotificationIcon />
                </Badge>
              </IconButton>
            </Tooltip>
          )}

          <Tooltip title={user?.username || ''}>
            <IconButton onClick={(e) => setUserMenuAnchor(e.currentTarget)}
              sx={{ ml: 1, color: '#00d4ff' }}>
              <Avatar src={getNavAvatarSrc(user) || undefined}
                sx={{ width: 32, height: 32, bgcolor: getNavAvatarSrc(user) ? 'transparent' : '#1a3a2a',
                  fontSize: '0.85rem', fontFamily: 'Share Tech Mono', border: '1px solid #00d4ff' }}>
                {!getNavAvatarSrc(user) && (user?.username?.charAt(0).toUpperCase() || '?')}
              </Avatar>
            </IconButton>
          </Tooltip>

          {/* User Dropdown — with Profile Settings */}
          <Menu anchorEl={userMenuAnchor} open={Boolean(userMenuAnchor)}
            onClose={() => setUserMenuAnchor(null)}
            PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a',
              minWidth: 220, mt: 1 } }}>
            <Box sx={{ px: 2, py: 1.5, borderBottom: '1px solid #1a3a2a', display: 'flex', alignItems: 'center', gap: 1.5 }}>
              <Avatar src={getNavAvatarSrc(user) || undefined}
                sx={{ width: 40, height: 40, bgcolor: getNavAvatarSrc(user) ? 'transparent' : '#00d4ff',
                  color: '#0a0a0a', fontSize: '1rem', fontWeight: 'bold',
                  fontFamily: 'Share Tech Mono', border: '1px solid #1a3a2a' }}>
                {!getNavAvatarSrc(user) && (user?.username?.charAt(0).toUpperCase() || '?')}
              </Avatar>
              <Box>
                <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.95rem', fontWeight: 'bold' }}>
                  {user?.full_name || user?.username}
                </Typography>
                <Typography sx={{ color: '#888', fontSize: '0.75rem', fontFamily: 'Share Tech Mono' }}>
                  {user?.role_display}
                </Typography>
              </Box>
            </Box>
            <MenuItem onClick={() => { setUserMenuAnchor(null); navigate('/profile'); }}
              sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', py: 1.2,
                '&:hover': { bgcolor: 'rgba(0,255,65,0.08)' } }}>
              <SettingsIcon sx={{ mr: 1.5, fontSize: 18, color: '#00d4ff' }} /> Profile Settings
            </MenuItem>
            <Divider sx={{ borderColor: '#1a3a2a' }} />
            <MenuItem onClick={handleLogout}
              sx={{ color: '#ff3b3b', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', py: 1.2,
                '&:hover': { bgcolor: 'rgba(255,59,59,0.08)' } }}>
              <LogoutIcon sx={{ mr: 1.5, fontSize: 18 }} /> Logout
            </MenuItem>
          </Menu>

          {/* Bell Popover */}
          <Popover open={Boolean(bellAnchor)} anchorEl={bellAnchor}
            onClose={() => setBellAnchor(null)}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            transformOrigin={{ vertical: 'top', horizontal: 'right' }}
            PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a',
              borderRadius: 2, width: 380, maxHeight: 460 } }}>
            <Box sx={{ p: 2, borderBottom: '1px solid #1a3a2a', display: 'flex',
              justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono',
                fontSize: '0.95rem', fontWeight: 'bold' }}>
                🔔 Threat Notifications
              </Typography>
              <Chip label={`${attackCount.toLocaleString()} total`} size="small"
                sx={{ bgcolor: unreadCount > 0 ? 'rgba(255,59,59,0.15)' : 'rgba(0,255,65,0.1)',
                  color: unreadCount > 0 ? '#ff3b3b' : '#00d4ff',
                  fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }} />
            </Box>
            <Box sx={{ maxHeight: 340, overflow: 'auto',
              '&::-webkit-scrollbar': { width: 4 },
              '&::-webkit-scrollbar-thumb': { bgcolor: '#1a3a2a', borderRadius: 2 } }}>
              {recentThreats.length > 0 ? recentThreats.map((threat, i) => {
                const sev = getSeverity(threat.prediction);
                return (
                  <Box key={i} sx={{ px: 2, py: 1.5, borderBottom: '1px solid #111820',
                    '&:hover': { bgcolor: 'rgba(0,255,65,0.03)' } }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <WarningIcon sx={{ fontSize: 16, color: sev.color }} />
                        <Typography sx={{ color: '#e0e0e0', fontSize: '0.85rem', fontFamily: 'Share Tech Mono' }}>
                          {threat.prediction ? (threat.prediction.length > 28 ? threat.prediction.slice(0, 28) + '...' : threat.prediction) : 'Attack'}
                        </Typography>
                      </Box>
                      <Chip label={sev.label} size="small"
                        sx={{ height: 20, fontSize: '0.65rem', bgcolor: `${sev.color}20`,
                          color: sev.color, fontFamily: 'Share Tech Mono' }} />
                    </Box>
                    <Typography sx={{ color: '#888', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                      {threat.src_ip} → {threat.dst_ip}:{threat.dst_port || '?'}
                    </Typography>
                  </Box>
                );
              }) : (
                <Box sx={{ p: 3, textAlign: 'center' }}>
                  <CheckIcon sx={{ fontSize: 40, color: '#00d4ff', mb: 1 }} />
                  <Typography sx={{ color: '#888', fontSize: '0.85rem' }}>No active threats</Typography>
                </Box>
              )}
            </Box>
            {recentThreats.length > 0 && (
              <Box sx={{ p: 1.5, borderTop: '1px solid #1a3a2a', textAlign: 'center' }}>
                <Button size="small" endIcon={<OpenIcon sx={{ fontSize: 14 }} />}
                  onClick={() => { setBellAnchor(null); navigate('/attacks'); }}
                  sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.8rem',
                    '&:hover': { bgcolor: 'rgba(0,255,65,0.05)' } }}>
                  View All Threats
                </Button>
              </Box>
            )}
          </Popover>
        </Toolbar>
      </AppBar>

      <Drawer variant="temporary" open={mobileOpen} onClose={handleDrawerToggle}
        ModalProps={{ keepMounted: true }}
        sx={{ '& .MuiDrawer-paper': { bgcolor: '#0a0a0a', borderRight: '1px solid #333' } }}>
        {drawer}
      </Drawer>
    </>
  );
};

export default Navbar;
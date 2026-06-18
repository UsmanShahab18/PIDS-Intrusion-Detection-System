import React, { useState, useEffect, useCallback } from 'react';
import {
  Box, Container, Typography, Paper, Button, TextField, Select, MenuItem,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Dialog, DialogTitle, DialogContent, DialogActions, IconButton,
  Chip, Alert, Switch, FormControlLabel, Grid, Tooltip, Divider, Avatar
} from '@mui/material';
import {
  PersonAdd as AddIcon, Delete as DeleteIcon, Edit as EditIcon,
  Lock as LockIcon, LockOpen as UnlockIcon, Refresh as RefreshIcon,
  AdminPanelSettings as AdminIcon, Security as SecurityIcon,
  Visibility as ViewIcon, History as HistoryIcon
} from '@mui/icons-material';
import axios from 'axios';
import { API_BASE } from '../config';
import { PRESET_AVATARS } from './ProfileSettings';
import { useAuth } from '../context/AuthContext';
import EngineSelector from './EngineSelector';

const ROLE_COLORS = {
  admin: '#ff3b3b',
  security_analyst: '#ff9800',
  network_monitor: '#00d4ff',
  it_support: '#ffd600',
  ml_engineer: '#aa66ff',
};

const ROLE_LABELS = {
  admin: 'Administrator',
  security_analyst: 'Security Analyst',
  network_monitor: 'Network Monitor',
  it_support: 'IT Support',
  ml_engineer: 'ML/AI Engineer',
};

const AdminPanel = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Create user dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [newUser, setNewUser] = useState({
    username: '', password: '', email: '', full_name: '', role: 'network_monitor'
  });

  // Edit user dialog
  const [editOpen, setEditOpen] = useState(false);
  const [editUser, setEditUser] = useState(null);

  // Audit log dialog
  const [auditOpen, setAuditOpen] = useState(false);

  // View permissions dialog
  const [permOpen, setPermOpen] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      const [usersRes, rolesRes] = await Promise.all([
        axios.get(`${API_BASE}/admin/users/`),
        axios.get(`${API_BASE}/admin/roles/`),
      ]);
      setUsers(usersRes.data);
      setRoles(rolesRes.data);
    } catch (err) {
      setError('Failed to load data');
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchAudit = async () => {
    try {
      const res = await axios.get(`${API_BASE}/admin/audit/?limit=50`);
      setAuditLogs(res.data);
    } catch (err) {
      setError('Failed to load audit logs');
    }
  };

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleCreateUser = async () => {
    setError(''); setSuccess('');
    if (!newUser.username || !newUser.password || !newUser.role) {
      setError('Username, password, and role are required');
      return;
    }
    if (newUser.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    try {
      await axios.post(`${API_BASE}/admin/users/create/`, newUser);
      setSuccess(`User "${newUser.username}" created successfully`);
      setCreateOpen(false);
      setNewUser({ username: '', password: '', email: '', full_name: '', role: 'network_monitor' });
      fetchData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create user');
    }
  };

  const handleUpdateUser = async () => {
    if (!editUser) return;
    setError(''); setSuccess('');
    try {
      await axios.put(`${API_BASE}/admin/users/${editUser.id}/`, {
        role: editUser.role,
        is_active: editUser.is_active,
        full_name: editUser.full_name,
      });
      setSuccess(`User "${editUser.username}" updated`);
      setEditOpen(false);
      setEditUser(null);
      fetchData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update user');
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Delete user "${username}"? This cannot be undone.`)) return;
    setError(''); setSuccess('');
    try {
      await axios.delete(`${API_BASE}/admin/users/${userId}/delete/`);
      setSuccess(`User "${username}" deleted`);
      fetchData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to delete user');
    }
  };

  const handleUnlockUser = async (userId, username) => {
    try {
      await axios.put(`${API_BASE}/admin/users/${userId}/`, { unlock: true });
      setSuccess(`User "${username}" unlocked`);
      fetchData();
    } catch (err) {
      setError('Failed to unlock user');
    }
  };

  const inputSx = {
    '& .MuiOutlinedInput-root': {
      color: '#e0e0e0', fontFamily: 'Share Tech Mono',
      '& fieldset': { borderColor: '#1a3a2a' },
      '&:hover fieldset': { borderColor: '#00d4ff' },
      '&.Mui-focused fieldset': { borderColor: '#00d4ff' },
    },
    '& .MuiInputLabel-root': { color: '#888', fontFamily: 'Share Tech Mono' },
    '& .MuiInputLabel-root.Mui-focused': { color: '#00d4ff' },
  };

  const selectSx = {
    color: '#e0e0e0', fontFamily: 'Share Tech Mono',
    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#1a3a2a' },
    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#00d4ff' },
    '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#00d4ff' },
    '& .MuiSelect-icon': { color: '#888' },
  };

  const pages = ['dashboard', 'threats', 'reports', 'retraining', 'diagnostics', 'architecture', 'admin_panel'];

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent', pt: 3, pb: 6 }}>
      <Container maxWidth="lg">
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Box>
            <Typography sx={{ fontSize: '2rem', fontFamily: 'Share Tech Mono', color: '#00d4ff', fontWeight: 'bold' }}>
              <AdminIcon sx={{ mr: 1, verticalAlign: 'middle', fontSize: 32 }} />
              Admin Panel
            </Typography>
            <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }}>
              User Management & Access Control
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button startIcon={<HistoryIcon />} onClick={() => { fetchAudit(); setAuditOpen(true); }}
              sx={{ color: '#888', fontFamily: 'Share Tech Mono', borderColor: '#333',
                '&:hover': { color: '#00d4ff', borderColor: '#00d4ff' } }} variant="outlined" size="small">
              Audit Log
            </Button>
            <Button startIcon={<ViewIcon />} onClick={() => setPermOpen(true)}
              sx={{ color: '#888', fontFamily: 'Share Tech Mono', borderColor: '#333',
                '&:hover': { color: '#00d4ff', borderColor: '#00d4ff' } }} variant="outlined" size="small">
              Permissions
            </Button>
            <Button startIcon={<AddIcon />} onClick={() => setCreateOpen(true)}
              sx={{ bgcolor: '#00d4ff', color: '#0a0a0a', fontFamily: 'Share Tech Mono', fontWeight: 'bold',
                '&:hover': { bgcolor: '#00a8cc' } }} variant="contained">
              Create User
            </Button>
          </Box>
        </Box>

        {/* Alerts */}
        {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>{error}</Alert>}
        {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>{success}</Alert>}

        {/* Detection Engine selector — admin only (component returns null otherwise). */}
        <EngineSelector />

        {/* Users Table */}
        <Paper sx={{ bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 }}>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow sx={{ '& th': { color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.85rem',
                  borderBottom: '1px solid #1a3a2a', bgcolor: '#0a1410' } }}>
                  <TableCell>Username</TableCell>
                  <TableCell>Full Name</TableCell>
                  <TableCell>Role</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Last Login</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {users.map(u => (
                  <TableRow key={u.id} sx={{ '& td': { color: '#e0e0e0', fontFamily: 'Share Tech Mono',
                    fontSize: '0.85rem', borderBottom: '1px solid #111820' },
                    '&:hover': { bgcolor: 'rgba(0,255,65,0.02)' } }}>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Avatar
                          src={(() => {
                            if (u.avatar_type === 'custom' && u.avatar_data) return u.avatar_data;
                            if (u.avatar_type === 'preset' && u.avatar_data) {
                              const p = PRESET_AVATARS.find(a => a.id === u.avatar_data);
                              if (p) return `data:image/svg+xml,${encodeURIComponent(p.svg)}`;
                            }
                            return undefined;
                          })()}
                          sx={{ width: 32, height: 32, bgcolor: '#1a3a2a', fontSize: '0.8rem',
                            color: '#00d4ff', fontFamily: 'Share Tech Mono',
                            border: `1px solid ${ROLE_COLORS[u.role] || '#555'}` }}>
                          {u.username.charAt(0).toUpperCase()}
                        </Avatar>
                        {u.username}
                        {u.id === currentUser?.id && (
                          <Chip label="YOU" size="small" sx={{ height: 18, fontSize: '0.6rem',
                            bgcolor: 'rgba(0,255,65,0.1)', color: '#00d4ff' }} />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>{u.full_name || '-'}</TableCell>
                    <TableCell>
                      <Chip label={ROLE_LABELS[u.role] || u.role || 'No Role'} size="small"
                        sx={{ bgcolor: `${ROLE_COLORS[u.role] || '#555'}20`,
                          color: ROLE_COLORS[u.role] || '#888',
                          fontFamily: 'Share Tech Mono', fontSize: '0.75rem' }} />
                    </TableCell>
                    <TableCell>
                      <Chip label={u.is_active ? 'Active' : 'Disabled'} size="small"
                        sx={{ bgcolor: u.is_active ? 'rgba(0,255,65,0.1)' : 'rgba(255,59,59,0.1)',
                          color: u.is_active ? '#00d4ff' : '#ff3b3b', fontSize: '0.7rem' }} />
                    </TableCell>
                    <TableCell sx={{ color: '#888 !important', fontSize: '0.8rem !important' }}>
                      {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => { setEditUser({...u}); setEditOpen(true); }}
                          sx={{ color: '#00d4ff', '&:hover': { color: '#00d4ff' } }}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {u.id !== currentUser?.id && (
                        <Tooltip title="Delete">
                          <IconButton size="small" onClick={() => handleDeleteUser(u.id, u.username)}
                            sx={{ color: '#ff3b3b', '&:hover': { color: '#ff6b6b' } }}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
                {users.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} sx={{ textAlign: 'center', color: '#888', py: 4 }}>
                      No users found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* ================ CREATE USER DIALOG ================ */}
        <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm" fullWidth
          PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 } }}>
          <DialogTitle sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', borderBottom: '1px solid #1a3a2a' }}>
            <AddIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Create New User
          </DialogTitle>
          <DialogContent sx={{ pt: '16px !important' }}>
            <TextField fullWidth label="Username" value={newUser.username}
              onChange={e => setNewUser(p => ({...p, username: e.target.value}))}
              sx={{ ...inputSx, mb: 2 }} required />
            <TextField fullWidth label="Full Name" value={newUser.full_name}
              onChange={e => setNewUser(p => ({...p, full_name: e.target.value}))}
              sx={{ ...inputSx, mb: 2 }} />
            <TextField fullWidth label="Email" value={newUser.email} type="email"
              onChange={e => setNewUser(p => ({...p, email: e.target.value}))}
              sx={{ ...inputSx, mb: 2 }} />
            <TextField fullWidth label="Password" value={newUser.password} type="password"
              onChange={e => setNewUser(p => ({...p, password: e.target.value}))}
              sx={{ ...inputSx, mb: 2 }} required helperText="Minimum 8 characters" 
              FormHelperTextProps={{ sx: { color: '#555' } }} />
            
            <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', mb: 1 }}>
              Role *
            </Typography>
            <Select fullWidth value={newUser.role}
              onChange={e => setNewUser(p => ({...p, role: e.target.value}))} sx={selectSx}>
              {Object.entries(ROLE_LABELS).filter(([key]) => key !== 'admin').map(([key, label]) => (
                <MenuItem key={key} value={key} sx={{ fontFamily: 'Share Tech Mono' }}>
                  <Chip label={label} size="small" sx={{ bgcolor: `${ROLE_COLORS[key]}20`,
                    color: ROLE_COLORS[key], fontFamily: 'Share Tech Mono', fontSize: '0.8rem', mr: 1 }} />
                </MenuItem>
              ))}
            </Select>

            {/* Show permissions preview */}
            {newUser.role && roles.length > 0 && (
              <Box sx={{ mt: 2, p: 1.5, bgcolor: '#0a1410', borderRadius: 1, border: '1px solid #1a3a2a' }}>
                <Typography sx={{ color: '#888', fontSize: '0.75rem', fontFamily: 'Share Tech Mono', mb: 1 }}>
                  Access preview for {ROLE_LABELS[newUser.role]}:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {pages.map(page => {
                    const role = roles.find(r => r.name === newUser.role);
                    const hasAccess = role?.permissions?.[page];
                    return (
                      <Chip key={page} label={page} size="small"
                        sx={{ fontSize: '0.65rem', fontFamily: 'Share Tech Mono',
                          bgcolor: hasAccess ? 'rgba(0,255,65,0.1)' : 'rgba(255,59,59,0.05)',
                          color: hasAccess ? '#00d4ff' : '#555' }} />
                    );
                  })}
                </Box>
              </Box>
            )}
          </DialogContent>
          <DialogActions sx={{ borderTop: '1px solid #1a3a2a', p: 2 }}>
            <Button onClick={() => setCreateOpen(false)} sx={{ color: '#888', fontFamily: 'Share Tech Mono' }}>Cancel</Button>
            <Button onClick={handleCreateUser} variant="contained"
              sx={{ bgcolor: '#00d4ff', color: '#0a0a0a', fontFamily: 'Share Tech Mono', fontWeight: 'bold',
                '&:hover': { bgcolor: '#00a8cc' } }}>
              Create User
            </Button>
          </DialogActions>
        </Dialog>

        {/* ================ EDIT USER DIALOG ================ */}
        <Dialog open={editOpen} onClose={() => setEditOpen(false)} maxWidth="sm" fullWidth
          PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 } }}>
          <DialogTitle sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', borderBottom: '1px solid #1a3a2a' }}>
            <EditIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Edit User: {editUser?.username}
          </DialogTitle>
          {editUser && (
            <DialogContent sx={{ pt: '16px !important' }}>
              <TextField fullWidth label="Full Name" value={editUser.full_name || ''}
                onChange={e => setEditUser(p => ({...p, full_name: e.target.value}))}
                sx={{ ...inputSx, mb: 2 }} />
              
              <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', mb: 1 }}>Role</Typography>
              {(editUser.id === currentUser?.id || editUser.role === 'admin') ? (
                <>
                  <Select fullWidth value={editUser.role || ''} disabled sx={{ ...selectSx, mb: 1, opacity: 0.6 }}>
                    {Object.entries(ROLE_LABELS).map(([key, label]) => (
                      <MenuItem key={key} value={key}><Chip label={label} size="small" sx={{ bgcolor: `${ROLE_COLORS[key]}20`, color: ROLE_COLORS[key], fontFamily: 'Share Tech Mono', mr: 1 }} /></MenuItem>
                    ))}
                  </Select>
                  <Typography sx={{ color: '#ff9800', fontSize: '0.7rem', fontFamily: 'Share Tech Mono', mb: 2 }}>
                    {editUser.id === currentUser?.id ? '⚠️ Cannot change your own role' : '🔒 Admin role can only be managed via command line'}
                  </Typography>
                </>
              ) : (
                <Select fullWidth value={editUser.role || ''}
                  onChange={e => setEditUser(p => ({...p, role: e.target.value}))} sx={{ ...selectSx, mb: 2 }}>
                  {Object.entries(ROLE_LABELS).filter(([key]) => key !== 'admin').map(([key, label]) => (
                    <MenuItem key={key} value={key} sx={{ fontFamily: 'Share Tech Mono' }}>
                      <Chip label={label} size="small" sx={{ bgcolor: `${ROLE_COLORS[key]}20`,
                        color: ROLE_COLORS[key], fontFamily: 'Share Tech Mono', mr: 1 }} />
                    </MenuItem>
                  ))}
                </Select>
              )}

              <FormControlLabel
                control={<Switch checked={editUser.is_active}
                  onChange={e => setEditUser(p => ({...p, is_active: e.target.checked}))}
                  sx={{ '& .MuiSwitch-switchBase.Mui-checked': { color: '#00d4ff' },
                    '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: '#00d4ff' } }} />}
                label={<Typography sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono', fontSize: '0.9rem' }}>
                  Account Active</Typography>}
                sx={{ mb: 1 }}
              />
            </DialogContent>
          )}
          <DialogActions sx={{ borderTop: '1px solid #1a3a2a', p: 2 }}>
            <Button onClick={() => setEditOpen(false)} sx={{ color: '#888', fontFamily: 'Share Tech Mono' }}>Cancel</Button>
            <Button onClick={handleUpdateUser} variant="contained"
              sx={{ bgcolor: '#00d4ff', color: '#0a0a0a', fontFamily: 'Share Tech Mono', fontWeight: 'bold',
                '&:hover': { bgcolor: '#00a0cc' } }}>
              Save Changes
            </Button>
          </DialogActions>
        </Dialog>

        {/* ================ PERMISSIONS MATRIX DIALOG ================ */}
        <Dialog open={permOpen} onClose={() => setPermOpen(false)} maxWidth="md" fullWidth
          PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 } }}>
          <DialogTitle sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', borderBottom: '1px solid #1a3a2a' }}>
            <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Role Permissions Matrix
          </DialogTitle>
          <DialogContent>
            <TableContainer sx={{ mt: 2 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ '& th': { color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.8rem',
                    borderBottom: '1px solid #1a3a2a' } }}>
                    <TableCell>Page</TableCell>
                    {roles.map(r => (
                      <TableCell key={r.name} align="center">
                        <Chip label={r.display} size="small" sx={{ bgcolor: `${ROLE_COLORS[r.name]}20`,
                          color: ROLE_COLORS[r.name], fontFamily: 'Share Tech Mono', fontSize: '0.7rem' }} />
                      </TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pages.map(page => (
                    <TableRow key={page} sx={{ '& td': { borderBottom: '1px solid #111820' } }}>
                      <TableCell sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono', fontSize: '0.85rem',
                        textTransform: 'capitalize' }}>
                        {page.replace('_', ' ')}
                      </TableCell>
                      {roles.map(r => (
                        <TableCell key={r.name} align="center">
                          {r.permissions[page] ?
                            <Typography sx={{ color: '#00d4ff', fontSize: '1rem' }}>{'✓'}</Typography> :
                            <Typography sx={{ color: '#333', fontSize: '1rem' }}>{'✗'}</Typography>
                          }
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContent>
          <DialogActions sx={{ borderTop: '1px solid #1a3a2a' }}>
            <Button onClick={() => setPermOpen(false)} sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono' }}>Close</Button>
          </DialogActions>
        </Dialog>

        {/* ================ AUDIT LOG DIALOG ================ */}
        <Dialog open={auditOpen} onClose={() => setAuditOpen(false)} maxWidth="md" fullWidth
          PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 } }}>
          <DialogTitle sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono', borderBottom: '1px solid #1a3a2a' }}>
            <HistoryIcon sx={{ mr: 1, verticalAlign: 'middle' }} /> Audit Log
          </DialogTitle>
          <DialogContent>
            <TableContainer sx={{ mt: 2, maxHeight: 400 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow sx={{ '& th': { color: '#00d4ff', fontFamily: 'Share Tech Mono', fontSize: '0.8rem',
                    bgcolor: '#0a1410', borderBottom: '1px solid #1a3a2a' } }}>
                    <TableCell>Time</TableCell>
                    <TableCell>User</TableCell>
                    <TableCell>Action</TableCell>
                    <TableCell>Details</TableCell>
                    <TableCell>IP</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {auditLogs.map((log, i) => (
                    <TableRow key={i} sx={{ '& td': { color: '#e0e0e0', fontFamily: 'Share Tech Mono',
                      fontSize: '0.8rem', borderBottom: '1px solid #111820' } }}>
                      <TableCell sx={{ color: '#888 !important', whiteSpace: 'nowrap' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell>{log.user}</TableCell>
                      <TableCell>
                        <Chip label={log.action} size="small" sx={{ fontFamily: 'Share Tech Mono',
                          fontSize: '0.7rem', bgcolor: 'rgba(0,255,65,0.1)', color: '#00d4ff' }} />
                      </TableCell>
                      <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {JSON.stringify(log.details)}
                      </TableCell>
                      <TableCell sx={{ color: '#888 !important' }}>{log.ip || '-'}</TableCell>
                    </TableRow>
                  ))}
                  {auditLogs.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} sx={{ textAlign: 'center', color: '#888', py: 3 }}>
                        No audit logs yet
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </DialogContent>
          <DialogActions sx={{ borderTop: '1px solid #1a3a2a' }}>
            <Button onClick={() => setAuditOpen(false)} sx={{ color: '#00d4ff', fontFamily: 'Share Tech Mono' }}>Close</Button>
          </DialogActions>
        </Dialog>

      </Container>
    </Box>
  );
};

export default AdminPanel;
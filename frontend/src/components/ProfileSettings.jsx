import React, { useState, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import axios from 'axios';
import { API_BASE } from '../config';
import {
  Box, Paper, Typography, TextField, Button, Avatar, Grid,
  Alert, Snackbar, Divider, IconButton, InputAdornment, Dialog, DialogTitle, DialogContent
} from '@mui/material';
import {
  Visibility, VisibilityOff, Save as SaveIcon,
  Lock as LockIcon, Person as PersonIcon,
  CameraAlt as CameraIcon, Close as CloseIcon
} from '@mui/icons-material';

// ====== PRESET AVATARS (16 total — SVG cyberpunk themed) ======
const PRESET_AVATARS = [
  // --- Row 1: Icon Avatars ---
  { id: 'hacker', label: 'Hacker', color: '#00d4ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#00d4ff" stroke-width="2"/><path d="M25 35 Q50 15 75 35 L70 55 Q50 65 30 55 Z" fill="#1a3a2a"/><circle cx="38" cy="42" r="4" fill="#00d4ff"/><circle cx="62" cy="42" r="4" fill="#00d4ff"/><path d="M40 55 Q50 60 60 55" stroke="#00d4ff" stroke-width="2" fill="none"/><path d="M20 30 Q50 5 80 30" stroke="#00d4ff" stroke-width="2" fill="none"/></svg>` },
  { id: 'shield', label: 'Shield', color: '#2E75B6', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#2E75B6" stroke-width="2"/><path d="M50 18 L75 30 L75 55 Q75 75 50 85 Q25 75 25 55 L25 30 Z" fill="#1a2a4a" stroke="#2E75B6" stroke-width="2"/><path d="M42 50 L48 58 L62 40" stroke="#00d4ff" stroke-width="3" fill="none" stroke-linecap="round"/></svg>` },
  { id: 'robot', label: 'Robot', color: '#aa66ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#aa66ff" stroke-width="2"/><rect x="28" y="30" width="44" height="35" rx="5" fill="#1a1a3a" stroke="#aa66ff" stroke-width="2"/><rect x="35" y="38" width="10" height="8" rx="2" fill="#00d4ff"/><rect x="55" y="38" width="10" height="8" rx="2" fill="#00d4ff"/><line x1="40" y1="55" x2="60" y2="55" stroke="#aa66ff" stroke-width="2"/><line x1="50" y1="22" x2="50" y2="30" stroke="#aa66ff" stroke-width="2"/><circle cx="50" cy="20" r="3" fill="#aa66ff"/></svg>` },
  { id: 'cyber', label: 'Cyber', color: '#ff3b3b', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#ff3b3b" stroke-width="2"/><ellipse cx="50" cy="42" rx="22" ry="25" fill="#1a1a1a" stroke="#ff3b3b" stroke-width="2"/><circle cx="40" cy="38" r="6" fill="#ff3b3b" opacity="0.8"/><circle cx="60" cy="38" r="6" fill="#ff3b3b" opacity="0.8"/><path d="M42 52 L46 56 L50 52 L54 56 L58 52" stroke="#ff3b3b" stroke-width="2" fill="none"/></svg>` },
  // --- Row 2: Icon Avatars ---
  { id: 'network', label: 'Network', color: '#00d4ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#00d4ff" stroke-width="2"/><circle cx="50" cy="50" r="25" fill="none" stroke="#00d4ff" stroke-width="1.5"/><ellipse cx="50" cy="50" rx="12" ry="25" fill="none" stroke="#00d4ff" stroke-width="1.5"/><line x1="25" y1="50" x2="75" y2="50" stroke="#00d4ff" stroke-width="1.5"/><circle cx="50" cy="35" r="3" fill="#00d4ff"/><circle cx="35" cy="50" r="3" fill="#00d4ff"/><circle cx="65" cy="50" r="3" fill="#00d4ff"/><circle cx="50" cy="65" r="3" fill="#00d4ff"/></svg>` },
  { id: 'terminal', label: 'Terminal', color: '#00d4ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#00d4ff" stroke-width="2"/><rect x="22" y="28" width="56" height="44" rx="4" fill="#0a1a10" stroke="#00d4ff" stroke-width="2"/><path d="M30 40 L40 48 L30 56" stroke="#00d4ff" stroke-width="2.5" fill="none" stroke-linecap="round"/><line x1="44" y1="56" x2="62" y2="56" stroke="#00d4ff" stroke-width="2.5" stroke-linecap="round"/><circle cx="30" cy="32" r="2" fill="#ff3b3b"/><circle cx="36" cy="32" r="2" fill="#ffd600"/><circle cx="42" cy="32" r="2" fill="#00d4ff"/></svg>` },
  { id: 'eye', label: 'Eye', color: '#ff9800', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#ff9800" stroke-width="2"/><path d="M15 50 Q50 25 85 50 Q50 75 15 50 Z" fill="#1a1a0a" stroke="#ff9800" stroke-width="2"/><circle cx="50" cy="50" r="12" fill="#ff9800" opacity="0.3" stroke="#ff9800" stroke-width="2"/><circle cx="50" cy="50" r="6" fill="#ff9800"/><circle cx="48" cy="48" r="2" fill="#fff"/></svg>` },
  { id: 'lock', label: 'Lock', color: '#ffd600', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0d1117" stroke="#ffd600" stroke-width="2"/><rect x="32" y="45" width="36" height="28" rx="4" fill="#1a1a0a" stroke="#ffd600" stroke-width="2"/><path d="M38 45 L38 35 Q38 22 50 22 Q62 22 62 35 L62 45" fill="none" stroke="#ffd600" stroke-width="2.5"/><circle cx="50" cy="58" r="4" fill="#ffd600"/><line x1="50" y1="62" x2="50" y2="67" stroke="#ffd600" stroke-width="2.5"/></svg>` },
  // --- Row 3: Realistic Person Avatars ---
  { id: 'analyst_m', label: 'Analyst', color: '#00d4ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0a1628" stroke="#00d4ff" stroke-width="2"/><ellipse cx="50" cy="37" rx="14" ry="15" fill="#c4956a"/><path d="M36 30 Q38 18 50 16 Q62 18 64 30 L62 28 Q58 20 50 19 Q42 20 38 28 Z" fill="#1a1a2e"/><rect x="40" y="33" width="8" height="4" rx="2" fill="rgba(0,212,255,0.3)" stroke="#00d4ff" stroke-width="0.5"/><rect x="52" y="33" width="8" height="4" rx="2" fill="rgba(0,212,255,0.3)" stroke="#00d4ff" stroke-width="0.5"/><circle cx="44" cy="35" r="1.5" fill="#1a1a2e"/><circle cx="56" cy="35" r="1.5" fill="#1a1a2e"/><path d="M47 42 Q50 44 53 42" stroke="#8b6e4e" stroke-width="1" fill="none"/><path d="M30 70 Q30 55 50 52 Q70 55 70 70 L70 80 L30 80 Z" fill="#0d2137" stroke="#00d4ff" stroke-width="1"/><circle cx="50" cy="60" r="2" fill="#00d4ff" opacity="0.6"/></svg>` },
  { id: 'analyst_f', label: 'Engineer', color: '#aa66ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0a1020" stroke="#aa66ff" stroke-width="2"/><ellipse cx="50" cy="37" rx="13" ry="14" fill="#d4a574"/><path d="M34 32 Q36 14 50 12 Q64 14 66 32 L64 34 Q62 22 50 20 Q38 22 36 34 Z" fill="#2a1a3a"/><path d="M34 32 Q32 40 35 46" stroke="#2a1a3a" stroke-width="3" fill="none"/><path d="M66 32 Q68 40 65 46" stroke="#2a1a3a" stroke-width="3" fill="none"/><ellipse cx="43" cy="35" rx="3" ry="2.5" fill="#fff"/><ellipse cx="57" cy="35" rx="3" ry="2.5" fill="#fff"/><circle cx="43" cy="35" r="1.5" fill="#3a1a5a"/><circle cx="57" cy="35" r="1.5" fill="#3a1a5a"/><path d="M47 43 Q50 45 53 43" stroke="#b8845a" stroke-width="1" fill="none"/><path d="M30 72 Q30 56 50 53 Q70 56 70 72 L70 82 L30 82 Z" fill="#1a0a2e" stroke="#aa66ff" stroke-width="1"/></svg>` },
  { id: 'soc_lead', label: 'SOC Lead', color: '#ff9800', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#1a0e00" stroke="#ff9800" stroke-width="2"/><ellipse cx="50" cy="37" rx="14" ry="15" fill="#a07850"/><path d="M35 33 Q37 20 50 18 Q63 20 65 33 L63 31 Q60 22 50 21 Q40 22 37 31 Z" fill="#1a1a1a"/><ellipse cx="43" cy="35" rx="3" ry="2.5" fill="#fff"/><ellipse cx="57" cy="35" rx="3" ry="2.5" fill="#fff"/><circle cx="43" cy="35" r="1.5" fill="#2a1a00"/><circle cx="57" cy="35" r="1.5" fill="#2a1a00"/><path d="M46 43 Q50 46 54 43" stroke="#8a6840" stroke-width="1.2" fill="none"/><path d="M28 72 Q28 54 50 52 Q72 54 72 72 L72 82 L28 82 Z" fill="#1a1200" stroke="#ff9800" stroke-width="1"/><rect x="44" y="56" width="12" height="3" rx="1" fill="#ff9800" opacity="0.4"/></svg>` },
  { id: 'pentester', label: 'Pentester', color: '#ff3b3b', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#1a0505" stroke="#ff3b3b" stroke-width="2"/><ellipse cx="50" cy="37" rx="14" ry="15" fill="#c4956a"/><path d="M34 34 Q36 16 50 14 Q64 16 66 34 L64 32 Q60 18 50 17 Q40 18 36 32 Z" fill="#1a1a1a"/><rect x="34" y="32" width="32" height="8" rx="2" fill="rgba(255,59,59,0.15)" stroke="#ff3b3b" stroke-width="0.8"/><circle cx="42" cy="36" r="3" fill="#ff3b3b" opacity="0.8"/><circle cx="58" cy="36" r="3" fill="#ff3b3b" opacity="0.8"/><circle cx="42" cy="36" r="1.2" fill="#fff"/><circle cx="58" cy="36" r="1.2" fill="#fff"/><path d="M46 44 L50 43 L54 44" stroke="#a07850" stroke-width="1" fill="none"/><path d="M28 72 Q28 54 50 52 Q72 54 72 72 L72 82 L28 82 Z" fill="#0a0505"/></svg>` },
  // --- Row 4: Abstract / Themed ---
  { id: 'hoodie', label: 'Shadow', color: '#00d4ff', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#050a05" stroke="#00d4ff" stroke-width="2"/><path d="M30 70 Q28 48 50 42 Q72 48 70 70 L70 82 L30 82 Z" fill="#0a1a0a" stroke="#00d4ff" stroke-width="1"/><path d="M32 50 Q32 30 50 26 Q68 30 68 50 L65 52 Q64 36 50 32 Q36 36 35 52 Z" fill="#0d1a0d" stroke="#00d4ff" stroke-width="0.8"/><ellipse cx="50" cy="45" rx="12" ry="14" fill="#1a1a1a" opacity="0.8"/><circle cx="44" cy="43" r="2" fill="#00d4ff" opacity="0.9"/><circle cx="56" cy="43" r="2" fill="#00d4ff" opacity="0.9"/><path d="M46 50 Q50 52 54 50" stroke="#00d4ff" stroke-width="0.8" fill="none" opacity="0.5"/></svg>` },
  { id: 'military', label: 'Tactical', color: '#4a7a4a', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0a120a" stroke="#4a7a4a" stroke-width="2"/><ellipse cx="50" cy="37" rx="14" ry="15" fill="#a08060"/><path d="M33 32 Q34 22 50 18 Q66 22 67 32 L67 28 L70 28 L68 24 Q64 14 50 12 Q36 14 32 24 L30 28 L33 28 Z" fill="#3a4a3a"/><ellipse cx="43" cy="35" rx="3" ry="2.5" fill="#fff"/><ellipse cx="57" cy="35" rx="3" ry="2.5" fill="#fff"/><circle cx="43" cy="35" r="1.5" fill="#2a3a2a"/><circle cx="57" cy="35" r="1.5" fill="#2a3a2a"/><path d="M46 43 Q50 45 54 43" stroke="#8a6840" stroke-width="1" fill="none"/><path d="M28 72 Q28 54 50 52 Q72 54 72 72 L72 82 L28 82 Z" fill="#2a3a2a"/></svg>` },
  { id: 'ai_core', label: 'AI Core', color: '#00ffcc', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#050f0f" stroke="#00ffcc" stroke-width="2"/><circle cx="50" cy="50" r="30" fill="none" stroke="#00ffcc" stroke-width="0.8" opacity="0.3"/><circle cx="50" cy="50" r="20" fill="none" stroke="#00ffcc" stroke-width="0.8" opacity="0.5"/><circle cx="50" cy="50" r="10" fill="#00ffcc" opacity="0.1" stroke="#00ffcc" stroke-width="1"/><circle cx="50" cy="50" r="4" fill="#00ffcc" opacity="0.8"/><line x1="50" y1="20" x2="50" y2="40" stroke="#00ffcc" stroke-width="1" opacity="0.6"/><line x1="50" y1="60" x2="50" y2="80" stroke="#00ffcc" stroke-width="1" opacity="0.6"/><line x1="20" y1="50" x2="40" y2="50" stroke="#00ffcc" stroke-width="1" opacity="0.6"/><line x1="60" y1="50" x2="80" y2="50" stroke="#00ffcc" stroke-width="1" opacity="0.6"/><circle cx="50" cy="20" r="2.5" fill="#00ffcc" opacity="0.7"/><circle cx="50" cy="80" r="2.5" fill="#00ffcc" opacity="0.7"/><circle cx="20" cy="50" r="2.5" fill="#00ffcc" opacity="0.7"/><circle cx="80" cy="50" r="2.5" fill="#00ffcc" opacity="0.7"/></svg>` },
  { id: 'skull', label: 'Threat', color: '#ff3b3b', svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="#0a0505" stroke="#ff3b3b" stroke-width="2"/><path d="M28 45 Q28 20 50 16 Q72 20 72 45 L72 55 Q72 62 65 65 L60 68 L60 72 L40 72 L40 68 L35 65 Q28 62 28 55 Z" fill="#1a0a0a" stroke="#ff3b3b" stroke-width="1.5"/><ellipse cx="40" cy="42" rx="8" ry="9" fill="#0a0505" stroke="#ff3b3b" stroke-width="1.2"/><ellipse cx="60" cy="42" rx="8" ry="9" fill="#0a0505" stroke="#ff3b3b" stroke-width="1.2"/><circle cx="40" cy="42" r="3" fill="#ff3b3b" opacity="0.6"/><circle cx="60" cy="42" r="3" fill="#ff3b3b" opacity="0.6"/><path d="M42 58 L44 62 L48 58 L52 62 L56 58 L58 62" stroke="#ff3b3b" stroke-width="1.5" fill="none"/></svg>` },
];

// Export for Navbar to use
export { PRESET_AVATARS };

const ProfileSettings = () => {
  const { user, refreshUser } = useAuth();
  const fileInputRef = useRef(null);

  // Load avatar state from user context (DB-backed) instead of localStorage
  const [selectedAvatar, setSelectedAvatar] = useState(() => {
    if (user?.avatar_type === 'preset') return user.avatar_data;
    return null;
  });
  const [customImage, setCustomImage] = useState(() => {
    if (user?.avatar_type === 'custom') return user.avatar_data;
    return null;
  });
  const [avatarDialogOpen, setAvatarDialogOpen] = useState(false);
  const [avatarSaving, setAvatarSaving] = useState(false);

  const [profile, setProfile] = useState({
    full_name: user?.full_name || '', email: user?.email || '',
    phone: user?.phone || '', department: user?.department || '',
  });
  const [profileLoading, setProfileLoading] = useState(false);
  const [passwords, setPasswords] = useState({ old_password: '', new_password: '', confirm_password: '' });
  const [showPasswords, setShowPasswords] = useState({ old: false, new: false, confirm: false });
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  const getPasswordStrength = (pw) => {
    if (!pw) return { score: 0, label: '', color: '#333', missing: [] };
    let s = 0;
    const missing = [];
    if (pw.length >= 8) s++; else missing.push('8+ characters');
    if (/[A-Z]/.test(pw)) s++; else missing.push('uppercase letter');
    if (/[a-z]/.test(pw)) s++; else missing.push('lowercase letter');
    if (/[0-9]/.test(pw)) s++; else missing.push('number');
    if (/[^A-Za-z0-9]/.test(pw)) s++; else missing.push('special character');
    return { score: s, label: ['','Very Weak','Weak','Fair','Strong','Very Strong'][s],
      color: ['','#ff3b3b','#ff6b35','#ff9800','#00cc66','#00d4ff'][s], missing };
  };
  const strength = getPasswordStrength(passwords.new_password);

  // ─── Save avatar to PostgreSQL via API ───
  const saveAvatarToDB = async (type, data) => {
    setAvatarSaving(true);
    try {
      await axios.put(`${API_BASE}/auth/profile/`, {
        full_name: profile.full_name, email: profile.email,
        phone: profile.phone, department: profile.department,
        avatar_type: type, avatar_data: data,
      });
      // Clean up old localStorage (migration from old system)
      localStorage.removeItem('pids_avatar');
      localStorage.removeItem('pids_custom_avatar');
      // Refresh user context so Navbar + AdminPanel update immediately
      await refreshUser();
      return true;
    } catch (e) {
      console.error('Avatar save error:', e);
      return false;
    } finally {
      setAvatarSaving(false);
    }
  };

  const getAvatarSrc = () => {
    if (customImage) return customImage;
    if (selectedAvatar) {
      const p = PRESET_AVATARS.find(a => a.id === selectedAvatar);
      if (p) return `data:image/svg+xml,${encodeURIComponent(p.svg)}`;
    }
    return null;
  };
  const avatarSrc = getAvatarSrc();
  const initials = (user?.full_name || user?.username || 'U').split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);

  const handleImageUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { setSnackbar({ open: true, message: '❌ Image must be under 2MB', severity: 'error' }); return; }
    const reader = new FileReader();
    reader.onload = async (ev) => {
      const base64 = ev.target.result;
      const saved = await saveAvatarToDB('custom', base64);
      if (saved) {
        setCustomImage(base64); setSelectedAvatar(null);
        setAvatarDialogOpen(false);
        setSnackbar({ open: true, message: '✅ Profile picture saved', severity: 'success' });
      } else {
        setSnackbar({ open: true, message: '❌ Failed to save avatar', severity: 'error' });
      }
    };
    reader.readAsDataURL(file);
  };

  const selectPreset = async (id) => {
    const saved = await saveAvatarToDB('preset', id);
    if (saved) {
      setSelectedAvatar(id); setCustomImage(null);
      setAvatarDialogOpen(false);
      setSnackbar({ open: true, message: '✅ Avatar saved', severity: 'success' });
    } else {
      setSnackbar({ open: true, message: '❌ Failed to save avatar', severity: 'error' });
    }
  };

  const removeAvatar = async () => {
    const saved = await saveAvatarToDB('initials', '');
    if (saved) {
      setSelectedAvatar(null); setCustomImage(null);
      setAvatarDialogOpen(false);
      setSnackbar({ open: true, message: '✅ Using initials', severity: 'success' });
    }
  };

  const handleSaveProfile = async () => {
    setProfileLoading(true);
    try {
      await axios.put(`${API_BASE}/auth/profile/`, profile);
      setSnackbar({ open: true, message: '✅ Profile updated', severity: 'success' });
      setTimeout(() => window.location.reload(), 1500);
    } catch (e) { setSnackbar({ open: true, message: `❌ ${e.response?.data?.error || 'Failed'}`, severity: 'error' }); }
    finally { setProfileLoading(false); }
  };

  const handleChangePassword = async () => {
    if (passwords.new_password !== passwords.confirm_password) { setSnackbar({ open: true, message: '❌ Passwords do not match', severity: 'error' }); return; }
    if (passwords.new_password === passwords.old_password) { setSnackbar({ open: true, message: '❌ New password must be different from current password', severity: 'error' }); return; }
    if (strength.score < 5) { setSnackbar({ open: true, message: `❌ Password needs: ${strength.missing.join(', ')}`, severity: 'error' }); return; }
    setPasswordLoading(true);
    try {
      await axios.post(`${API_BASE}/auth/change-password/`, passwords);
      setPasswords({ old_password: '', new_password: '', confirm_password: '' });
      setSnackbar({ open: true, message: '✅ Password changed — redirecting...', severity: 'success' });
      // Refresh user context (clears must_change_password flag)
      await refreshUser();
      // If this was a forced password change, redirect to dashboard
      if (user?.must_change_password) {
        setTimeout(() => { window.location.href = '/dashboard'; }, 1500);
      }
    } catch (e) { setSnackbar({ open: true, message: `❌ ${e.response?.data?.error || 'Failed'}`, severity: 'error' }); }
    finally { setPasswordLoading(false); }
  };

  const inputStyle = { style: { color: '#e0e0e0', fontFamily: 'Share Tech Mono' } };
  const labelStyle = { style: { color: '#888', fontFamily: 'Share Tech Mono' } };
  const tfSx = { '& .MuiOutlinedInput-root': { '& fieldset': { borderColor: '#1a3a2a' }, '&:hover fieldset': { borderColor: '#00d4ff' }, '&.Mui-focused fieldset': { borderColor: '#00d4ff' } } };
  const tfSxOrange = { '& .MuiOutlinedInput-root': { '& fieldset': { borderColor: '#3a2a1a' }, '&:hover fieldset': { borderColor: '#ff9800' }, '&.Mui-focused fieldset': { borderColor: '#ff9800' } } };

  return (
    <Box sx={{ maxWidth: 800, mx: 'auto', p: 3 }}>
      {/* Force password change banner */}
      {user?.must_change_password && (
        <Paper sx={{ p: 2, mb: 3, bgcolor: 'rgba(255,59,59,0.08)', border: '1px solid #ff3b3b', borderRadius: 2,
          display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <LockIcon sx={{ color: '#ff3b3b' }} />
          <Box>
            <Typography sx={{ color: '#ff3b3b', fontFamily: 'Share Tech Mono', fontWeight: 'bold', fontSize: '0.95rem' }}>
              Password Change Required
            </Typography>
            <Typography sx={{ color: '#ff9800', fontFamily: 'Share Tech Mono', fontSize: '0.8rem' }}>
              You must change your password below before accessing the system. This is required for all new accounts.
            </Typography>
          </Box>
        </Paper>
      )}
      {/* Avatar Section */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2, textAlign: 'center' }}>
        <Box sx={{ position: 'relative', display: 'inline-block', mb: 2 }}>
          <Avatar src={avatarSrc || undefined}
            sx={{ width: 100, height: 100, bgcolor: avatarSrc ? 'transparent' : '#1a3a2a',
              fontSize: '2rem', fontFamily: 'Share Tech Mono', color: '#00d4ff',
              border: '2px solid #00d4ff', cursor: 'pointer' }}
            onClick={() => setAvatarDialogOpen(true)}>
            {!avatarSrc && initials}
          </Avatar>
          <IconButton onClick={() => setAvatarDialogOpen(true)}
            sx={{ position: 'absolute', bottom: 0, right: -5, bgcolor: '#0d1117', border: '1px solid #00d4ff', p: 0.5,
              '&:hover': { bgcolor: '#1a3a2a' } }}>
            <CameraIcon sx={{ fontSize: 16, color: '#00d4ff' }} />
          </IconButton>
        </Box>
        <Typography sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono', fontWeight: 'bold' }}>{user?.full_name || user?.username}</Typography>
        <Typography sx={{ color: '#00d4ff', fontSize: '0.85rem', fontFamily: 'Share Tech Mono' }}>{user?.role_display}</Typography>
      </Paper>

      {/* Avatar Dialog */}
      <Dialog open={avatarDialogOpen} onClose={() => setAvatarDialogOpen(false)} maxWidth="sm" fullWidth
        PaperProps={{ sx: { bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 } }}>
        <DialogTitle sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          Choose Avatar
          <IconButton onClick={() => setAvatarDialogOpen(false)} sx={{ color: '#888' }}><CloseIcon /></IconButton>
        </DialogTitle>
        <DialogContent>
          <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', mb: 1.5 }}>Preset Avatars</Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1.5, mb: 2 }}>
            {PRESET_AVATARS.map(av => (
              <Box key={av.id} onClick={() => !avatarSaving && selectPreset(av.id)}
                sx={{ textAlign: 'center', p: 1.5, borderRadius: 2, cursor: avatarSaving ? 'wait' : 'pointer',
                  border: `2px solid ${selectedAvatar === av.id ? av.color : 'transparent'}`,
                  bgcolor: selectedAvatar === av.id ? `${av.color}10` : 'transparent',
                  opacity: avatarSaving ? 0.5 : 1,
                  transition: 'all 0.2s', '&:hover': { bgcolor: `${av.color}15`, border: `2px solid ${av.color}40` } }}>
                <Avatar src={`data:image/svg+xml,${encodeURIComponent(av.svg)}`} sx={{ width: 64, height: 64, mx: 'auto', bgcolor: 'transparent' }} />
                <Typography sx={{ color: '#888', fontSize: '0.7rem', fontFamily: 'Share Tech Mono', mt: 0.5 }}>{av.label}</Typography>
              </Box>
            ))}
          </Box>

          <Divider sx={{ borderColor: '#1a3a2a', mb: 2 }} />
          <Typography sx={{ color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.85rem', mb: 1.5 }}>Upload Your Own</Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 2 }}>
            <input ref={fileInputRef} type="file" accept="image/*" hidden onChange={handleImageUpload} />
            <Button variant="outlined" onClick={() => fileInputRef.current?.click()} disabled={avatarSaving}
              sx={{ color: '#00d4ff', borderColor: '#1a3a4a', fontFamily: 'Share Tech Mono', '&:hover': { borderColor: '#00d4ff', bgcolor: 'rgba(0,212,255,0.05)' } }}>
              📷 Upload Image
            </Button>
            <Typography sx={{ color: '#555', fontSize: '0.75rem' }}>JPG, PNG — max 2MB</Typography>
          </Box>

          <Divider sx={{ borderColor: '#1a3a2a', mb: 2 }} />
          <Button variant="outlined" onClick={removeAvatar} disabled={avatarSaving}
            sx={{ color: '#ff3b3b', borderColor: '#3a1a1a', fontFamily: 'Share Tech Mono', fontSize: '0.8rem', '&:hover': { borderColor: '#ff3b3b', bgcolor: 'rgba(255,59,59,0.05)' } }}>
            Use Initials Instead
          </Button>
        </DialogContent>
      </Dialog>

      {/* Profile Info */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <PersonIcon sx={{ color: '#00d4ff', mr: 1 }} />
          <Typography variant="h6" sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono' }}>Profile Information</Typography>
        </Box>
        <Divider sx={{ borderColor: '#1a3a2a', mb: 2 }} />
        {/* Off-screen trap fields to absorb Chrome autofill */}
        <Box sx={{ position: 'absolute', left: -9999, top: -9999, width: 1, height: 1, overflow: 'hidden' }}>
          <input type="text" name="trap_user" autoComplete="username" tabIndex={-1} aria-hidden="true" />
          <input type="password" name="trap_pass" autoComplete="current-password" tabIndex={-1} aria-hidden="true" />
        </Box>
        <Grid container spacing={2}>
          {[
            ['Full Name','full_name'],
            ['Email','email'],
            ['Phone','phone'],
            ['Department','department']
          ].map(([label, key]) => (
            <Grid item xs={12} sm={6} key={key}>
              <TextField fullWidth label={label} value={profile[key]}
                onChange={e => setProfile({ ...profile, [key]: e.target.value })}
                autoComplete="nope"
                name={`pids_profile_${key}`}
                inputProps={{ autoComplete: 'nope', 'data-lpignore': 'true', 'data-1p-ignore': 'true', 'data-form-type': 'other' }}
                InputProps={inputStyle} InputLabelProps={labelStyle} sx={tfSx} />
            </Grid>
          ))}
        </Grid>
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
          <Button variant="contained" startIcon={<SaveIcon />} disabled={profileLoading} onClick={handleSaveProfile}
            sx={{ bgcolor: '#00d4ff', color: '#0a0a0a', fontFamily: 'Share Tech Mono', fontWeight: 'bold', '&:hover': { bgcolor: '#00a8cc' }, '&.Mui-disabled': { bgcolor: '#1a3a2a', color: '#555' } }}>
            {profileLoading ? 'Saving...' : 'Save Changes'}
          </Button>
        </Box>
      </Paper>

      {/* Change Password */}
      <Paper sx={{ p: 3, bgcolor: '#0d1117', border: '1px solid #1a3a2a', borderRadius: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <LockIcon sx={{ color: '#ff9800', mr: 1 }} />
          <Typography variant="h6" sx={{ color: '#e0e0e0', fontFamily: 'Share Tech Mono' }}>Change Password</Typography>
        </Box>
        <Divider sx={{ borderColor: '#1a3a2a', mb: 2 }} />
        <Grid container spacing={2}>
          {[
            ['Current Password','old_password','old','current-password'],
            ['New Password','new_password','new','new-password'],
            ['Confirm Password','confirm_password','confirm','new-password']
          ].map(([label, key, vis, ac], i) => (
            <Grid item xs={12} sm={i === 0 ? 12 : 6} key={key}>
              <TextField fullWidth label={label} type={showPasswords[vis] ? 'text' : 'password'}
                value={passwords[key]} onChange={e => setPasswords({ ...passwords, [key]: e.target.value })}
                autoComplete={ac}
                error={key === 'confirm_password' && passwords.confirm_password !== '' && passwords.new_password !== passwords.confirm_password}
                helperText={key === 'confirm_password' && passwords.confirm_password !== '' && passwords.new_password !== passwords.confirm_password ? 'Passwords do not match' : ''}
                InputProps={{ ...inputStyle, endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPasswords({ ...showPasswords, [vis]: !showPasswords[vis] })} sx={{ color: '#888' }}>
                      {showPasswords[vis] ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                )}} InputLabelProps={labelStyle} sx={tfSxOrange} />
              {key === 'new_password' && passwords.new_password && (
                <Box sx={{ mt: 1 }}>
                  <Box sx={{ display: 'flex', gap: 0.5, mb: 0.5 }}>
                    {[1,2,3,4,5].map(j => <Box key={j} sx={{ flex: 1, height: 4, borderRadius: 2, bgcolor: j <= strength.score ? strength.color : '#1a1a2e' }} />)}
                  </Box>
                  <Typography sx={{ color: strength.color, fontSize: '0.7rem', fontFamily: 'Share Tech Mono' }}>{strength.label}</Typography>
                  {strength.missing.length > 0 && (
                    <Typography sx={{ color: '#ff9800', fontSize: '0.65rem', fontFamily: 'Share Tech Mono', mt: 0.5 }}>
                      Missing: {strength.missing.join(', ')}
                    </Typography>
                  )}
                </Box>
              )}
            </Grid>
          ))}
        </Grid>
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
          <Button variant="contained" startIcon={<LockIcon />}
            disabled={passwordLoading || !passwords.old_password || !passwords.new_password || !passwords.confirm_password}
            onClick={handleChangePassword}
            sx={{ bgcolor: '#ff9800', color: '#0a0a0a', fontFamily: 'Share Tech Mono', fontWeight: 'bold', '&:hover': { bgcolor: '#e68900' }, '&.Mui-disabled': { bgcolor: '#1a3a2a', color: '#555' } }}>
            {passwordLoading ? 'Changing...' : 'Change Password'}
          </Button>
        </Box>
      </Paper>

      <Snackbar open={snackbar.open} autoHideDuration={4000} onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert onClose={() => setSnackbar({ ...snackbar, open: false })} severity={snackbar.severity}
          sx={{ bgcolor: '#0d1117', color: snackbar.severity === 'success' ? '#00d4ff' : '#ff3b3b',
            border: `1px solid ${snackbar.severity === 'success' ? '#00d4ff' : '#ff3b3b'}`, fontFamily: 'Share Tech Mono' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ProfileSettings;
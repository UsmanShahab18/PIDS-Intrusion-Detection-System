import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box, Container, Typography, TextField, Button, Paper, Alert,
  CircularProgress, Fade, IconButton, InputAdornment, LinearProgress
} from '@mui/material';
import {
  Lock as LockIcon, PersonAdd as SetupIcon,
  Visibility, VisibilityOff
} from '@mui/icons-material';
import { useAuth } from '../context/AuthContext';

const validatePassword = (password) => {
  const checks = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
  };
  const score = Object.values(checks).filter(Boolean).length;
  let label, color;
  if (score <= 2) { label = 'Weak'; color = '#ff3b3b'; }
  else if (score <= 3) { label = 'Fair'; color = '#ff9800'; }
  else if (score <= 4) { label = 'Good'; color = '#ffd600'; }
  else { label = 'Strong'; color = '#00d4ff'; }
  return { checks, score, label, color, isValid: score === 5 };
};

const LoginPage = () => {
  const { login, initialSetup, setupRequired } = useAuth();
  const navigate = useNavigate();
  const [isSetup, setIsSetup] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [form, setForm] = useState({
    username: '', password: '', email: '', full_name: '', confirmPassword: ''
  });

  const passwordStrength = useMemo(() => validatePassword(form.password), [form.password]);
  const handleChange = (e) => { setForm(prev => ({ ...prev, [e.target.name]: e.target.value })); setError(''); };

  const handleLogin = async (e) => {
    e.preventDefault(); setLoading(true); setError('');
    try { const result = await login(form.username, form.password);
      if (result.user?.must_change_password) {
        navigate('/profile');
      } else {
        navigate('/dashboard');
      } }
    catch (err) { setError(err.response?.data?.error || 'Login failed'); }
    finally { setLoading(false); }
  };

  const handleSetup = async (e) => {
    e.preventDefault();
    if (!passwordStrength.isValid) { setError('Password must contain: uppercase, lowercase, number, symbol, and 8+ characters'); return; }
    if (form.password !== form.confirmPassword) { setError('Passwords do not match'); return; }
    setLoading(true); setError('');
    try { await initialSetup({ username: form.username, password: form.password, email: form.email, full_name: form.full_name }); navigate('/dashboard'); }
    catch (err) { setError(err.response?.data?.error || 'Setup failed'); }
    finally { setLoading(false); }
  };

  const showSetup = setupRequired || isSetup;

  const inputSx = {
    mb: 2,
    '& .MuiOutlinedInput-root': {
      color: '#e0e0e0', fontFamily: 'Share Tech Mono', bgcolor: 'rgba(10, 20, 16, 0.6)',
      '& fieldset': { borderColor: '#1a3a2a' },
      '&:hover fieldset': { borderColor: '#00d4ff !important' },
      '&.Mui-focused fieldset': { borderColor: '#00d4ff !important', borderWidth: '2px !important' },
    },
    '& .MuiInputLabel-root': { color: '#888', fontFamily: 'Share Tech Mono' },
    '& .MuiInputLabel-root.Mui-focused': { color: '#00d4ff !important' },
    '& .MuiInputBase-input': {
      '&:-webkit-autofill': {
        WebkitBoxShadow: '0 0 0 100px #0a1410 inset !important',
        WebkitTextFillColor: '#e0e0e0 !important', caretColor: '#00d4ff',
      },
    },
  };

  const eyeSx = { color: '#888', '&:hover': { color: '#00d4ff' } };

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', overflow: 'hidden' }}>
      <Box sx={{ position: 'absolute', inset: 0, opacity: 0.03, backgroundImage: 'linear-gradient(#00d4ff 1px, transparent 1px), linear-gradient(90deg, #00d4ff 1px, transparent 1px)', backgroundSize: '50px 50px' }} />

      <Container maxWidth="sm" sx={{ position: 'relative', zIndex: 1 }}>
        <Fade in={true} timeout={800}>
          <Paper sx={{ p: 4, bgcolor: 'rgba(13, 17, 23, 0.95)', border: '1px solid #1a3a2a', borderRadius: 2, boxShadow: '0 0 40px rgba(0, 255, 65, 0.1)' }}>
            <Box sx={{ textAlign: 'center', mb: 3 }}>
              <Typography sx={{ fontSize: '2rem', fontFamily: '"Orbitron", "Share Tech Mono", monospace', fontWeight: 900, color: '#00d4ff', letterSpacing: '0.2em', textShadow: '0 0 20px rgba(0,255,65,0.5)' }}>P.I.D.S.</Typography>
              <Typography sx={{ fontSize: '0.75rem', fontFamily: 'Share Tech Mono', color: '#888', letterSpacing: '0.3em', mt: 0.5 }}>PREDICTIVE INTRUSION DETECTION SYSTEM</Typography>
              <Box sx={{ width: '60%', height: 1, bgcolor: '#00d4ff', mx: 'auto', mt: 2, opacity: 0.3 }} />
            </Box>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3, justifyContent: 'center' }}>
              {showSetup ? <SetupIcon sx={{ color: '#00d4ff' }} /> : <LockIcon sx={{ color: '#00d4ff' }} />}
              <Typography sx={{ fontFamily: 'Share Tech Mono', color: '#00d4ff', fontSize: '1.1rem' }}>
                {showSetup ? 'INITIAL SETUP' : 'SYSTEM LOGIN'}
              </Typography>
            </Box>

            {setupRequired && !isSetup && (
              <Alert severity="info" sx={{ mb: 2, bgcolor: 'rgba(0,255,65,0.05)', color: '#00d4ff', '& .MuiAlert-icon': { color: '#00d4ff' } }}>
                No admin account exists. Create one to get started.
              </Alert>
            )}
            {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

            <Box component="form" onSubmit={showSetup ? handleSetup : handleLogin}>
              {showSetup && <TextField fullWidth label="Full Name" name="full_name" value={form.full_name} onChange={handleChange} sx={inputSx} />}

              <TextField fullWidth label="Username" name="username" value={form.username} onChange={handleChange} required autoFocus autoComplete="username" sx={inputSx} />

              {showSetup && <TextField fullWidth label="Email" name="email" value={form.email} onChange={handleChange} type="email" sx={inputSx} />}

              <TextField fullWidth label="Password" name="password" type={showPassword ? 'text' : 'password'}
                value={form.password} onChange={handleChange} required autoComplete={showSetup ? 'new-password' : 'current-password'}
                InputProps={{ endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowPassword(!showPassword)} edge="end" sx={eyeSx} tabIndex={-1}>
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                )}} sx={inputSx} />

              {showSetup && form.password && (
                <Box sx={{ mb: 2, mt: -1 }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                    <Typography sx={{ fontSize: '0.7rem', fontFamily: 'Share Tech Mono', color: '#888' }}>Password Strength</Typography>
                    <Typography sx={{ fontSize: '0.7rem', fontFamily: 'Share Tech Mono', color: passwordStrength.color, fontWeight: 'bold' }}>{passwordStrength.label}</Typography>
                  </Box>
                  <LinearProgress variant="determinate" value={passwordStrength.score * 20}
                    sx={{ height: 4, borderRadius: 2, bgcolor: '#1a1a1a', '& .MuiLinearProgress-bar': { bgcolor: passwordStrength.color, borderRadius: 2 } }} />
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
                    {[{ key: 'length', label: '8+ chars' }, { key: 'uppercase', label: 'A-Z' }, { key: 'lowercase', label: 'a-z' }, { key: 'number', label: '0-9' }, { key: 'symbol', label: '!@#$' }].map(({ key, label }) => (
                      <Typography key={key} sx={{ fontSize: '0.65rem', fontFamily: 'Share Tech Mono',
                        color: passwordStrength.checks[key] ? '#00d4ff' : '#555',
                        bgcolor: passwordStrength.checks[key] ? 'rgba(0,255,65,0.08)' : 'transparent',
                        px: 0.8, py: 0.2, borderRadius: 0.5,
                        border: `1px solid ${passwordStrength.checks[key] ? '#00d4ff30' : '#222'}` }}>
                        {passwordStrength.checks[key] ? '✓' : '✗'} {label}
                      </Typography>
                    ))}
                  </Box>
                </Box>
              )}

              {showSetup && (
                <TextField fullWidth label="Confirm Password" name="confirmPassword"
                  type={showConfirm ? 'text' : 'password'} value={form.confirmPassword}
                  onChange={handleChange} required autoComplete="new-password"
                  InputProps={{ endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowConfirm(!showConfirm)} edge="end" sx={eyeSx} tabIndex={-1}>
                        {showConfirm ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  )}}
                  error={form.confirmPassword.length > 0 && form.password !== form.confirmPassword}
                  helperText={form.confirmPassword.length > 0 && form.password !== form.confirmPassword ? 'Passwords do not match' : ''}
                  FormHelperTextProps={{ sx: { color: '#ff3b3b' } }}
                  sx={inputSx} />
              )}

              <Button fullWidth type="submit" variant="contained" disabled={loading || (showSetup && !passwordStrength.isValid)}
                sx={{ mt: 1, py: 1.5, fontFamily: 'Share Tech Mono', fontSize: '1rem', bgcolor: '#00d4ff', color: '#0a0a0a', fontWeight: 'bold',
                  '&:hover': { bgcolor: '#00a8cc', boxShadow: '0 0 20px rgba(0,255,65,0.4)' }, '&:disabled': { bgcolor: '#1a3a2a', color: '#555' } }}>
                {loading ? <CircularProgress size={24} sx={{ color: '#00d4ff' }} /> : showSetup ? 'CREATE ADMIN & LOGIN' : 'LOGIN'}
              </Button>
            </Box>

            {setupRequired && (
              <Button fullWidth onClick={() => setIsSetup(!isSetup)}
                sx={{ mt: 2, color: '#888', fontFamily: 'Share Tech Mono', fontSize: '0.8rem', '&:hover': { color: '#00d4ff' } }}>
                {isSetup ? '← Back to Login' : 'First time? Create Admin Account →'}
              </Button>
            )}

            <Typography sx={{ textAlign: 'center', mt: 3, fontSize: '0.7rem', color: '#555', fontFamily: 'Share Tech Mono' }}>
              Lahore Garrison University | FYP 2026
            </Typography>
          </Paper>
        </Fade>
      </Container>
    </Box>
  );
};

export default LoginPage;
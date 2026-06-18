import React from 'react';
import { Navigate } from 'react-router-dom';
import { Box, CircularProgress } from '@mui/material';
import { useAuth } from '../context/AuthContext';

/**
 * ProtectedRoute — wraps a page component.
 * - If not authenticated → redirect to /login
 * - If must change password → redirect to /profile
 * - If authenticated but no page access → redirect to /dashboard
 * - If setup required → redirect to /login (shows setup wizard)
 * 
 * Usage: <ProtectedRoute page="retraining"><ModelRetraining /></ProtectedRoute>
 */
const ProtectedRoute = ({ children, page }) => {
  const { user, isAuthenticated, loading, setupRequired, hasPageAccess } = useAuth();

  // Show loading spinner while checking auth
  if (loading) {
    return (
      <Box sx={{
        display: 'flex', justifyContent: 'center', alignItems: 'center',
        minHeight: '80vh', bgcolor: 'transparent'
      }}>
        <CircularProgress sx={{ color: '#00d4ff' }} />
      </Box>
    );
  }

  // Setup required — go to login (which shows setup wizard)
  if (setupRequired) {
    return <Navigate to="/login" replace />;
  }

  // Not logged in — go to login
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Force password change on first login — redirect to profile
  if (user?.must_change_password && page !== 'profile') {
    return <Navigate to="/profile" replace />;
  }

  // Check page permission (if page name provided)
  if (page && !hasPageAccess(page)) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

export default ProtectedRoute;
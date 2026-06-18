import React from 'react';
import { Box, CircularProgress } from '@mui/material';

// Shared Suspense fallback (skill: progressive-loading, loading-states).
export default function PageLoader() {
  return (
    <Box
      sx={{
        minHeight: '70vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'transparent',
      }}
    >
      <CircularProgress sx={{ color: '#00ff88' }} />
    </Box>
  );
}

import React from 'react';
import { Box, Typography, Button, Paper } from '@mui/material';
import { Error as ErrorIcon, Refresh as RefreshIcon } from '@mui/icons-material';
import ErrorLogger from '../utils/errorLogger';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    this.setState({ error, errorInfo });
    ErrorLogger.logError(error, errorInfo, 'frontend');
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <Box sx={{ 
          minHeight: '100vh', 
          bgcolor: '#0a0a0a', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          p: 3
        }}>
          <Paper sx={{ 
            p: 4, 
            bgcolor: 'rgba(244,67,54,0.1)', 
            border: '2px solid #ff3b6b',
            borderRadius: 3,
            maxWidth: 500,
            textAlign: 'center'
          }}>
            <ErrorIcon sx={{ fontSize: 80, color: '#ff3b6b', mb: 2 }} />
            <Typography variant="h5" sx={{ color: '#ff3b6b', mb: 2, fontFamily: 'Share Tech Mono' }}>
              Something Went Wrong
            </Typography>
            <Typography variant="body2" sx={{ color: '#888', mb: 3 }}>
              An error occurred in the application. The error has been logged automatically.
            </Typography>
            
            {this.state.error && (
              <Box sx={{ 
                bgcolor: '#000', 
                p: 2, 
                borderRadius: 1, 
                mb: 3,
                textAlign: 'left',
                maxHeight: 150,
                overflow: 'auto'
              }}>
                <Typography variant="caption" sx={{ color: '#ff3b6b', fontFamily: 'monospace' }}>
                  {this.state.error.toString()}
                </Typography>
              </Box>
            )}
            
            <Button
              variant="contained"
              startIcon={<RefreshIcon />}
              onClick={this.handleReload}
              sx={{
                bgcolor: '#ff3b6b',
                '&:hover': { bgcolor: '#d32f2f' }
              }}
            >
              Reload Page
            </Button>
          </Paper>
        </Box>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
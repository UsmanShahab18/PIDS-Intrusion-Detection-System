import React, { useEffect, lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';

// Auth
import { AuthProvider, useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import LoginPage from './components/LoginPage';

// Components
import Navbar from './components/Navbar';
import LandingPage from './components/LandingPage';
import Dashboard from './components/Dashboard';
import Attacks from './components/Attacks';
import ModelRetraining from './components/ModelRetraining';
import SystemDiagnostics from './components/SystemDiagnostics';
import Architecture from './components/Architecture';
import AdminPanel from './components/AdminPanel';
import ProfileSettings from './components/ProfileSettings';
import TrainingViz from './components/TrainingViz';
import LiteratureAnalysis from './components/LiteratureAnalysis';
import Cyber3DBackground from './components/Cyber3DBackground';

// Scroll-driven Learn pages — animated scrollytelling per model stack.
// GnnLearn is disabled (no trained GNN model yet); re-import + re-add its
// route to bring the Graph page back.
import ClassicalLearn from './components/learn/ClassicalLearn';
import DeepLearn from './components/learn/DeepLearn';

// Error Logger
import ErrorLogger from './utils/errorLogger';
import PageLoader from './components/PageLoader';

// Design/motion demo page — code-split (lazy) to showcase Suspense.
const MotionDemo = lazy(() => import('./components/MotionDemo'));

import './App.css';

const darkTheme = createTheme({
  palette: { mode: 'dark' },
  typography: {
    // Professional, eye-friendly sizing (close to MUI defaults). The old
    // +12.5% bump made body copy feel oversized across the app.
    fontSize: 14,
    htmlFontSize: 16,
    body1: { fontSize: '0.88rem', lineHeight: 1.65 },
    body2: { fontSize: '0.8rem', lineHeight: 1.6 },
    button: { fontSize: '0.82rem' },
  },
});

// Inner app with auth-aware routing
const AppRoutes = () => {
  const { isAuthenticated, loading } = useAuth();
  const location = useLocation();

  // Hide navbar on landing page and login page
  const hideNavbar = location.pathname === '/' || location.pathname === '/login' || location.pathname === '/demo';

  // Hide the global rotating-sphere/torus-knot 3D backdrop on the
  // The animated Learn pages keep the global 3D background (their wrappers
  // are translucent so it shows through). Only /demo hides it.
  const hideGlobal3D = location.pathname === '/demo';

  return (
    <>
      {!hideGlobal3D && <Cyber3DBackground core={!location.pathname.startsWith('/learn')} />}
      {isAuthenticated && !hideNavbar && <Navbar />}

      <Routes>
        {/* Public routes */}
        <Route path="/login" element={
          isAuthenticated ? <Navigate to="/dashboard" replace /> : <LoginPage />
        } />

        {/* Landing page — public but shows login button if not authenticated */}
        <Route path="/" element={<LandingPage />} />

        {/* Public design/motion demo — preview before full-site rollout */}
        <Route path="/demo" element={
          <Suspense fallback={<PageLoader />}>
            <MotionDemo />
          </Suspense>
        } />

        {/* Protected routes — hidden navbar items based on role */}
        <Route path="/dashboard" element={
          <ProtectedRoute page="dashboard"><Dashboard /></ProtectedRoute>
        } />
        <Route path="/attacks" element={
          <ProtectedRoute page="threats"><Attacks /></ProtectedRoute>
        } />
        <Route path="/retraining" element={
          <ProtectedRoute page="retraining"><ModelRetraining /></ProtectedRoute>
        } />
        <Route path="/diagnostics" element={
          <ProtectedRoute page="diagnostics"><SystemDiagnostics /></ProtectedRoute>
        } />
        {/* Unified Learn experience — replaces the old Architecture
            and How-It-Works pages. GNN sub-page is fully built;
            Classical / Deep use a polished placeholder until Steps
            4 & 5 ship their scroll-driven content. */}
        <Route path="/learn" element={<Navigate to="/learn/classical" replace />} />
        {/* GNN learn page disabled — redirect to Classical until re-enabled. */}
        <Route path="/learn/gnn" element={<Navigate to="/learn/classical" replace />} />
        <Route path="/learn/deep" element={
          <ProtectedRoute page="architecture">
            <DeepLearn />
          </ProtectedRoute>
        } />
        <Route path="/learn/classical" element={
          <ProtectedRoute page="architecture">
            <ClassicalLearn />
          </ProtectedRoute>
        } />

        {/* Old routes redirect to the new unified Learn page. The
            original Architecture / TrainingViz components are kept
            in the codebase for now; they'll move to _deprecated/
            in Step 6 once Deep and Classical scenes ship. */}
        <Route path="/architecture" element={<Navigate to="/learn/classical" replace />} />
        <Route path="/how-it-works" element={<Navigate to="/learn/deep" replace />} />
        <Route path="/analysis" element={
          <ProtectedRoute><LiteratureAnalysis /></ProtectedRoute>
        } />
        {/* Zero-Day Scanner page removed — redirect any old link home. */}
        <Route path="/zero-day" element={<Navigate to="/dashboard" replace />} />
        <Route path="/admin" element={
          <ProtectedRoute page="admin_panel"><AdminPanel /></ProtectedRoute>
        } />
        <Route path="/profile" element={<ProfileSettings />} />

        {/* Catch-all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
};

function App() {
  useEffect(() => {
    ErrorLogger.init();
  }, []);

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      {/*
        Global Three.js background is mounted route-conditionally
        inside <AppRoutes/> so that /learn/* pages — which have
        their own per-stack 3D scenes — don't render two competing
        canvases at the same time.
      */}
      <Router>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </Router>
    </ThemeProvider>
  );
}

export default App;
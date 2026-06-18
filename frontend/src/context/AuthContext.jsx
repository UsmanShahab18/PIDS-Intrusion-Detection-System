import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { API_BASE } from '../config';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [setupRequired, setSetupRequired] = useState(false);

  // Store tokens in memory only (not localStorage — safer against XSS)
  const [tokens, setTokens] = useState(() => {
    // Restore from sessionStorage for tab persistence
    const saved = sessionStorage.getItem('pids_tokens');
    return saved ? JSON.parse(saved) : null;
  });

  // Save tokens to sessionStorage when they change
  useEffect(() => {
    if (tokens) {
      sessionStorage.setItem('pids_tokens', JSON.stringify(tokens));
    } else {
      sessionStorage.removeItem('pids_tokens');
    }
  }, [tokens]);

  // Axios interceptor — attach JWT to every request
  useEffect(() => {
    const interceptor = axios.interceptors.request.use(config => {
      if (tokens?.access) {
        config.headers.Authorization = `Bearer ${tokens.access}`;
      }
      return config;
    });
    return () => axios.interceptors.request.eject(interceptor);
  }, [tokens]);

  // Axios response interceptor — auto-refresh on 401
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      response => response,
      async error => {
        const originalRequest = error.config;
        if (error.response?.status === 401 && !originalRequest._retry && tokens?.refresh) {
          originalRequest._retry = true;
          try {
            const res = await axios.post(`${API_BASE}/auth/refresh/`, {
              refresh: tokens.refresh
            });
            const newTokens = { ...tokens, access: res.data.access };
            setTokens(newTokens);
            originalRequest.headers.Authorization = `Bearer ${res.data.access}`;
            return axios(originalRequest);
          } catch (refreshError) {
            // Refresh failed — force logout
            logout();
            return Promise.reject(refreshError);
          }
        }
        return Promise.reject(error);
      }
    );
    return () => axios.interceptors.response.eject(interceptor);
  }, [tokens]);

  // Check setup status + validate existing token on mount
  useEffect(() => {
    const init = async () => {
      try {
        // Check if setup is needed
        const setupRes = await axios.get(`${API_BASE}/auth/setup/check/`);
        setSetupRequired(setupRes.data.setup_required);

        // If we have tokens, validate them
        if (tokens?.access) {
          try {
            const meRes = await axios.get(`${API_BASE}/auth/me/`, {
              headers: { Authorization: `Bearer ${tokens.access}` }
            });
            setUser(meRes.data);
          } catch (err) {
            // Token invalid — try refresh
            if (tokens?.refresh) {
              try {
                const refRes = await axios.post(`${API_BASE}/auth/refresh/`, {
                  refresh: tokens.refresh
                });
                setTokens(prev => ({ ...prev, access: refRes.data.access }));
                const meRes = await axios.get(`${API_BASE}/auth/me/`, {
                  headers: { Authorization: `Bearer ${refRes.data.access}` }
                });
                setUser(meRes.data);
              } catch {
                logout();
              }
            } else {
              logout();
            }
          }
        }
      } catch (err) {
        console.log('Auth init error:', err.message);
      } finally {
        setLoading(false);
      }
    };
    init();
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await axios.post(`${API_BASE}/auth/login/`, { username, password });
    setTokens({ access: res.data.access, refresh: res.data.refresh });
    setUser(res.data.user);
    setSetupRequired(false);
    return res.data;
  }, []);

  const initialSetup = useCallback(async (data) => {
    const res = await axios.post(`${API_BASE}/auth/setup/`, data);
    setTokens({ access: res.data.access, refresh: res.data.refresh });
    setUser(res.data.user);
    setSetupRequired(false);
    return res.data;
  }, []);

  const logout = useCallback(() => {
    if (tokens?.access) {
      axios.post(`${API_BASE}/auth/logout/`, {}, {
        headers: { Authorization: `Bearer ${tokens.access}` }
      }).catch(() => {});
    }
    setUser(null);
    setTokens(null);
    sessionStorage.removeItem('pids_tokens');
    sessionStorage.removeItem('pids_seen_attacks');
  }, [tokens]);

  const hasPageAccess = useCallback((pageName) => {
    if (!user) return false;
    if (user.is_admin) return true;
    return user.pages?.[pageName] || false;
  }, [user]);

  const refreshUser = useCallback(async () => {
    if (tokens?.access) {
      try {
        const res = await axios.get(`${API_BASE}/auth/me/`, {
          headers: { Authorization: `Bearer ${tokens.access}` }
        });
        setUser(res.data);
      } catch (err) {
        console.log('Refresh user error:', err.message);
      }
    }
  }, [tokens]);

  const value = {
    user,
    loading,
    setupRequired,
    isAuthenticated: !!user,
    isAdmin: user?.is_admin || false,
    login,
    logout,
    initialSetup,
    hasPageAccess,
    refreshUser,
    tokens,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, getToken, setToken, setUnauthorizedHandler } from './api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expired, setExpired] = useState(false);

  const clear = useCallback(() => {
    setToken(null);
    setSession(null);
  }, []);

  // A 401 from any request drops the session exactly once, here.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSession((current) => {
        if (current) setExpired(true);
        return null;
      });
    });
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!getToken()) {
        setLoading(false);
        return;
      }
      try {
        const data = await api.me();
        if (!cancelled) setSession(data);
      } catch {
        clear();
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [clear]);

  const login = useCallback(async (email, password) => {
    const data = await api.login(email, password);
    setToken(data.access_token);
    setSession(data);
    setExpired(false);
    return data;
  }, []);

  const loginWithToken = useCallback(async (token) => {
    setToken(token);
    const data = await api.me();
    setSession(data);
    setExpired(false);
    return data;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* the token may already be invalid; clearing locally is what matters */
    }
    clear();
  }, [clear]);

  const value = useMemo(() => {
    const capabilities = session?.capabilities || [];
    return {
      session,
      user: session?.user || null,
      role: session?.user?.role || null,
      roleLabel: session?.role_label || null,
      capabilities,
      can: (capability) => capabilities.includes(capability),
      canAny: (...list) => list.some((c) => capabilities.includes(c)),
      isAdmin: session?.user?.role === 'admin',
      isViewer: session?.user?.role === 'viewer',
      loading,
      expired,
      dismissExpired: () => setExpired(false),
      login,
      loginWithToken,
      logout,
    };
  }, [session, loading, expired, login, loginWithToken, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>');
  return context;
}

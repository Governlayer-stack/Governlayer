import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem('gl_token'));
  const [email, setEmail] = useState(() => localStorage.getItem('gl_email'));

  const login = useCallback((newToken, newEmail) => {
    localStorage.setItem('gl_token', newToken);
    localStorage.setItem('gl_email', newEmail);
    setToken(newToken);
    setEmail(newEmail);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('gl_token');
    localStorage.removeItem('gl_email');
    setToken(null);
    setEmail(null);
  }, []);

  useEffect(() => {
    const handler = () => logout();
    window.addEventListener('gl:logout', handler);
    return () => window.removeEventListener('gl:logout', handler);
  }, [logout]);

  return (
    <AuthContext.Provider value={{ token, email, isAuthenticated: !!token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

export function RequireAuth({ children }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!isAuthenticated) {
    return <RedirectToLogin from={location.pathname} />;
  }

  return children;
}

function RedirectToLogin({ from }) {
  const navigate = useNavigate();
  useEffect(() => {
    navigate('/login', { state: { from }, replace: true });
  }, [navigate, from]);
  return null;
}

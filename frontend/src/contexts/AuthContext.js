import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('schiro_token'));
  const [loading, setLoading] = useState(true);

  const validateToken = useCallback(async () => {
    if (!token) { setLoading(false); return; }
    try {
      const res = await axios.get(`${API}/auth/me`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUser(res.data);
    } catch {
      localStorage.removeItem('schiro_token');
      setToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { validateToken(); }, [validateToken]);

  const login = async (key) => {
    // TEMP BYPASS - remove later
    localStorage.setItem('schiro_token', 'bypass-token');
    setToken('bypass-token');
    setUser({ id: 'bypass', label: 'Bypass Master', is_master: true });
    return { token: 'bypass-token', user: { id: 'bypass', is_master: true } };
  };

  const logout = async () => {
    try {
      if (token) {
        await axios.post(`${API}/auth/logout`, {}, {
          headers: { Authorization: `Bearer ${token}` }
        });
      }
    } catch { /* ignore */ }
    localStorage.removeItem('schiro_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

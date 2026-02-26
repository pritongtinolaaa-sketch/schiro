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
  // TEMP BYPASS - remove later when DB/auth fixed
  console.log("Bypass login triggered with key:", key);

  // Generate a fake but signed JWT token (same format as backend)
  // This uses a dummy JWT_SECRET - in real backend it's from env
  // For testing, use a constant secret (change to your real JWT_SECRET if you know it)
  const dummySecret = "dummy-jwt-secret-for-bypass-2026"; // change this to match your JWT_SECRET if known

  const payload = {
    key_id: "bypass-id",
    session_id: "bypass-session-" + Date.now(),
    is_master: true,
    exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7) // 7 days
  };

  // Simple JWT encode (you can use jwt-encode lib if installed, but for bypass use this manual)
  // Note: This is NOT secure - only for local testing bypass
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const signature = btoa("dummy-signature"); // fake sig - backend will reject unless you bypass validation too

  const fakeToken = `${header}.${body}.${signature}`;

    localStorage.setItem('schiro_token', fakeToken);
    setToken(fakeToken);
    setUser({ id: 'bypass', label: 'Bypass Master', is_master: true });

    return { token: fakeToken, user: { id: 'bypass', is_master: true } };
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

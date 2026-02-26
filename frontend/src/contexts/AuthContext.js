import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

// TEMP: Hardcode API base (adjust if your backend path changes)
const API = '/api';  // or '/api' if prefix is different

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState({
    id: 'bypass',
    label: 'Bypass Master',
    is_master: true
  });
  const [token, setToken] = useState('bypass-token');
  const [loading, setLoading] = useState(false); // Skip loading

  // Skip real token validation - we're always "logged in"
  useEffect(() => {
    // Force bypass state on mount
    localStorage.setItem('schiro_token', 'bypass-token');
    setToken('bypass-token');
    setUser({ id: 'bypass', label: 'Bypass Master', is_master: true });
    setLoading(false);
  }, []);

  const login = async (key) => {
    // Completely ignore key - always succeed
    console.log("Bypass login triggered (key ignored):", key);

    const fakeToken = 'bypass-token';

    localStorage.setItem('schiro_token', fakeToken);
    setToken(fakeToken);
    setUser({ id: 'bypass', label: 'Bypass Master', is_master: true });

    return { token: fakeToken, user: { id: 'bypass', is_master: true } };
  };

  const logout = async () => {
    // Optional: clear state but stay bypassed
    localStorage.removeItem('schiro_token');
    setToken(null);
    setUser(null);
  };

  // Return always-authenticated context
  return (
    <AuthContext.Provider value={{ user, token, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { gateway } from '../api/client';
import { type Role, getPermissions, type Permission } from './roles';

interface User {
  username: string;
  role: Role;
}

interface AuthState {
  user: User | null;
  permissions: Permission;
  isAuthenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  loginWithApiKey: (apiKey: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    const stored = localStorage.getItem('btv_user');
    return stored ? JSON.parse(stored) : null;
  });

  const permissions = getPermissions(user?.role ?? 'viewer');
  const isAuthenticated = user !== null;

  const login = useCallback(async (username: string, password: string) => {
    const { data } = await gateway.post('/v1/auth/login', { username, password });
    localStorage.setItem('btv_token', data.token);
    const u: User = { username: data.username, role: data.role };
    localStorage.setItem('btv_user', JSON.stringify(u));
    setUser(u);
  }, []);

  const loginWithApiKey = useCallback(async (apiKey: string) => {
    localStorage.setItem('btv_api_key', apiKey);
    // Verify key works by calling health
    await gateway.get('/health');
    const u: User = { username: 'api-user', role: 'admin' };
    localStorage.setItem('btv_user', JSON.stringify(u));
    setUser(u);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('btv_token');
    localStorage.removeItem('btv_api_key');
    localStorage.removeItem('btv_user');
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, permissions, isAuthenticated, login, loginWithApiKey, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be inside AuthProvider');
  return ctx;
}

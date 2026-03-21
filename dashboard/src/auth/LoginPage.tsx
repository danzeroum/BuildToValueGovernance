import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

export default function LoginPage() {
  const { login, loginWithApiKey } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<'jwt' | 'apikey'>('apikey');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'jwt') {
        await login(username, password);
      } else {
        await loginWithApiKey(apiKey);
      }
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-xl shadow-lg p-8">
        <h1 className="text-2xl font-bold text-center mb-2">BuildToValue</h1>
        <p className="text-sm text-gray-500 text-center mb-6">Sovereign Trust OS</p>

        <div className="flex mb-6 border rounded-lg overflow-hidden">
          <button
            type="button"
            className={`flex-1 py-2 text-sm font-medium ${mode === 'apikey' ? 'bg-btv-600 text-white' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'}`}
            onClick={() => setMode('apikey')}
          >
            API Key
          </button>
          <button
            type="button"
            className={`flex-1 py-2 text-sm font-medium ${mode === 'jwt' ? 'bg-btv-600 text-white' : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'}`}
            onClick={() => setMode('jwt')}
          >
            Username / Password
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === 'jwt' ? (
            <>
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
                required
              />
            </>
          ) : (
            <input
              type="password"
              placeholder="API Key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="w-full px-3 py-2 border rounded-lg dark:bg-gray-700 dark:border-gray-600"
              required
            />
          )}

          {error && <p className="text-red-500 text-sm">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-btv-600 text-white rounded-lg font-medium hover:bg-btv-700 disabled:opacity-50"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

import React, { useState } from 'react';
import { Shield, ShieldAlert, Lock, User, RefreshCw, CheckCircle2 } from 'lucide-react';

interface AuthProps {
  onSuccess: (username: string) => void;
}

export const Auth: React.FC<AuthProps> = ({ onSuccess }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      if (isLogin) {
        onSuccess(data.username);
      } else {
        setIsLogin(true);
        setError('Registration successful! Please login.');
        setUsername('');
        setPassword('');
      }
    } catch (err: any) {
      setError(err.message || 'Server error, please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1.5rem', background: 'var(--bg-main)' }}>
      <div className="card" style={{ width: '100%', maxWidth: '400px', backgroundColor: '#111726', border: '1px solid #1e293b', borderRadius: '8px' }}>
        
        {/* Brand Header */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            background: 'rgba(59, 130, 246, 0.12)',
            padding: '0.85rem',
            borderRadius: '12px',
            border: '1px solid rgba(59, 130, 246, 0.25)',
            marginBottom: '0.85rem'
          }}>
            <Shield size={32} style={{ color: '#3b82f6' }} />
          </div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--text-primary)', textAlign: 'center', letterSpacing: '-0.01em' }}>
            NEXUS SECURITY OPERATIONS
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Enterprise Threat Detection & Active IPS Portal
          </p>
        </div>

        {error && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            background: error.includes('successful') ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${error.includes('successful') ? 'var(--status-normal-border)' : 'var(--status-danger-border)'}`,
            color: error.includes('successful') ? 'var(--status-normal)' : 'var(--status-danger)',
            padding: '0.65rem 0.85rem',
            borderRadius: '6px',
            fontSize: '0.8rem',
            marginBottom: '1rem'
          }}>
            {error.includes('successful') ? <CheckCircle2 size={16} /> : <ShieldAlert size={16} />}
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="username">OPERATOR USERNAME</label>
            <div style={{ position: 'relative' }}>
              <User size={15} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                id="username"
                type="text"
                className="form-input"
                style={{ paddingLeft: '2.1rem' }}
                placeholder="e.g. admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                disabled={loading}
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label" htmlFor="password">ACCESS PASSWORD</label>
            <div style={{ position: 'relative' }}>
              <Lock size={15} style={{ position: 'absolute', left: '10px', top: '10px', color: 'var(--text-muted)' }} />
              <input
                id="password"
                type="password"
                className="form-input"
                style={{ paddingLeft: '2.1rem' }}
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
              />
            </div>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', marginTop: '0.5rem', padding: '0.6rem 1rem' }}
            disabled={loading}
          >
            {loading ? (
              <RefreshCw className="animate-spin" size={16} />
            ) : isLogin ? (
              'SIGN IN TO SOC PORTAL'
            ) : (
              'CREATE OPERATOR ACCOUNT'
            )}
          </button>
        </form>

        <div style={{ marginTop: '1.25rem', textAlign: 'center' }}>
          <button
            onClick={() => {
              setIsLogin(!isLogin);
              setError('');
            }}
            style={{
              background: 'none',
              border: 'none',
              color: '#3b82f6',
              fontSize: '0.8rem',
              cursor: 'pointer',
              fontWeight: 500
            }}
            disabled={loading}
          >
            {isLogin ? "Need a new account? Register here" : "Already registered? Sign in"}
          </button>
        </div>
      </div>
    </div>
  );
};

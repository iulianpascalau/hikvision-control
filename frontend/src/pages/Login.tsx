import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { login } from '../api';

export const Login: React.FC = () => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username || !password) {
      setError('Please fill in all fields');
      return;
    }

    try {
      setIsLoading(true);
      setError('');
      
      const token = await login(username, password);
      
      localStorage.setItem('auth_token', token);
      
      navigate('/');
    } catch (err: any) {
      const errorMsg = err.response?.data?.error || err.message || 'Login failed. Check credentials.';
      setError(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px' }}>
      <main style={{ maxWidth: '400px', width: '100%' }}>
        
        <header style={{ textAlign: 'center', marginBottom: '40px' }} className="animate-fade-in">
          <Shield color="var(--primary)" size={48} style={{ marginBottom: '16px' }} />
          <h1 style={{ fontSize: '36px', fontWeight: 800, marginBottom: '8px', letterSpacing: '0.5px' }}>
            Unifi Control
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '18px', letterSpacing: '1px' }}>
            Secure Access Panel
          </p>
        </header>

        <form onSubmit={handleLogin} className="glass-card animate-fade-in" style={{ animationDelay: '0.1s' }}>
          {error && <div className="error-msg" style={{ marginBottom: '20px' }}>{error}</div>}
          
          <input
            className="input-field"
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
          
          <input
            className="input-field"
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />

          <button type="submit" className="btn-primary" disabled={isLoading} style={{ marginTop: '12px' }}>
            {isLoading ? 'Authenticating...' : 'Authenticate'}
          </button>
        </form>

      </main>
    </div>
  );
};

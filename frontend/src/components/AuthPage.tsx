import React, { FormEvent, useState } from 'react';
import { LockKeyhole, ShieldCheck } from 'lucide-react';
import { authApi } from '../services/auth';

type AuthMode = 'login' | 'register' | 'setup' | 'configuration';

interface AuthPageProps {
  mode: AuthMode;
  onAuthenticated: () => void;
  onRetry: () => void;
  onModeChange: (mode: 'login' | 'register') => void;
}

export const AuthPage: React.FC<AuthPageProps> = ({ mode, onAuthenticated, onRetry, onModeChange }) => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const isSetup = mode === 'setup';
  const isRegister = mode === 'register';

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    if (isRegister && password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setSubmitting(true);
    try {
      if (isSetup) {
        await authApi.bootstrap(username, email, password);
      } else if (isRegister) {
        await authApi.register(username, email, password);
      } else {
        await authApi.login(username, password);
      }
      onAuthenticated();
    } catch (requestError: any) {
      setError(requestError.message || 'Unable to authenticate');
    } finally {
      setSubmitting(false);
    }
  };

  if (mode === 'configuration') {
    return (
      <main className="min-h-screen bg-radial-gradient cyber-grid-bg text-slate-100 flex items-center justify-center p-6">
        <section className="glass-panel max-w-lg w-full p-8 text-center space-y-6 border-amber-500/30 shadow-[0_0_40px_rgba(245,158,11,0.15)]">
          <div className="w-16 h-16 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center mx-auto shadow-[0_0_20px_rgba(245,158,11,0.25)]">
            <LockKeyhole className="w-8 h-8 text-amber-400" />
          </div>
          <h1 className="text-2xl font-heading font-extrabold text-white tracking-wide">AUTHENTICATION CONFIGURATION</h1>
          <p className="text-slate-400 text-sm">Set a unique <code className="code-pill text-amber-300">JWT_SECRET</code> with at least 32 characters in <code className="code-pill">.env</code>, then restart the backend.</p>
          <button onClick={onRetry} className="btn-cyber-primary w-full py-3">
            RETRY CONNECTION
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-radial-gradient cyber-grid-bg text-slate-100 flex items-center justify-center p-6">
      <section className="glass-panel max-w-md w-full p-8 space-y-6 border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.12)]">
        <div className="text-center space-y-3">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-emerald-500/20 border border-cyan-500/40 flex items-center justify-center mx-auto shadow-[0_0_25px_rgba(6,182,212,0.35)]">
            <ShieldCheck className="w-9 h-9 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-heading font-extrabold tracking-wider text-white">
              SOC <span className="text-emerald-400">CHESS</span>
            </h1>
            <p className="text-xs font-mono text-cyan-400 uppercase tracking-widest mt-0.5">Autonomous Security Operations</p>
          </div>
          <p className="text-slate-400 text-xs">{isSetup ? 'Initialize the primary administrator account.' : isRegister ? 'Create an analyst account for the security operations console.' : 'Sign in to the autonomous security console.'}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block text-xs font-heading font-bold text-slate-300 uppercase tracking-wider">
            Username
            <input value={username} onChange={(event) => setUsername(event.target.value)} required minLength={3}
              placeholder="e.g. analyst_lead"
              className="mt-1.5 w-full rounded-lg bg-slate-950/90 border border-white/10 px-3.5 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500 font-mono" />
          </label>
          {(isSetup || isRegister) && (
            <label className="block text-xs font-heading font-bold text-slate-300 uppercase tracking-wider">
              Email
              <input value={email} onChange={(event) => setEmail(event.target.value)} required type="email"
                placeholder="analyst@socchess.local"
                className="mt-1.5 w-full rounded-lg bg-slate-950/90 border border-white/10 px-3.5 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500 font-mono" />
            </label>
          )}
          <label className="block text-xs font-heading font-bold text-slate-300 uppercase tracking-wider">
            Password
            <input value={password} onChange={(event) => setPassword(event.target.value)} required type="password" minLength={isRegister || isSetup ? 12 : 1}
              placeholder="••••••••••••"
              className="mt-1.5 w-full rounded-lg bg-slate-950/90 border border-white/10 px-3.5 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500 font-mono" />
          </label>
          {isRegister && (
            <label className="block text-xs font-heading font-bold text-slate-300 uppercase tracking-wider">
              Confirm password
              <input value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} required type="password" minLength={12}
                placeholder="••••••••••••"
                className="mt-1.5 w-full rounded-lg bg-slate-950/90 border border-white/10 px-3.5 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-500 font-mono" />
            </label>
          )}
          {isSetup && <p className="text-[11px] text-slate-500 font-mono">Use at least 12 characters. Setup is only available from the local machine.</p>}
          {error && <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">{error}</p>}
          <button disabled={submitting} className="btn-cyber-primary w-full py-3 text-xs tracking-wider">
            {submitting ? 'AUTHENTICATING...' : isSetup ? 'CREATE ADMINISTRATOR' : isRegister ? 'REGISTER ACCOUNT' : 'SECURE SIGN IN'}
          </button>
        </form>
        {!isSetup && (
          <button type="button" onClick={() => onModeChange(isRegister ? 'login' : 'register')} className="w-full text-xs font-mono text-cyan-400 hover:text-cyan-300 text-center transition-colors">
            {isRegister ? 'Already have an account? Sign in' : 'Need an analyst account? Register'}
          </button>
        )}
      </section>
    </main>
  );
};

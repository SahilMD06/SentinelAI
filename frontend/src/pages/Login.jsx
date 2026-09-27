import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogoMark, Wordmark } from '../components/Logo';
import { Button, Spinner, cx } from '../components/ui';
import { IconChevron, IconLock, IconMoon, IconSun } from '../components/icons';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useTheme } from '../lib/theme';

const ROLE_TONE = {
  admin: 'text-critical border-critical/30 bg-critical/8',
  manager: 'text-high border-high/30 bg-high/8',
  analyst: 'text-accent border-accent/30 bg-accent/8',
  viewer: 'text-ink-2 border-line bg-sunken',
};

export default function Login() {
  const { login, expired, dismissExpired } = useAuth();
  const { theme, toggle } = useTheme();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [demo, setDemo] = useState(null);
  const [sso, setSso] = useState(null);

  useEffect(() => {
    api.demoAccounts().then(setDemo).catch(() => setDemo(null));
    api.ssoConfig().then(setSso).catch(() => setSso(null));
  }, []);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    dismissExpired();
    try {
      await login(email.trim(), password);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message || 'Sign-in failed');
    } finally {
      setBusy(false);
    }
  };

  const applyAccount = (account) => {
    setEmail(account.email);
    setPassword(account.password);
    setError(null);
  };

  return (
    <div className="min-h-screen flex flex-col bg-canvas">
      <header className="h-14 shrink-0 flex items-center justify-between px-5 border-b border-line bg-surface">
        <div className="flex items-center gap-2.5">
          <LogoMark size={24} />
          <Wordmark className="text-[15px]" />
        </div>
        <button
          type="button"
          onClick={toggle}
          className="btn-ghost btn-sm px-1.5"
          aria-label="Toggle theme"
        >
          {theme === 'dark' ? <IconSun size={15} /> : <IconMoon size={15} />}
        </button>
      </header>

      <main className="flex-1 flex items-start justify-center px-4 py-10 sm:py-14">
        <div className="w-full max-w-[860px] grid lg:grid-cols-[380px_1fr] gap-6 items-start">
          {/* ---------------------------------------------------- Sign-in card */}
          <div className="panel p-6">
            <div className="flex flex-col items-center text-center mb-6">
              <LogoMark size={44} />
              <h1 className="text-lg font-semibold text-ink mt-3">Sign in to SentinelAI</h1>
              <p className="text-xs text-ink-3 mt-1">
                Security Operations Console
              </p>
            </div>

            {expired && (
              <div className="mb-4 px-3 py-2 rounded border border-medium/30 bg-medium/8 text-xs text-medium">
                Your session expired. Sign in again to continue.
              </div>
            )}

            <form onSubmit={submit} className="space-y-3.5">
              <label className="flex flex-col gap-1.5">
                <span className="text-xs font-medium text-ink-2">Work email</span>
                <input
                  type="email"
                  required
                  autoComplete="username"
                  autoFocus
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@sentinelai.io"
                  className="field h-9"
                />
              </label>

              <label className="flex flex-col gap-1.5">
                <span className="text-xs font-medium text-ink-2">Password</span>
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="••••••••••"
                  className="field h-9"
                />
              </label>

              {error && (
                <div
                  role="alert"
                  className="px-3 py-2 rounded border border-critical/30 bg-critical/8 text-xs text-critical"
                >
                  {error}
                </div>
              )}

              <button type="submit" className="btn-primary w-full h-9" disabled={busy}>
                {busy ? <Spinner /> : null}
                {busy ? 'Verifying…' : 'Sign in'}
              </button>
            </form>

            {sso?.enabled && (
              <>
                <div className="flex items-center gap-3 my-4">
                  <span className="flex-1 divider" />
                  <span className="text-2xs text-ink-3 uppercase tracking-wider">or</span>
                  <span className="flex-1 divider" />
                </div>
                <a
                  href={api.ssoLoginUrl(email || undefined)}
                  className="btn-secondary w-full h-9"
                >
                  Continue with {sso.provider}
                  <IconChevron size={13} />
                </a>
                <p className="text-2xs text-ink-3 mt-2 text-center leading-relaxed">
                  {sso.mode === 'mock-idp'
                    ? 'Mock IdP — exercises the full OAuth2 authorisation-code round trip locally.'
                    : 'Federated sign-in via your organisation identity provider.'}
                </p>
              </>
            )}

            <div className="mt-6 pt-4 border-t border-line space-y-2">
              <p className="flex items-start gap-2 text-2xs text-ink-3 leading-relaxed">
                <IconLock size={12} className="mt-px shrink-0" />
                Self-registration is disabled. Accounts are provisioned by an administrator
                through User Management.
              </p>
              <p className="text-2xs text-ink-3 leading-relaxed">
                This system is monitored. All authentication attempts, queries and case actions
                are recorded in the audit log. Unauthorised access is prohibited.
              </p>
            </div>
          </div>

          {/* -------------------------------------------------- Demo accounts */}
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">Evaluation accounts</h2>
                <p className="text-2xs text-ink-3 mt-px">
                  Select an account to prefill the form — each role sees a different console
                </p>
              </div>
            </div>

            <div className="p-3 grid sm:grid-cols-2 gap-2">
              {(demo?.accounts || []).map((account) => (
                <button
                  key={account.email}
                  type="button"
                  onClick={() => applyAccount(account)}
                  className={cx(
                    'text-left rounded-md border border-line bg-surface p-3',
                    'hover:border-accent/50 hover:bg-accent/[0.03] transition-colors duration-120',
                    email === account.email && 'border-accent bg-accent/[0.05]',
                  )}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className={cx('badge border', ROLE_TONE[account.role])}>
                      {account.label}
                    </span>
                    <span className="text-2xs text-ink-3">{account.name}</span>
                  </div>
                  <p className="font-mono text-2xs text-ink truncate">{account.email}</p>
                  <p className="font-mono text-2xs text-ink-3">{account.password}</p>
                  <p className="text-2xs text-ink-2 mt-1.5 leading-relaxed">{account.blurb}</p>
                </button>
              ))}

              {!demo && (
                <div className="sm:col-span-2 py-8 flex items-center justify-center gap-2 text-xs text-ink-3">
                  <Spinner /> Loading evaluation accounts…
                </div>
              )}
            </div>

            {demo?.notice && (
              <p className="px-4 pb-4 text-2xs text-ink-3 leading-relaxed">{demo.notice}</p>
            )}
          </div>
        </div>
      </main>

      <footer className="shrink-0 px-5 py-3 border-t border-line text-2xs text-ink-3 flex flex-wrap items-center justify-between gap-2">
        <span>SentinelAI · Intelligent SecOps &amp; Threat Response</span>
        <span className="flex items-center gap-3">
          <span>bcrypt + JWT</span>
          <span>·</span>
          <span>RBAC enforced server-side</span>
          <span>·</span>
          <span>ISO 27001 / SOC 2 aligned</span>
        </span>
      </footer>
    </div>
  );
}

export function SsoCallback() {
  const { loginWithToken } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
    const token = params.get('token');
    if (!token) {
      setError('The identity provider did not return a token.');
      return;
    }
    loginWithToken(token)
      .then(() => navigate('/', { replace: true }))
      .catch((err) => setError(err.message || 'Federated sign-in failed'));
  }, [loginWithToken, navigate]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center gap-3 bg-canvas">
      <LogoMark size={36} />
      {error ? (
        <>
          <p className="text-sm text-critical">{error}</p>
          <Button onClick={() => navigate('/login', { replace: true })}>Back to sign in</Button>
        </>
      ) : (
        <p className="flex items-center gap-2 text-sm text-ink-2">
          <Spinner /> Completing federated sign-in…
        </p>
      )}
    </div>
  );
}

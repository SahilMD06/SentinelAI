import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Tooltip, cx } from './ui';
import { IconChevronDown, IconLogout, IconMoon, IconSearch, IconSun } from './icons';
import { useTheme } from '../lib/theme';
import { useAuth } from '../lib/auth';
import { initials } from '../lib/format';

export default function Topbar({ title, subtitle, actions, health }) {
  const { theme, toggle } = useTheme();
  const { user, roleLabel, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [query, setQuery] = useState('');
  const menuRef = useRef(null);
  const searchRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const onClick = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) setMenuOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  // ⌘K / Ctrl-K focuses global search, the convention every SOC analyst already
  // has in muscle memory from Splunk and Datadog.
  useEffect(() => {
    const onKey = (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);

  const submitSearch = (event) => {
    event.preventDefault();
    const term = query.trim();
    if (!term) return;
    if (/^(INC|SIM)-\d{4}-\d+$/i.test(term)) navigate(`/incidents?ref=${term.toUpperCase()}`);
    else navigate(`/hunt?q=${encodeURIComponent(term)}`);
    setQuery('');
  };

  const statusTone =
    health?.status === 'healthy' ? 'bg-success' : health?.status ? 'bg-medium' : 'bg-ink-3';

  return (
    <header className="h-[52px] shrink-0 border-b border-line bg-surface flex items-center gap-3 px-4">
      <div className="min-w-0 flex-1">
        <h1 className="text-md font-semibold text-ink leading-tight truncate">{title}</h1>
        {subtitle && <p className="text-2xs text-ink-3 truncate leading-tight">{subtitle}</p>}
      </div>

      <form onSubmit={submitSearch} className="relative hidden md:block w-[260px] shrink-0">
        <IconSearch size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3 pointer-events-none" />
        <input
          ref={searchRef}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search cases, IPs, hosts…"
          className="field pl-8 pr-11"
          aria-label="Global search"
        />
        <span className="kbd absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none">⌘K</span>
      </form>

      {actions && <div className="flex items-center gap-1.5 shrink-0">{actions}</div>}

      <Tooltip
        label={
          health
            ? `Platform ${health.status} · ${health.database?.engine} · v${health.version}`
            : 'Checking platform health'
        }
      >
        <span className="hidden lg:inline-flex items-center gap-1.5 h-8 px-2 rounded border border-line text-2xs text-ink-2">
          <span className={cx('w-1.5 h-1.5 rounded-full', statusTone)} />
          {health?.status || 'checking'}
        </span>
      </Tooltip>

      <Tooltip label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}>
        <Button variant="ghost" size="sm" onClick={toggle} aria-label="Toggle theme" className="px-1.5">
          {theme === 'dark' ? <IconSun size={15} /> : <IconMoon size={15} />}
        </Button>
      </Tooltip>

      <div className="relative shrink-0" ref={menuRef}>
        <button
          type="button"
          onClick={() => setMenuOpen((open) => !open)}
          className="flex items-center gap-1.5 h-8 pl-1 pr-1.5 rounded hover:bg-sunken transition-colors duration-120"
          aria-haspopup="menu"
          aria-expanded={menuOpen}
        >
          <span className="w-6 h-6 rounded-full bg-accent/15 text-accent text-2xs font-semibold flex items-center justify-center">
            {initials(user?.full_name)}
          </span>
          <IconChevronDown size={13} className="text-ink-3" />
        </button>

        {menuOpen && (
          <div
            role="menu"
            className="absolute right-0 top-full mt-1.5 w-60 bg-raised border border-line-strong rounded-md shadow-pop z-50 animate-slide-up overflow-hidden"
          >
            <div className="px-3 py-2.5 border-b border-line">
              <p className="text-sm font-medium text-ink truncate">{user?.full_name}</p>
              <p className="text-2xs text-ink-3 truncate">{user?.email}</p>
              <div className="flex items-center gap-1.5 mt-1.5">
                <span className="badge badge-outline">{roleLabel}</span>
                {user?.auth_provider === 'oidc' && <span className="badge badge-outline">SSO</span>}
              </div>
            </div>
            <div className="px-3 py-2 border-b border-line text-2xs text-ink-3 space-y-1">
              <div className="flex justify-between gap-2">
                <span>Team</span>
                <span className="text-ink-2 truncate">{user?.team}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span>MFA</span>
                <span className="text-ink-2">{user?.mfa_enrolled ? 'Enrolled' : 'Not enrolled'}</span>
              </div>
            </div>
            <button
              type="button"
              role="menuitem"
              onClick={logout}
              className="w-full flex items-center gap-2 px-3 h-9 text-sm text-ink-2 hover:bg-sunken hover:text-ink transition-colors duration-120"
            >
              <IconLogout size={14} />
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}

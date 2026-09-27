import { useState } from 'react';
import { Button, Panel, cx, useToast } from '../components/ui';
import { IconMoon, IconRefresh, IconShieldCheck, IconSun } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { useTheme } from '../lib/theme';
import { formatFullDate, initials } from '../lib/format';

export default function Settings() {
  const { user, roleLabel, capabilities, can } = useAuth();
  const { theme, setTheme } = useTheme();
  const toast = useToast();
  const [reindexing, setReindexing] = useState(false);

  const meta = useAsync(() => api.meta(), []);
  const health = useAsync(() => api.health(), []);
  const status = useAsync(() => api.ragStatus(), []);
  const intel = useAsync(() => api.intelStatus(), []);

  const reindex = async () => {
    setReindexing(true);
    try {
      const res = await api.ragReindex();
      toast.success(`Knowledge base reindexed — ${res.documents ?? 'index'} document(s).`);
      status.refresh();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setReindexing(false);
    }
  };

  return (
    <div className="p-4 space-y-4 max-w-4xl">
      <Panel title="Profile" dense bodyClass="p-4">
        <div className="flex items-center gap-3">
          <span className="w-11 h-11 rounded-full bg-accent/15 text-accent text-sm font-semibold flex items-center justify-center shrink-0">
            {initials(user?.full_name)}
          </span>
          <div className="min-w-0">
            <p className="text-sm font-medium text-ink truncate">{user?.full_name}</p>
            <p className="text-xs text-ink-3 truncate">{user?.email}</p>
          </div>
          <span className="badge badge-outline ml-auto">{roleLabel}</span>
        </div>
        <div className="grid sm:grid-cols-3 gap-3 mt-4 pt-4 border-t border-line text-xs">
          <Row label="Team" value={user?.team} />
          <Row label="Job title" value={user?.job_title} />
          <Row label="Auth provider" value={user?.auth_provider === 'oidc' ? 'SSO (OIDC)' : 'Email + password'} />
          <Row label="MFA" value={user?.mfa_enrolled ? 'Enrolled' : 'Not enrolled'} />
          <Row label="Last sign-in" value={user?.last_login_at ? formatFullDate(user.last_login_at) : 'This session'} />
          <Row label="Account created" value={user?.created_at ? formatFullDate(user.created_at) : '—'} />
        </div>
      </Panel>

      <Panel title="Appearance" dense bodyClass="p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-ink">Theme</p>
            <p className="text-2xs text-ink-3 mt-0.5">Persisted to this browser.</p>
          </div>
          <div className="flex items-center gap-1 p-0.5 rounded border border-line bg-surface">
            <button
              type="button"
              onClick={() => setTheme('light')}
              className={cx(
                'h-7 px-3 rounded text-xs font-medium flex items-center gap-1.5 transition-colors duration-120',
                theme === 'light' ? 'bg-accent/12 text-accent' : 'text-ink-3 hover:text-ink hover:bg-sunken',
              )}
            >
              <IconSun size={13} /> Light
            </button>
            <button
              type="button"
              onClick={() => setTheme('dark')}
              className={cx(
                'h-7 px-3 rounded text-xs font-medium flex items-center gap-1.5 transition-colors duration-120',
                theme === 'dark' ? 'bg-accent/12 text-accent' : 'text-ink-3 hover:text-ink hover:bg-sunken',
              )}
            >
              <IconMoon size={13} /> Dark
            </button>
          </div>
        </div>
      </Panel>

      <Panel title="Access & capabilities" dense bodyClass="p-4">
        <p className="text-2xs text-ink-3 mb-2">
          Capabilities are enforced server-side; this list mirrors exactly what your role grants.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {capabilities.length ? (
            capabilities.map((c) => (
              <span key={c} className="chip font-mono">{c}</span>
            ))
          ) : (
            <span className="text-xs text-ink-3">No capabilities granted.</span>
          )}
        </div>
      </Panel>

      <Panel title="Platform status" dense bodyClass="p-4">
        <div className="grid sm:grid-cols-2 gap-3 text-xs">
          <Row label="Version" value={meta.data?.version} />
          <Row label="Environment" value={meta.data?.environment || 'development'} />
          <Row label="Database" value={health.data?.database?.engine} />
          <Row
            label="Health"
            value={health.data?.status}
            valueClass={health.data?.status === 'healthy' ? 'text-success' : 'text-medium'}
          />
          <Row label="Knowledge base" value={status.data ? `${status.data.documents} documents · ${status.data.vector_backend}` : '—'} />
          <Row label="Threat intel" value={intel.data?.intel?.mode === 'live' ? 'Live providers' : 'Offline heuristic'} />
        </div>
        {can('settings:write') && (
          <div className="mt-4 pt-3 border-t border-line flex items-center justify-between">
            <div>
              <p className="text-xs text-ink-2">Rebuild the RAG index from current knowledge-base documents</p>
              <p className="text-2xs text-ink-3 mt-0.5">Run after bulk edits to playbooks or reference material.</p>
            </div>
            <Button size="sm" icon={IconRefresh} onClick={reindex} disabled={reindexing}>
              {reindexing ? 'Reindexing…' : 'Reindex'}
            </Button>
          </div>
        )}
      </Panel>

      <Panel title="About" dense bodyClass="p-4">
        <div className="flex items-start gap-2.5 text-xs text-ink-2 leading-relaxed">
          <IconShieldCheck size={15} className="text-ink-3 shrink-0 mt-0.5" />
          <p>
            SentinelAI is an intelligent SecOps &amp; threat response console: a nine-agent
            investigation pipeline, hybrid semantic search over MITRE ATT&amp;CK and internal
            playbooks, behavioural anomaly detection, and ISO 27001 / SOC 2 compliance tracking —
            all enforced through server-side, capability-based RBAC.
          </p>
        </div>
      </Panel>
    </div>
  );
}

function Row({ label, value, valueClass }) {
  return (
    <div className="flex items-center justify-between gap-2 py-1">
      <span className="text-ink-3">{label}</span>
      <span className={cx('text-ink text-right truncate max-w-[60%] capitalize', valueClass)}>
        {value || '—'}
      </span>
    </div>
  );
}

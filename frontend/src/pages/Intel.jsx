import { useState } from 'react';
import { Button, Empty, Panel, Spinner, cx, useToast } from '../components/ui';
import { IconGlobe, IconRefresh, IconSearch, IconServer } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { relativeTime } from '../lib/format';

const VERDICT_TONE = {
  malicious: 'text-critical border-critical/30 bg-critical/8',
  suspicious: 'text-high border-high/30 bg-high/8',
  'low-confidence': 'text-medium border-medium/30 bg-medium/8',
  clean: 'text-success border-success/30 bg-success/8',
  internal: 'text-info border-line bg-sunken',
  unknown: 'text-ink-3 border-line bg-sunken',
};

export default function Intel() {
  const toast = useToast();
  const [indicator, setIndicator] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const status = useAsync(() => api.intelStatus(), []);
  const history = useAsync(() => api.intelHistory(), []);

  const lookup = async (refresh = false) => {
    if (!indicator.trim()) return;
    setBusy(true);
    try {
      const res = await api.intelLookup(indicator.trim(), refresh);
      setResult(res);
      history.refresh();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="p-4 space-y-4">
      <Panel dense bodyClass="p-4">
        <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
          <h2 className="text-md font-semibold text-ink">Reputation lookup</h2>
          <div className="flex items-center gap-3 text-2xs text-ink-3">
            <span className="flex items-center gap-1.5">
              <span className={cx('w-1.5 h-1.5 rounded-full', status.data?.intel?.mode === 'live' ? 'bg-success' : 'bg-medium')} />
              {status.data?.intel?.mode === 'live' ? 'Live providers configured' : 'Offline heuristic scoring'}
            </span>
            <span>·</span>
            <span>cache: {status.data?.cache?.backend}</span>
          </div>
        </div>

        <form
          onSubmit={(e) => { e.preventDefault(); lookup(false); }}
          className="flex items-center gap-2"
        >
          <div className="relative flex-1">
            <IconSearch size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" />
            <input
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              placeholder="IP address, domain, or file hash…"
              className="field h-10 pl-9 font-mono text-sm"
              autoFocus
            />
          </div>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? <Spinner /> : null} Lookup
          </Button>
          <Button icon={IconRefresh} onClick={() => lookup(true)} disabled={busy || !indicator.trim()}>
            Force refresh
          </Button>
        </form>

        {!status.data?.intel?.virustotal && !status.data?.intel?.abuseipdb && (
          <p className="text-2xs text-ink-3 mt-2">
            No live API keys configured (VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY). Results use
            deterministic offline heuristic scoring — clearly marked below.
          </p>
        )}
      </Panel>

      {result && (
        <Panel dense bodyClass="p-4">
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-lg text-ink">{result.indicator}</span>
                <span className="badge badge-outline uppercase">{result.indicator_type}</span>
              </div>
              <p className="text-2xs text-ink-3 mt-1">
                {result.live ? 'Live provider data' : 'Offline heuristic'} ·{' '}
                {result.cached ? 'served from cache' : 'freshly fetched'} · TTL 24h
              </p>
            </div>
            <div className={cx('badge border text-sm px-2.5 h-6', VERDICT_TONE[result.verdict] || VERDICT_TONE.unknown)}>
              {result.verdict} · {result.score}/100
            </div>
          </div>

          <div className="grid sm:grid-cols-2 gap-3 mt-4">
            {result.providers.map((provider) => (
              <div key={provider.provider} className="rounded border border-line p-3">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-xs font-semibold text-ink capitalize flex items-center gap-1.5">
                    <IconServer size={13} className="text-ink-3" /> {provider.provider}
                  </span>
                  <span className={cx('badge border', VERDICT_TONE[provider.verdict] || VERDICT_TONE.unknown)}>
                    {provider.score}
                  </span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">{provider.detail}</p>
                {provider.signals && Object.keys(provider.signals).length > 0 && (
                  <dl className="mt-2 pt-2 border-t border-line grid grid-cols-2 gap-1 text-2xs">
                    {Object.entries(provider.signals).slice(0, 6).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-1 min-w-0">
                        <dt className="text-ink-3 truncate">{k.replace(/_/g, ' ')}</dt>
                        <dd className="text-ink-2 truncate">{String(v ?? '—')}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="Recent lookups" dense bodyClass="p-0">
        {history.data?.items?.length ? (
          <table className="dtable">
            <thead>
              <tr>
                <th>Indicator</th>
                <th className="w-[70px]">Type</th>
                <th className="w-[90px]">Provider</th>
                <th className="w-[100px]">Verdict</th>
                <th className="w-[70px]">Score</th>
                <th className="w-[60px]">Live</th>
                <th className="w-[110px]">Fetched</th>
              </tr>
            </thead>
            <tbody>
              {history.data.items.map((row, index) => (
                <tr key={`${row.indicator}-${row.provider}-${index}`}>
                  <td className="font-mono text-xs">{row.indicator}</td>
                  <td className="text-2xs text-ink-3">{row.indicator_type}</td>
                  <td className="text-xs capitalize">{row.provider}</td>
                  <td>
                    <span className={cx('badge border', VERDICT_TONE[row.verdict] || VERDICT_TONE.unknown)}>
                      {row.verdict}
                    </span>
                  </td>
                  <td className="tnum text-xs">{row.score}</td>
                  <td className="text-2xs">{row.live ? 'yes' : 'no'}</td>
                  <td className="text-2xs text-ink-3">{relativeTime(row.fetched_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty icon={IconGlobe} title="No lookups yet" className="py-10" />
        )}
      </Panel>
    </div>
  );
}

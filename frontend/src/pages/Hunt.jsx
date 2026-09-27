import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Button,
  Empty,
  Loading,
  Panel,
  SeverityBadge,
  cx,
  useToast,
} from '../components/ui';
import { ColumnChart } from '../components/charts';
import { IconBook, IconSearch, IconTarget } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { formatFullDate, formatTime } from '../lib/format';

const EXAMPLE_CHIPS = [
  'severity:critical',
  'event_type:auth_failure user:root',
  'src_ip:45.* -severity:info',
  'status>=500 source:nginx',
  '"union select"',
];

export default function Hunt() {
  const [params, setParams] = useSearchParams();
  const { can } = useAuth();
  const toast = useToast();
  const [query, setQuery] = useState(params.get('q') || '');
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [selected, setSelected] = useState(null);
  const [saveName, setSaveName] = useState('');

  const schema = useAsync(() => api.huntSchema(), []);
  const saved = useAsync(() => api.savedHunts(), []);

  const runQuery = async (q = query) => {
    setRunning(true);
    try {
      const res = await api.hunt({ query: q, limit: 300 });
      setResult(res);
      setQuery(q);
      const next = new URLSearchParams(params);
      next.set('q', q);
      setParams(next, { replace: true });
    } catch (err) {
      toast.error(err.message);
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    if (params.get('q')) runQuery(params.get('q'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const saveCurrentHunt = async () => {
    if (!saveName.trim() || !query.trim()) return;
    try {
      await api.saveHunt(saveName.trim(), query);
      setSaveName('');
      saved.refresh();
      toast.success('Hunt saved.');
    } catch (err) {
      toast.error(err.message);
    }
  };

  const histogramPoints = (result?.histogram || []).map((b) => ({ label: b.bucket, value: b.count }));

  return (
    <div className="p-4 h-full flex flex-col min-h-0 gap-4">
      <Panel dense bodyClass="p-3" className="shrink-0">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runQuery();
          }}
          className="flex items-center gap-2"
        >
          <div className="relative flex-1">
            <IconSearch size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='field:value AND "exact phrase" -exclude  ·  press Enter to search'
              className="field h-10 pl-9 font-mono text-sm"
              autoFocus
            />
          </div>
          <Button type="submit" variant="primary" disabled={running}>
            {running ? 'Searching…' : 'Search'}
          </Button>
        </form>
        <div className="flex items-center gap-1.5 flex-wrap mt-2">
          <span className="text-2xs text-ink-3">Try:</span>
          {EXAMPLE_CHIPS.map((chip) => (
            <button
              key={chip}
              type="button"
              onClick={() => runQuery(chip)}
              className="chip hover:border-accent/50 hover:text-accent transition-colors duration-120"
            >
              {chip}
            </button>
          ))}
        </div>
      </Panel>

      <div className="grid lg:grid-cols-[1fr_260px] gap-4 flex-1 min-h-0">
        <div className="flex flex-col min-h-0 gap-3">
          {result?.warnings?.length > 0 && (
            <div className="rounded border border-medium/30 bg-medium/8 px-3 py-2 text-xs text-medium shrink-0">
              {result.warnings.join(' · ')}
            </div>
          )}

          {result && (
            <Panel dense bodyClass="p-3" className="shrink-0">
              <div className="flex items-center justify-between mb-1.5">
                <p className="text-2xs text-ink-3">
                  <span className="text-ink font-medium tnum">{result.total}</span> matches ·{' '}
                  {result.took_ms}ms
                </p>
                {can('hunt:save') && (
                  <div className="flex items-center gap-1.5">
                    <input
                      value={saveName}
                      onChange={(e) => setSaveName(e.target.value)}
                      placeholder="Name this hunt…"
                      className="field h-6 text-2xs w-36"
                    />
                    <Button size="sm" onClick={saveCurrentHunt} disabled={!saveName.trim()}>
                      Save
                    </Button>
                  </div>
                )}
              </div>
              <ColumnChart
                points={histogramPoints}
                height={64}
                formatLabel={(p) => `${p.value} events · ${formatTime(p.label)}`}
              />
            </Panel>
          )}

          <Panel className="flex-1 min-h-0" bodyClass="p-0 h-full" dense>
            <div className="h-full overflow-auto">
              {!result ? (
                <Empty icon={IconSearch} title="Run a query" hint="Search raw telemetry across every ingested log source." className="py-16" />
              ) : running ? (
                <Loading className="py-16" />
              ) : result.items.length ? (
                <table className="dtable">
                  <thead>
                    <tr>
                      <th className="w-[128px]">Time</th>
                      <th className="w-[80px]">Source</th>
                      <th className="w-[70px]">Sev</th>
                      <th className="w-[130px]">Type</th>
                      <th className="w-[110px]">Src IP</th>
                      <th>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.items.map((event) => (
                      <tr key={event.id} className={cx('cursor-pointer', selected?.id === event.id && 'is-selected')} onClick={() => setSelected(event)}>
                        <td className="font-mono text-2xs whitespace-nowrap">{formatFullDate(event.ts)}</td>
                        <td className="text-xs">{event.source}</td>
                        <td><SeverityBadge value={event.severity} /></td>
                        <td className="text-xs">{event.event_type}</td>
                        <td className="text-xs font-mono">{event.src_ip || '—'}</td>
                        <td className="text-xs text-ink-2 max-w-0">
                          <span className="block truncate" title={event.message}>{event.message}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <Empty icon={IconTarget} title="No matches" hint="Adjust the query — check the field reference for supported syntax." className="py-16" />
              )}
            </div>
          </Panel>
        </div>

        <div className="space-y-4 min-h-0 overflow-auto">
          <Panel title="Facets" dense bodyClass="p-3 space-y-3">
            {result?.facets?.filter((f) => f.values.length).length ? (
              result.facets
                .filter((f) => f.values.length)
                .map((facet) => (
                  <div key={facet.field}>
                    <p className="text-2xs font-medium text-ink-3 mb-1 capitalize">{facet.field.replace('_', ' ')}</p>
                    <ul className="space-y-1">
                      {facet.values.map((v) => (
                        <li key={String(v.value)}>
                          <button
                            type="button"
                            onClick={() => runQuery(`${query} ${facet.field}:${v.value}`.trim())}
                            className="w-full flex items-center justify-between gap-2 text-xs text-ink-2 hover:text-accent"
                          >
                            <span className="truncate">{String(v.value)}</span>
                            <span className="text-2xs tnum text-ink-3">{v.count}</span>
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))
            ) : (
              <p className="text-2xs text-ink-3">Run a query to see facets.</p>
            )}
          </Panel>

          <Panel title="Saved hunts" dense bodyClass="p-0">
            {saved.data?.length ? (
              <ul className="divide-y divide-line">
                {saved.data.map((hunt) => (
                  <li key={hunt.id}>
                    <button
                      type="button"
                      onClick={() => runQuery(hunt.query)}
                      className="w-full text-left px-3 py-2 hover:bg-sunken transition-colors duration-120"
                    >
                      <p className="text-xs text-ink font-medium truncate">{hunt.name}</p>
                      <p className="font-mono text-2xs text-ink-3 truncate">{hunt.query}</p>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-2xs text-ink-3 p-3">No saved hunts yet.</p>
            )}
          </Panel>

          <Panel title="Field reference" dense bodyClass="p-3">
            <div className="flex items-center gap-1.5 mb-2 text-2xs text-ink-3">
              <IconBook size={12} /> Operators
            </div>
            <ul className="space-y-1 mb-3">
              {(schema.data?.operators || []).map((op) => (
                <li key={op.op} className="flex items-baseline gap-2 text-2xs">
                  <span className="kbd">{op.op}</span>
                  <span className="text-ink-3">{op.meaning}</span>
                </li>
              ))}
            </ul>
            <p className="text-2xs text-ink-3 mb-1">Fields</p>
            <div className="flex flex-wrap gap-1">
              {(schema.data?.fields || []).map((field) => (
                <span key={field} className="chip">{field}</span>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

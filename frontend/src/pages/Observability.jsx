import { useState } from 'react';
import { Empty, Loading, Panel, cx } from '../components/ui';
import { BarList } from '../components/charts';
import { IconTrace } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { formatDuration, formatNumber, relativeTime } from '../lib/format';

export default function Observability() {
  const [traceId, setTraceId] = useState(null);
  const stats = useAsync(() => api.tracingStats(168), []);
  const traces = useAsync(() => api.traces(30), []);
  const config = useAsync(() => api.tracingConfig(), []);
  const detail = useAsync(() => (traceId ? api.trace(traceId) : Promise.resolve(null)), [traceId]);

  return (
    <div className="p-4 space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <MetricTile label="Traces (7d)" value={stats.data?.total_traces} />
        <MetricTile label="Spans" value={stats.data?.total_spans} />
        <MetricTile label="Tokens" value={stats.data ? formatNumber(stats.data.tokens_in + stats.data.tokens_out) : undefined} />
        <MetricTile label="Cost" value={stats.data ? `$${stats.data.cost_usd.toFixed(4)}` : undefined} />
        <MetricTile label="p95 latency" value={stats.data ? formatDuration(stats.data.p95_ms) : undefined} />
      </div>

      <Panel dense bodyClass="p-3">
        <div className="flex items-center justify-between flex-wrap gap-2 text-xs">
          <span className="text-ink-2">
            Exporter: <span className="font-medium text-ink capitalize">{config.data?.exporter}</span>
            {' '}({config.data?.project})
          </span>
          <span className="text-2xs text-ink-3">{config.data?.note}</span>
        </div>
        <div className="flex items-center gap-3 mt-2 text-2xs text-ink-3">
          <span>LangSmith key: {config.data?.langsmith_key ? 'configured' : 'not configured'}</span>
          <span>·</span>
          <span>Phoenix endpoint: {config.data?.phoenix_endpoint ? 'configured' : 'not configured'}</span>
          <span>·</span>
          <span>${config.data?.cost_model?.input_per_1k_usd}/1k in · ${config.data?.cost_model?.output_per_1k_usd}/1k out</span>
        </div>
      </Panel>

      <div className="grid lg:grid-cols-[1fr_320px] gap-4">
        <Panel title="Recent traces" dense bodyClass="p-0">
          {traces.loading && !traces.data ? (
            <Loading className="py-10" />
          ) : traces.data?.length ? (
            <table className="dtable">
              <thead>
                <tr>
                  <th>Root span</th>
                  <th className="w-[70px]">Spans</th>
                  <th className="w-[90px]">Tokens</th>
                  <th className="w-[80px]">Cost</th>
                  <th className="w-[80px]">Duration</th>
                  <th className="w-[100px]">When</th>
                </tr>
              </thead>
              <tbody>
                {traces.data.map((trace) => (
                  <tr
                    key={trace.trace_id}
                    className={cx('cursor-pointer', traceId === trace.trace_id && 'is-selected')}
                    onClick={() => setTraceId(trace.trace_id)}
                  >
                    <td className="text-xs font-mono truncate max-w-0" title={trace.root_name}>
                      {trace.root_name}
                    </td>
                    <td className="tnum text-xs">{trace.spans}</td>
                    <td className="tnum text-xs">{formatNumber(trace.tokens_in + trace.tokens_out)}</td>
                    <td className="tnum text-xs">${trace.cost_usd.toFixed(4)}</td>
                    <td className="tnum text-xs">{formatDuration(trace.duration_ms)}</td>
                    <td className="text-2xs text-ink-3">{relativeTime(trace.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty icon={IconTrace} title="No traces yet" hint="Run an investigation or ask Copilot a question to generate telemetry." className="py-10" />
          )}
        </Panel>

        <Panel title="By agent" dense bodyClass="p-3">
          <BarList
            items={(stats.data?.by_agent || [])
              .slice(0, 10)
              .map((a) => ({ label: a.agent, value: a.calls }))}
            valueLabel="calls"
          />
        </Panel>
      </div>

      {traceId && detail.data && (
        <Panel title={`Trace ${traceId.slice(0, 16)}…`} dense bodyClass="p-0">
          <table className="dtable">
            <thead>
              <tr>
                <th>Span</th>
                <th className="w-[80px]">Kind</th>
                <th className="w-[90px]">Model</th>
                <th className="w-[80px]">Tokens</th>
                <th className="w-[80px]">Duration</th>
                <th className="w-[70px]">Status</th>
              </tr>
            </thead>
            <tbody>
              {detail.data.spans.map((span) => (
                <tr key={span.id}>
                  <td className="text-xs" style={{ paddingLeft: span.parent_span_id ? 24 : 12 }}>
                    {span.name}
                  </td>
                  <td className="text-2xs text-ink-3">{span.kind}</td>
                  <td className="text-2xs text-ink-3">{span.model || '—'}</td>
                  <td className="tnum text-xs">{formatNumber(span.tokens_in + span.tokens_out)}</td>
                  <td className="tnum text-xs">{formatDuration(span.duration_ms)}</td>
                  <td>
                    <span className={cx('badge', span.status === 'ok' ? 'badge-outline' : 'bg-critical/12 text-critical border border-critical/30')}>
                      {span.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}

function MetricTile({ label, value }) {
  return (
    <div className="panel px-3.5 py-3">
      <p className="section-label">{label}</p>
      <p className="text-xl font-semibold tnum text-ink mt-1">{value ?? '—'}</p>
    </div>
  );
}

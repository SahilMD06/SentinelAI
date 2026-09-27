import { useNavigate } from 'react-router-dom';
import {
  Button,
  Empty,
  ErrorState,
  Panel,
  RiskMeter,
  SeverityBadge,
  SkeletonRows,
  StatTile,
  StatusBadge,
  cx,
} from '../components/ui';
import { BarList, ColumnChart, Donut } from '../components/charts';
import PipelineHealth from '../components/PipelineHealth';
import {
  IconAlert,
  IconAnomaly,
  IconClock,
  IconGauge,
  IconRefresh,
  IconStream,
  IconTarget,
} from '../components/icons';
import { api } from '../lib/api';
import { useAsync, useInterval, useLocalState } from '../lib/hooks';
import {
  SEVERITY_ORDER,
  formatMinutes,
  formatNumber,
  formatTime,
  relativeTime,
  titleCase,
} from '../lib/format';

const RANGES = [
  { hours: 6, label: '6h' },
  { hours: 24, label: '24h' },
  { hours: 72, label: '3d' },
  { hours: 168, label: '7d' },
];

export default function Overview() {
  const navigate = useNavigate();
  const [hours, setHours] = useLocalState('sentinelai.overview.hours', 24);

  const dashboard = useAsync(() => api.dashboard(hours), [hours]);
  const pipeline = useAsync(() => api.pipeline(), []);
  const sla = useAsync(() => api.sla(), []);

  useInterval(() => {
    dashboard.refresh();
    pipeline.refresh();
    sla.refresh();
  }, 60000);

  if (dashboard.error) return <ErrorState error={dashboard.error} onRetry={dashboard.refresh} />;

  const data = dashboard.data;
  const severitySegments = SEVERITY_ORDER.map((severity) => ({
    label: severity,
    value: data?.severity_breakdown?.find((s) => s.label === severity)?.value || 0,
  })).filter((s) => s.value > 0);

  const timeline = (data?.events_timeline || []).map((point) => ({
    label: point.label,
    value: point.value,
  }));

  return (
    <div className="p-4 space-y-4">
      {/* ------------------------------------------------------------ header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-1 p-0.5 rounded border border-line bg-surface">
          {RANGES.map((option) => (
            <button
              key={option.hours}
              type="button"
              onClick={() => setHours(option.hours)}
              className={cx(
                'h-7 px-2.5 rounded text-xs font-medium transition-colors duration-120',
                hours === option.hours
                  ? 'bg-accent/12 text-accent'
                  : 'text-ink-3 hover:text-ink hover:bg-sunken',
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 text-2xs text-ink-3">
          <span>Auto-refresh 60s</span>
          <Button size="sm" icon={IconRefresh} onClick={dashboard.refresh} disabled={dashboard.loading}>
            Refresh
          </Button>
        </div>
      </div>

      {/* -------------------------------------------------------------- tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
        <StatTile
          label="Open incidents"
          value={data ? formatNumber(data.open_incidents) : '—'}
          sub="Not closed or dismissed"
          icon={IconAlert}
          onClick={() => navigate('/incidents')}
        />
        <StatTile
          label="Critical open"
          value={data ? formatNumber(data.critical_incidents) : '—'}
          sub="Containment mandatory"
          tone={data?.critical_incidents ? 'critical' : 'default'}
          icon={IconTarget}
          onClick={() => navigate('/incidents?severity=critical')}
        />
        <StatTile
          label={`Events (${hours}h)`}
          value={data ? formatNumber(data.events_24h) : '—'}
          sub={`${data?.pipeline?.ingest_rate_per_min ?? 0}/min average`}
          icon={IconStream}
          onClick={() => navigate('/feed')}
        />
        <StatTile
          label="Open anomalies"
          value={data ? formatNumber(data.anomalies_open) : '—'}
          sub="Behavioural, no signature"
          tone={data?.anomalies_open ? 'medium' : 'default'}
          icon={IconAnomaly}
          onClick={() => navigate('/anomalies')}
        />
        <StatTile
          label="Mean time to remediate"
          value={data ? formatMinutes(data.mttr_minutes) : '—'}
          sub="Across closed cases"
          icon={IconClock}
        />
        <StatTile
          label="Mean risk index"
          value={data ? data.risk_index : '—'}
          sub={`ATT&CK coverage ${data?.detection_coverage ?? 0}%`}
          tone={data?.risk_index >= 60 ? 'high' : 'default'}
          icon={IconGauge}
        />
      </div>

      {/* ------------------------------------------------------- main grid */}
      <div className="grid xl:grid-cols-3 gap-4">
        <Panel
          title="Event volume"
          subtitle={`24 buckets across the last ${hours} hours`}
          className="xl:col-span-2"
        >
          {dashboard.loading && !data ? (
            <div className="h-[150px] skeleton" />
          ) : (
            <ColumnChart
              points={timeline}
              height={150}
              formatLabel={(point) =>
                `${formatNumber(point.value)} events · ${formatTime(point.label)}`
              }
            />
          )}
          <div className="flex items-center justify-between mt-2 text-2xs text-ink-3">
            <span>{timeline.length ? formatTime(timeline[0].label) : ''}</span>
            <span>{timeline.length ? formatTime(timeline[timeline.length - 1].label) : ''}</span>
          </div>
        </Panel>

        <Panel title="Open case severity">
          {severitySegments.length ? (
            <div className="flex items-center gap-5">
              <Donut
                segments={severitySegments}
                centerValue={formatNumber(data.open_incidents)}
                centerLabel="open"
              />
              <ul className="flex-1 space-y-1.5 min-w-0">
                {severitySegments.map((segment) => (
                  <li key={segment.label} className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-2 min-w-0">
                      <SeverityBadge value={segment.label} />
                    </span>
                    <span className="text-sm tnum text-ink">{segment.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <Empty title="No open cases" hint="Every incident is closed or dismissed." />
          )}
        </Panel>
      </div>

      <div className="grid xl:grid-cols-3 gap-4">
        <Panel title="Ingress pipeline health" className="xl:col-span-2">
          <PipelineHealth pipeline={pipeline.data} />
        </Panel>

        <Panel title="Telemetry by source" subtitle={`Last ${hours} hours`}>
          <BarList
            items={(data?.top_sources || []).map((s) => ({ label: s.label, value: s.value }))}
            valueLabel="events"
          />
        </Panel>
      </div>

      <div className="grid xl:grid-cols-3 gap-4">
        {/* ------------------------------------------------------ SLA watch */}
        <Panel
          title="SLA watchlist"
          subtitle="Cases against their containment clock"
          className="xl:col-span-1"
          dense
        >
          {sla.loading && !sla.data ? (
            <SkeletonRows rows={4} />
          ) : (sla.data?.breached?.length || sla.data?.at_risk?.length) ? (
            <ul className="divide-y divide-line">
              {[...(sla.data.breached || []), ...(sla.data.at_risk || [])]
                .slice(0, 7)
                .map((item) => (
                  <li key={item.ref}>
                    <button
                      type="button"
                      onClick={() => navigate(`/incidents?ref=${item.ref}`)}
                      className="w-full text-left px-4 py-2.5 hover:bg-sunken transition-colors duration-120"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-2xs text-ink-2">{item.ref}</span>
                        <span
                          className={cx(
                            'text-2xs tnum font-medium',
                            item.minutes_remaining < 0 ? 'text-critical' : 'text-medium',
                          )}
                        >
                          {item.minutes_remaining < 0
                            ? `breached ${formatMinutes(-item.minutes_remaining)}`
                            : `${formatMinutes(item.minutes_remaining)} left`}
                        </span>
                      </div>
                      <p className="text-xs text-ink truncate mt-0.5">{item.title}</p>
                      <div className="flex items-center gap-1.5 mt-1">
                        <SeverityBadge value={item.severity} />
                        <span className="text-2xs text-ink-3 truncate">
                          {item.assignee || 'unassigned'}
                        </span>
                      </div>
                    </button>
                  </li>
                ))}
            </ul>
          ) : (
            <Empty title="No SLA pressure" hint="Nothing is breaching or approaching its clock." />
          )}
        </Panel>

        {/* ------------------------------------------------- recent incidents */}
        <Panel
          title="Latest cases"
          subtitle="Newest first"
          className="xl:col-span-2"
          dense
          actions={
            <Button size="sm" onClick={() => navigate('/incidents')}>
              Open queue
            </Button>
          }
        >
          {dashboard.loading && !data ? (
            <SkeletonRows rows={6} />
          ) : (
            <div className="overflow-x-auto">
              <table className="dtable">
                <thead>
                  <tr>
                    <th className="w-[110px]">Case</th>
                    <th>Title</th>
                    <th className="w-[80px]">Severity</th>
                    <th className="w-[110px]">Status</th>
                    <th className="w-[110px]">Risk</th>
                    <th className="w-[92px]">Opened</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.recent_incidents || []).map((incident) => (
                    <tr
                      key={incident.ref}
                      className="cursor-pointer"
                      onClick={() => navigate(`/incidents?ref=${incident.ref}`)}
                    >
                      <td className="font-mono text-2xs text-ink-2 whitespace-nowrap">
                        {incident.ref}
                      </td>
                      <td className="max-w-0">
                        <span className="block truncate text-ink">{incident.title}</span>
                        <span className="block truncate text-2xs text-ink-3">
                          {titleCase(incident.category)} · {incident.asset}
                        </span>
                      </td>
                      <td><SeverityBadge value={incident.severity} /></td>
                      <td><StatusBadge value={incident.status} /></td>
                      <td><RiskMeter score={incident.risk_score} size="sm" /></td>
                      <td className="text-2xs text-ink-3 whitespace-nowrap">
                        {relativeTime(incident.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="ATT&CK techniques on open cases" subtitle="Ranked by case count">
        {data?.top_techniques?.length ? (
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {data.top_techniques.map((technique) => (
              <div key={technique.id} className="rounded border border-line px-3 py-2.5">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="font-mono text-xs text-accent">{technique.id}</span>
                  <span className="text-2xs tnum text-ink-3">{technique.count} cases</span>
                </div>
                <p className="text-xs text-ink mt-1 truncate" title={technique.name}>
                  {technique.name}
                </p>
                <p className="text-2xs text-ink-3 mt-0.5 truncate">{technique.tactic}</p>
              </div>
            ))}
          </div>
        ) : (
          <Empty title="No techniques mapped" hint="Run investigations to populate ATT&CK coverage." />
        )}
      </Panel>
    </div>
  );
}

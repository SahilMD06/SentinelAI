import { useState } from 'react';
import {
  Button,
  Empty,
  ErrorState,
  Loading,
  Panel,
  SeverityBadge,
  Tooltip,
  cx,
  useToast,
} from '../components/ui';
import { IconAnomaly, IconCheck, IconClose, IconRefresh } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { relativeTime } from '../lib/format';

export default function Anomalies() {
  const { can } = useAuth();
  const toast = useToast();
  const [statusFilter, setStatusFilter] = useState('open');
  const [selected, setSelected] = useState(null);
  const [retraining, setRetraining] = useState(false);

  const alerts = useAsync(() => api.anomalies({ status: statusFilter || undefined }), [statusFilter]);
  const status = useAsync(() => api.anomalyStatus(), []);
  const history = useAsync(() => api.modelHistory(), []);
  const context = useAsync(
    () => (selected ? api.anomalyContext(selected.id) : Promise.resolve(null)),
    [selected?.id],
  );

  const retrain = async () => {
    setRetraining(true);
    try {
      await api.retrain();
      toast.success('Retraining scheduled — the detector rescores the last 48 hours in the background.');
      setTimeout(() => {
        status.refresh();
        alerts.refresh();
        history.refresh();
      }, 4000);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setRetraining(false);
    }
  };

  const triage = async (id, next) => {
    try {
      await api.triageAnomaly(id, next);
      alerts.refresh();
      toast.success(`Marked ${next}.`);
    } catch (err) {
      toast.error(err.message);
    }
  };

  return (
    <div className="p-4 grid lg:grid-cols-[1fr_320px] gap-4 h-full min-h-0">
      <div className="flex flex-col min-h-0 gap-3">
        <Panel dense bodyClass="p-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-1.5">
              {['open', 'triaged', 'dismissed', ''].map((s) => (
                <button
                  key={s || 'all'}
                  type="button"
                  onClick={() => setStatusFilter(s)}
                  className={cx('badge cursor-pointer', statusFilter === s ? 'bg-accent text-white' : 'badge-outline')}
                >
                  {s || 'all'}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 text-2xs text-ink-3">
              <span className={cx('inline-flex items-center gap-1.5')}>
                <span className={cx('w-1.5 h-1.5 rounded-full', status.data?.trained ? 'bg-success' : 'bg-medium')} />
                {status.data?.trained ? `model ${status.data.model_version}` : 'not yet trained'}
              </span>
              <Button
                size="sm"
                icon={IconRefresh}
                onClick={retrain}
                disabled={retraining}
                locked={!can('anomaly:write')}
              >
                {retraining ? 'Scheduling…' : 'Retrain now'}
              </Button>
            </div>
          </div>
        </Panel>

        <Panel className="flex-1 min-h-0" bodyClass="p-0 h-full" dense>
          <div className="h-full overflow-auto">
            {alerts.error ? (
              <ErrorState error={alerts.error} onRetry={alerts.refresh} />
            ) : alerts.loading && !alerts.data ? (
              <Loading className="py-16" />
            ) : alerts.data?.length ? (
              <table className="dtable">
                <thead>
                  <tr>
                    <th className="w-[120px]">Detected</th>
                    <th className="w-[80px]">Score</th>
                    <th className="w-[70px]">Sev</th>
                    <th>Reason</th>
                    <th className="w-[90px]">Status</th>
                    <th className="w-[120px]" />
                  </tr>
                </thead>
                <tbody>
                  {alerts.data.map((alert) => (
                    <tr
                      key={alert.id}
                      className={cx('cursor-pointer', selected?.id === alert.id && 'is-selected')}
                      onClick={() => setSelected(alert)}
                    >
                      <td className="font-mono text-2xs whitespace-nowrap">{relativeTime(alert.detected_at)}</td>
                      <td className="tnum text-xs font-medium">{alert.score.toFixed(0)}</td>
                      <td><SeverityBadge value={alert.severity} /></td>
                      <td className="text-xs text-ink-2 max-w-0">
                        <span className="block truncate" title={alert.reason}>{alert.reason}</span>
                      </td>
                      <td className="text-2xs capitalize text-ink-3">{alert.status}</td>
                      <td onClick={(e) => e.stopPropagation()}>
                        {alert.status === 'open' && can('anomaly:write') && (
                          <div className="flex items-center gap-1">
                            <Tooltip label="Mark triaged">
                              <button onClick={() => triage(alert.id, 'triaged')} className="btn-ghost btn-sm px-1.5">
                                <IconCheck size={12} />
                              </button>
                            </Tooltip>
                            <Tooltip label="Dismiss">
                              <button onClick={() => triage(alert.id, 'dismissed')} className="btn-ghost btn-sm px-1.5">
                                <IconClose size={12} />
                              </button>
                            </Tooltip>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty icon={IconAnomaly} title="No anomalies" hint="The Isolation Forest detector has not flagged anything in this filter." className="py-16" />
            )}
          </div>
        </Panel>
      </div>

      <div className="space-y-4 min-h-0 overflow-auto">
        <Panel title="Detector status" dense bodyClass="p-3 space-y-2 text-xs">
          <Row label="Trained" value={status.data?.trained ? 'Yes' : 'No'} />
          <Row label="Samples" value={status.data?.samples ?? '—'} />
          <Row label="Running" value={status.data?.running ? 'Background daemon active' : 'Idle'} />
          <Row label="Interval" value={status.data ? `${status.data.interval_seconds}s` : '—'} />
          <Row label="Last flagged" value={status.data?.last_flagged ?? '—'} />
          {status.data?.error && <p className="text-2xs text-critical mt-1">{status.data.error}</p>}
          <div className="pt-2 border-t border-line">
            <p className="text-2xs text-ink-3 mb-1">Feature vector (12-dim)</p>
            <div className="flex flex-wrap gap-1">
              {(status.data?.features || []).map((f) => (
                <span key={f} className="chip">{f}</span>
              ))}
            </div>
          </div>
        </Panel>

        <Panel title="Training history" dense bodyClass="p-0">
          {history.data?.length ? (
            <ul className="divide-y divide-line">
              {history.data.slice(0, 6).map((snap) => (
                <li key={snap.id} className="px-3 py-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-2xs text-ink-2">{snap.version}</span>
                    <span className="text-2xs text-ink-3">{relativeTime(snap.trained_at)}</span>
                  </div>
                  <p className="text-2xs text-ink-3 mt-0.5">
                    {snap.samples} samples · {snap.duration_ms}ms
                  </p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-2xs text-ink-3 p-3">No training runs recorded.</p>
          )}
        </Panel>

        {selected && (
          <Panel title={`Alert #${selected.id}`} dense bodyClass="p-3 space-y-2">
            <p className="text-xs text-ink-2 leading-relaxed">{selected.reason}</p>
            {context.data?.event && (
              <div className="pt-2 border-t border-line space-y-1 text-2xs">
                <Row label="Host" value={context.data.event.host} />
                <Row label="Source" value={context.data.event.source} />
                <Row label="Src IP" value={context.data.event.src_ip || '—'} />
                <Row label="Event type" value={context.data.event.event_type} />
                <Row label="Message" value={context.data.event.message} wrap />
              </div>
            )}
          </Panel>
        )}
      </div>
    </div>
  );
}

function Row({ label, value, wrap }) {
  return (
    <div className={cx('flex gap-2', wrap ? 'flex-col' : 'items-center justify-between')}>
      <span className="text-ink-3">{label}</span>
      <span className={cx('text-ink text-right', wrap && 'text-left break-words')}>{value}</span>
    </div>
  );
}

import { useRef, useState } from 'react';
import {
  Button,
  Empty,
  ErrorState,
  Field,
  Loading,
  Modal,
  Panel,
  SeverityBadge,
  Tooltip,
  cx,
  useToast,
} from '../components/ui';
import PipelineHealth from '../components/PipelineHealth';
import { IconAnomaly, IconRefresh, IconSearch, IconStream, IconUpload } from '../components/icons';
import { api } from '../lib/api';
import { useAsync, useDebounced, useInterval, useLocalState } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { formatBytes, formatFullDate } from '../lib/format';

export default function Feed() {
  const { can } = useAuth();
  const [q, setQ] = useState('');
  const debouncedQ = useDebounced(q, 350);
  const [severity, setSeverity] = useLocalState('sentinelai.feed.severity', []);
  const [anomaliesOnly, setAnomaliesOnly] = useState(false);
  const [live, setLive] = useState(true);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [selected, setSelected] = useState(null);

  const events = useAsync(
    () => api.events({ q: debouncedQ, severity, anomalies_only: anomaliesOnly || undefined, size: 60 }),
    [debouncedQ, severity, anomaliesOnly],
  );
  const pipeline = useAsync(() => api.pipeline(), []);

  useInterval(() => {
    if (live) {
      events.refresh();
      pipeline.refresh();
    }
  }, 15000);

  const toggleSeverity = (value) =>
    setSeverity((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]));

  return (
    <div className="p-4 space-y-4 h-full flex flex-col min-h-0">
      <Panel title="Ingress pipeline health" dense bodyClass="p-4" className="shrink-0">
        <PipelineHealth pipeline={pipeline.data} compact />
      </Panel>

      <div className="flex-1 min-h-0 flex flex-col panel">
        <div className="panel-header flex-wrap gap-2 h-auto py-2.5">
          <div className="flex items-center gap-1.5 flex-1 min-w-[220px]">
            <div className="relative flex-1 max-w-sm">
              <IconSearch size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search message, IP, host, user…"
                className="field h-8 pl-7"
              />
            </div>
            {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => toggleSeverity(sev)}
                className={cx('badge cursor-pointer', severity.includes(sev) ? 'bg-accent text-white' : 'badge-outline')}
              >
                {sev}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setAnomaliesOnly((v) => !v)}
              className={cx(
                'badge cursor-pointer flex items-center gap-1',
                anomaliesOnly ? 'bg-accent text-white' : 'badge-outline',
              )}
            >
              <IconAnomaly size={11} /> anomalies
            </button>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <label className="flex items-center gap-1.5 text-2xs text-ink-3 cursor-pointer select-none">
              <input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} className="accent-accent" />
              Live
            </label>
            <Button size="sm" icon={IconRefresh} onClick={events.refresh}>
              Refresh
            </Button>
            <Button
              size="sm"
              variant="primary"
              icon={IconUpload}
              onClick={() => setUploadOpen(true)}
              locked={!can('events:ingest')}
              lockedReason="Log ingestion requires Analyst, SOC Manager or Administrator"
            >
              Ingest logs
            </Button>
          </div>
        </div>

        <div className="flex-1 min-h-0 flex overflow-hidden">
          <div className="flex-1 min-w-0 overflow-auto">
            {events.error ? (
              <ErrorState error={events.error} onRetry={events.refresh} />
            ) : events.loading && !events.data ? (
              <Loading className="py-16" />
            ) : events.data?.items?.length ? (
              <table className="dtable">
                <thead>
                  <tr>
                    <th className="w-[128px]">Time</th>
                    <th className="w-[80px]">Source</th>
                    <th className="w-[70px]">Sev</th>
                    <th className="w-[130px]">Type</th>
                    <th className="w-[120px]">Host</th>
                    <th className="w-[110px]">Src IP</th>
                    <th>Message</th>
                    <th className="w-[60px]" />
                  </tr>
                </thead>
                <tbody>
                  {events.data.items.map((event) => (
                    <tr
                      key={event.id}
                      className={cx('cursor-pointer', selected?.id === event.id && 'is-selected')}
                      onClick={() => setSelected(event)}
                    >
                      <td className="font-mono text-2xs whitespace-nowrap">{formatFullDate(event.ts)}</td>
                      <td className="text-xs">{event.source}</td>
                      <td><SeverityBadge value={event.severity} /></td>
                      <td className="text-xs">{event.event_type}</td>
                      <td className="text-xs font-mono">{event.host}</td>
                      <td className="text-xs font-mono">{event.src_ip || '—'}</td>
                      <td className="text-xs text-ink-2 max-w-0">
                        <span className="block truncate" title={event.message}>{event.message}</span>
                      </td>
                      <td>
                        {event.is_anomaly && (
                          <Tooltip label={`Anomaly score ${event.anomaly_score}`}>
                            <IconAnomaly size={13} className="text-medium" />
                          </Tooltip>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty icon={IconStream} title="No events match" className="py-16" />
            )}
          </div>

          {selected && (
            <div className="w-[360px] shrink-0 border-l border-line scroll-y p-4 space-y-3">
              <div className="flex items-center justify-between">
                <p className="section-label">Event detail</p>
                <button type="button" onClick={() => setSelected(null)} className="text-2xs text-ink-3 hover:text-ink">
                  Close
                </button>
              </div>
              <dl className="space-y-2 text-xs">
                {[
                  ['Timestamp', formatFullDate(selected.ts)],
                  ['Source', selected.source],
                  ['Host', selected.host],
                  ['Event type', selected.event_type],
                  ['Matched rule', selected.matched_rule || 'none'],
                  ['Source IP', selected.src_ip || '—'],
                  ['Destination', selected.dest_ip ? `${selected.dest_ip}:${selected.dest_port || ''}` : '—'],
                  ['Username', selected.username || '—'],
                  ['Protocol', selected.protocol || '—'],
                  ['Country', selected.geo_country || '—'],
                  ['Bytes out', formatBytes(selected.bytes_out)],
                  ['Bytes in', formatBytes(selected.bytes_in)],
                  ['Anomaly score', selected.anomaly_score],
                  ['Linked incident', selected.incident_id ? `#${selected.incident_id}` : 'none'],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between gap-3">
                    <dt className="text-ink-3">{label}</dt>
                    <dd className="text-ink text-right break-all">{value}</dd>
                  </div>
                ))}
              </dl>
              <div>
                <p className="section-label mb-1.5">Raw log</p>
                <pre className="font-mono text-2xs text-ink-2 bg-sunken border border-line rounded p-2.5 whitespace-pre-wrap break-all leading-relaxed">
                  {selected.raw}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>

      <UploadModal open={uploadOpen} onClose={() => setUploadOpen(false)} onDone={() => { events.refresh(); pipeline.refresh(); }} />
    </div>
  );
}

function UploadModal({ open, onClose, onDone }) {
  const toast = useToast();
  const [text, setText] = useState('');
  const [hint, setHint] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const fileRef = useRef(null);

  const submit = async () => {
    const lines = text.split('\n').filter((l) => l.trim());
    if (!lines.length) return;
    setBusy(true);
    try {
      const res = await api.ingest(lines, hint || undefined);
      setResult(res);
      toast.success(`Ingested ${res.accepted} event(s).`);
      onDone();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setBusy(false);
    }
  };

  const onFile = async (file) => {
    const content = await file.text();
    setText(content.slice(0, 200000));
    setHint(file.name.replace(/\.[^.]+$/, ''));
  };

  return (
    <Modal
      open={open}
      onClose={() => { setResult(null); setText(''); onClose(); }}
      title="Ingest raw log lines"
      subtitle="Paste or upload sshd, nginx, or key=value firewall logs — parsed and enriched automatically"
      width="max-w-2xl"
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={submit} disabled={busy || !text.trim()}>
            {busy ? 'Ingesting…' : 'Ingest'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <input
            ref={fileRef}
            type="file"
            accept=".log,.txt"
            className="hidden"
            onChange={(e) => e.target.files[0] && onFile(e.target.files[0])}
          />
          <Button size="sm" icon={IconUpload} onClick={() => fileRef.current?.click()}>
            Choose file
          </Button>
          <Field label="" className="flex-1">
            <input
              value={hint}
              onChange={(e) => setHint(e.target.value)}
              placeholder="Source hint (optional, e.g. bastion-01)"
              className="field h-8"
            />
          </Field>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={10}
          placeholder={'Aug 23 04:12:01 web-edge-01 sshd[9921]: Failed password for invalid user root from 185.220.101.47 port 44122 ssh2'}
          className="field font-mono text-xs resize-none py-2"
        />
        {result && (
          <div className="rounded border border-line bg-sunken p-2.5 text-xs">
            <p>
              <span className="text-success font-medium">{result.accepted} accepted</span>
              {' · '}
              <span className="text-ink-3">{result.rejected} rejected</span>
            </p>
            {result.errors.length > 0 && (
              <ul className="mt-1 text-2xs text-critical space-y-0.5">
                {result.errors.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}

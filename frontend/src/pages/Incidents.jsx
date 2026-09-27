import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Button,
  Checkbox,
  Empty,
  ErrorState,
  Field,
  Loading,
  LockedNotice,
  Modal,
  RiskMeter,
  Select,
  SeverityBadge,
  SeverityDot,
  StatusBadge,
  Tabs,
  Tooltip,
  cx,
  useToast,
} from '../components/ui';
import AgentTimeline from '../components/AgentTimeline';
import ThreatChainView from '../components/ThreatChain';
import {
  IconAlert,
  IconChevron,
  IconClock,
  IconDownload,
  IconFilter,
  IconPlay,
  IconSearch,
  IconSend,
  IconTarget,
} from '../components/icons';
import { api, ApiError } from '../lib/api';
import { useAsync, useDebounced, useLocalState } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import {
  PHASE_LABEL,
  SEVERITY_ORDER,
  formatDate,
  formatFullDate,
  relativeTime,
  titleCase,
} from '../lib/format';

const STATUS_ORDER = [
  'new', 'triaging', 'investigating', 'contained', 'remediated', 'closed', 'false_positive',
];

export default function Incidents() {
  const [params, setParams] = useSearchParams();
  const { can } = useAuth();
  const toast = useToast();

  const [q, setQ] = useState(params.get('q') || '');
  const debouncedQ = useDebounced(q, 350);
  const [severity, setSeverity] = useLocalState('sentinelai.incidents.severity', params.get('severity') ? [params.get('severity')] : []);
  const [status, setStatus] = useLocalState('sentinelai.incidents.status', []);
  const [sort, setSort] = useLocalState('sentinelai.incidents.sort', 'created_at');
  const [page, setPage] = useState(1);
  const [selectedRef, setSelectedRef] = useState(params.get('ref') || null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [simulateOpen, setSimulateOpen] = useState(false);

  const list = useAsync(
    () => api.incidents({ q: debouncedQ, severity, status, sort, order: 'desc', page, size: 30 }),
    [debouncedQ, severity, status, sort, page],
  );

  useEffect(() => setPage(1), [debouncedQ, severity, status, sort]);

  // Deep-link support: /incidents?ref=INC-2026-1004
  useEffect(() => {
    const ref = params.get('ref');
    if (ref && ref !== selectedRef) setSelectedRef(ref);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!selectedRef && list.data?.items?.length) setSelectedRef(list.data.items[0].ref);
  }, [list.data, selectedRef]);

  const selectRef = (ref) => {
    setSelectedRef(ref);
    const next = new URLSearchParams(params);
    next.set('ref', ref);
    setParams(next, { replace: true });
  };

  const toggleSeverity = (value) =>
    setSeverity((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]));
  const toggleStatus = (value) =>
    setStatus((current) => (current.includes(value) ? current.filter((v) => v !== value) : [...current, value]));

  const activeFilters = severity.length + status.length + (q ? 1 : 0);

  return (
    <div className="flex h-full min-h-0">
      {/* ============================================================ QUEUE */}
      <div className="w-[360px] shrink-0 border-r border-line flex flex-col min-h-0 bg-surface">
        <div className="p-2.5 border-b border-line space-y-2 shrink-0">
          <div className="flex items-center gap-1.5">
            <div className="relative flex-1">
              <IconSearch size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-3" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search ref, title, asset, IP…"
                className="field h-8 pl-7"
              />
            </div>
            <Tooltip label="Filters">
              <button
                type="button"
                onClick={() => setFiltersOpen((v) => !v)}
                className={cx('btn-secondary btn-sm px-2 relative', activeFilters > 0 && 'border-accent text-accent')}
              >
                <IconFilter size={13} />
                {activeFilters > 0 && (
                  <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full bg-accent text-white text-[9px] flex items-center justify-center">
                    {activeFilters}
                  </span>
                )}
              </button>
            </Tooltip>
            <Button
              variant="primary"
              size="sm"
              icon={IconPlay}
              onClick={() => setSimulateOpen(true)}
              locked={!can('simulate:run')}
              lockedReason="Threat simulation is an administrator-only action"
            >
              Simulate
            </Button>
          </div>

          {filtersOpen && (
            <div className="rounded border border-line bg-sunken p-2.5 space-y-2.5 animate-slide-up">
              <div>
                <p className="text-2xs font-medium text-ink-3 mb-1.5">Severity</p>
                <div className="flex flex-wrap gap-1">
                  {SEVERITY_ORDER.map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => toggleSeverity(sev)}
                      className={cx(
                        'badge cursor-pointer',
                        severity.includes(sev) ? 'bg-accent text-white' : 'badge-outline',
                      )}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-2xs font-medium text-ink-3 mb-1.5">Status</p>
                <div className="flex flex-wrap gap-1">
                  {STATUS_ORDER.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => toggleStatus(s)}
                      className={cx(
                        'badge cursor-pointer',
                        status.includes(s) ? 'bg-accent text-white' : 'badge-outline',
                      )}
                    >
                      {titleCase(s)}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex items-center justify-between gap-2">
                <Select
                  value={sort}
                  onChange={(e) => setSort(e.target.value)}
                  className="h-7 text-xs w-auto"
                  options={[
                    { value: 'created_at', label: 'Sort: newest' },
                    { value: 'risk_score', label: 'Sort: risk' },
                    { value: 'updated_at', label: 'Sort: updated' },
                    { value: 'severity', label: 'Sort: severity' },
                  ]}
                />
                {activeFilters > 0 && (
                  <button
                    type="button"
                    className="text-2xs text-accent hover:underline"
                    onClick={() => {
                      setSeverity([]);
                      setStatus([]);
                      setQ('');
                    }}
                  >
                    Clear all
                  </button>
                )}
              </div>
            </div>
          )}

          <p className="text-2xs text-ink-3">
            {list.loading ? 'Loading…' : `${list.data?.total ?? 0} case(s)`}
          </p>
        </div>

        <div className="scroll-y flex-1 min-h-0">
          {list.error ? (
            <ErrorState error={list.error} onRetry={list.refresh} className="py-8" />
          ) : list.loading && !list.data ? (
            <Loading className="py-10" />
          ) : list.data?.items?.length ? (
            <ul>
              {list.data.items.map((incident) => (
                <li key={incident.ref}>
                  <button
                    type="button"
                    onClick={() => selectRef(incident.ref)}
                    className={cx(
                      'w-full text-left px-3 py-2.5 border-b border-line/70 transition-colors duration-120',
                      selectedRef === incident.ref ? 'bg-accent/[0.07]' : 'hover:bg-sunken',
                    )}
                  >
                    <div className="flex items-start gap-2">
                      <SeverityDot value={incident.severity} className="mt-1.5" />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-2xs text-ink-3">{incident.ref}</span>
                          <span className="text-2xs text-ink-3 shrink-0">
                            {relativeTime(incident.created_at)}
                          </span>
                        </div>
                        <p
                          className={cx(
                            'text-sm mt-0.5 leading-snug line-clamp-2',
                            selectedRef === incident.ref ? 'text-ink font-medium' : 'text-ink',
                          )}
                        >
                          {incident.title}
                        </p>
                        <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
                          <StatusBadge value={incident.status} />
                          {incident.open_tasks > 0 && (
                            <span className="text-2xs text-ink-3">
                              {incident.total_tasks - incident.open_tasks}/{incident.total_tasks} tasks
                            </span>
                          )}
                          <span className="ml-auto"><RiskMeter score={incident.risk_score} size="sm" /></span>
                        </div>
                      </div>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <Empty icon={IconAlert} title="No cases match" hint="Try clearing filters or widening your search." />
          )}
        </div>

        {list.data && list.data.total > 30 && (
          <div className="flex items-center justify-between px-3 py-2 border-t border-line shrink-0">
            <Button size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
              <IconChevron size={12} className="rotate-180" /> Prev
            </Button>
            <span className="text-2xs text-ink-3">
              Page {page} of {Math.ceil(list.data.total / 30)}
            </span>
            <Button
              size="sm"
              onClick={() => setPage((p) => p + 1)}
              disabled={page >= Math.ceil(list.data.total / 30)}
            >
              Next <IconChevron size={12} />
            </Button>
          </div>
        )}
      </div>

      {/* ============================================================= CASE */}
      <div className="flex-1 min-w-0 min-h-0">
        {selectedRef ? (
          <CaseDetail
            ref_={selectedRef}
            onChanged={() => {
              list.refresh();
            }}
          />
        ) : (
          <Empty icon={IconTarget} title="Select a case" className="h-full" />
        )}
      </div>

      <SimulateModal
        open={simulateOpen}
        onClose={() => setSimulateOpen(false)}
        onCreated={(ref) => {
          setSimulateOpen(false);
          list.refresh();
          selectRef(ref);
          toast.success(`Simulation ${ref} created and investigated.`);
        }}
      />
    </div>
  );
}

/* =============================================================== CASE PANE */
function CaseDetail({ ref_, onChanged }) {
  const { can } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState('workspace');
  const [note, setNote] = useState('');
  const [investigating, setInvestigating] = useState(false);
  const [exporting, setExporting] = useState(false);

  const detail = useAsync(() => api.incident(ref_), [ref_]);
  const incident = detail.data;

  if (detail.error) return <ErrorState error={detail.error} onRetry={detail.refresh} className="h-full" />;
  if (!incident) return <Loading className="h-full" />;

  const canWrite = can('incidents:write');
  const canClose = can('incidents:close');

  const runInvestigation = async () => {
    setInvestigating(true);
    try {
      await api.investigate(ref_);
      toast.success('Investigation complete — 9 agents ran.');
      await detail.refresh();
      onChanged();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setInvestigating(false);
    }
  };

  const updateStatus = async (nextStatus) => {
    try {
      await api.updateIncident(ref_, { status: nextStatus });
      await detail.refresh();
      onChanged();
      toast.success(`Status updated to ${titleCase(nextStatus)}.`);
    } catch (err) {
      toast.error(err.message);
    }
  };

  const submitNote = async () => {
    if (!note.trim()) return;
    try {
      await api.addNote(ref_, note.trim());
      setNote('');
      await detail.refresh();
    } catch (err) {
      toast.error(err.message);
    }
  };

  const togglePlaybook = async (itemId, completed) => {
    try {
      const updated = await api.togglePlaybookItem(ref_, itemId, completed);
      detail.setData(updated);
      onChanged();
    } catch (err) {
      toast.error(err.message);
    }
  };

  const exportReport = async () => {
    setExporting(true);
    try {
      await api.incidentReport(ref_);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setExporting(false);
    }
  };

  const doneTasks = incident.playbook_items.filter((i) => i.completed).length;

  return (
    <div className="h-full flex flex-col min-h-0">
      {/* ---------------------------------------------------------- header */}
      <div className="shrink-0 border-b border-line px-4 py-3">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-ink-3">{incident.ref}</span>
              <SeverityBadge value={incident.severity} />
              <StatusBadge value={incident.status} />
              <span className="badge badge-outline">{incident.priority}</span>
            </div>
            <h1 className="text-lg font-semibold text-ink mt-1 leading-snug">{incident.title}</h1>
            <div className="flex items-center gap-3 mt-1.5 text-2xs text-ink-3 flex-wrap">
              <span>{titleCase(incident.category)}</span>
              <span>·</span>
              <span>{incident.asset} ({incident.asset_criticality})</span>
              <span>·</span>
              <span>origin {incident.src_ip || 'internal'}</span>
              <span>·</span>
              <span>opened {formatDate(incident.created_at)}</span>
              {incident.sla_due_at && (
                <>
                  <span>·</span>
                  <span className="flex items-center gap-1">
                    <IconClock size={11} /> SLA {formatDate(incident.sla_due_at)}
                  </span>
                </>
              )}
            </div>
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            <RiskMeter score={incident.risk_score} />
            <Select
              value={incident.status}
              onChange={(e) => updateStatus(e.target.value)}
              className="h-8 text-xs w-auto"
              disabled={!canWrite || (['closed', 'false_positive'].includes(incident.status) && !canClose)}
              options={STATUS_ORDER.filter((s) => {
                if (['closed', 'false_positive'].includes(s)) return canClose;
                return true;
              }).map((s) => ({ value: s, label: titleCase(s) }))}
            />
            <Button size="sm" icon={IconDownload} onClick={exportReport} disabled={exporting}>
              {exporting ? 'Exporting…' : 'PDF'}
            </Button>
          </div>
        </div>

        {!canWrite && (
          <div className="mt-2.5">
            <LockedNotice>Viewer role — case actions, notes and the playbook are read-only.</LockedNotice>
          </div>
        )}
      </div>

      {/* ------------------------------------------------------------- tabs */}
      <Tabs
        tabs={[
          { key: 'workspace', label: 'Agent workspace' },
          { key: 'playbook', label: 'Playbook', count: `${doneTasks}/${incident.playbook_items.length}` },
          { key: 'chain', label: 'Threat chain' },
          { key: 'evidence', label: 'Evidence', count: incident.events.length },
          { key: 'notes', label: 'Notes', count: incident.notes.length },
        ]}
        active={tab}
        onChange={setTab}
        className="shrink-0 px-4"
      />

      <div className="flex-1 min-h-0 overflow-hidden">
        {tab === 'workspace' && (
          <AgentTimeline
            runs={incident.runs}
            onInvestigate={runInvestigation}
            canRun={can('agents:run')}
            running={investigating}
          />
        )}

        {tab === 'playbook' && (
          <div className="scroll-y h-full p-4">
            {incident.playbook_key && (
              <p className="text-xs text-ink-3 mb-3">
                Playbook <span className="font-mono text-ink-2">{incident.playbook_key}</span> ·{' '}
                {doneTasks}/{incident.playbook_items.length} steps complete
              </p>
            )}
            {!canWrite && <LockedNotice>Checklist items are locked for your role.</LockedNotice>}
            <div className="space-y-4 mt-3">
              {['identification', 'containment', 'eradication', 'recovery', 'lessons-learned'].map((phase) => {
                const items = incident.playbook_items.filter((i) => i.phase === phase);
                if (!items.length) return null;
                return (
                  <div key={phase}>
                    <p className="section-label mb-2">{PHASE_LABEL[phase] || titleCase(phase)}</p>
                    <div className="space-y-2.5">
                      {items.map((item) => (
                        <div
                          key={item.id}
                          className={cx(
                            'rounded border border-line px-3 py-2.5',
                            item.completed && 'bg-sunken/60',
                          )}
                        >
                          <Checkbox
                            checked={item.completed}
                            disabled={!canWrite}
                            onChange={(checked) => togglePlaybook(item.id, checked)}
                            label={item.title}
                            hint={
                              item.detail +
                              (item.completed_by
                                ? ` — completed by ${item.completed_by} ${relativeTime(item.completed_at)}`
                                : '') +
                              (item.automatable ? ' · SOAR-automatable' : '')
                            }
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
              {!incident.playbook_items.length && (
                <Empty title="No playbook attached" hint="Run an investigation to select and attach a response playbook." />
              )}
            </div>
          </div>
        )}

        {tab === 'chain' && (
          <div className="scroll-y h-full p-4">
            <ThreatChainView chain={incident.threat_chain} />
            {incident.root_cause && (
              <div className="mt-4 rounded border border-line p-3 max-w-2xl">
                <p className="section-label mb-1.5">Root cause</p>
                <p className="text-sm text-ink-2 leading-relaxed">{incident.root_cause}</p>
              </div>
            )}
          </div>
        )}

        {tab === 'evidence' && (
          <div className="h-full overflow-auto">
            {incident.events.length ? (
              <table className="dtable">
                <thead>
                  <tr>
                    <th className="w-[130px]">Time (UTC)</th>
                    <th className="w-[90px]">Source</th>
                    <th className="w-[130px]">Host</th>
                    <th className="w-[70px]">Sev</th>
                    <th className="w-[130px]">Type</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {incident.events.map((event) => (
                    <tr key={event.id}>
                      <td className="font-mono text-2xs whitespace-nowrap">{formatFullDate(event.ts)}</td>
                      <td className="text-xs">{event.source}</td>
                      <td className="text-xs font-mono">{event.host}</td>
                      <td><SeverityBadge value={event.severity} /></td>
                      <td className="text-xs">{event.event_type}</td>
                      <td className="text-xs text-ink-2 max-w-0">
                        <span className="block truncate" title={event.message}>{event.message}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty title="No correlated evidence" className="py-16" />
            )}
          </div>
        )}

        {tab === 'notes' && (
          <div className="h-full flex flex-col min-h-0">
            <div className="scroll-y flex-1 p-4 space-y-3">
              {incident.notes.length ? (
                incident.notes.map((n) => (
                  <div key={n.id} className="flex gap-2.5">
                    <span
                      className={cx(
                        'w-1 rounded-full shrink-0',
                        n.kind === 'system' ? 'bg-info' : n.kind === 'status' ? 'bg-accent' : 'bg-line-strong',
                      )}
                    />
                    <div className="min-w-0 flex-1 pb-1">
                      <div className="flex items-center gap-2 text-2xs text-ink-3">
                        <span className="font-medium text-ink-2">{n.author_name || 'System'}</span>
                        <span>{formatFullDate(n.created_at)}</span>
                        {n.kind !== 'note' && <span className="badge-outline badge">{n.kind}</span>}
                      </div>
                      <p className="text-sm text-ink-2 mt-0.5 leading-relaxed whitespace-pre-wrap">{n.body}</p>
                    </div>
                  </div>
                ))
              ) : (
                <Empty title="No notes yet" className="py-10" />
              )}
            </div>
            <div className="shrink-0 border-t border-line p-3">
              {canWrite ? (
                <div className="flex items-end gap-2">
                  <textarea
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="Add an analyst note…"
                    rows={2}
                    className="field resize-none flex-1 py-1.5"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) submitNote();
                    }}
                  />
                  <Button variant="primary" icon={IconSend} onClick={submitNote} disabled={!note.trim()}>
                    Post
                  </Button>
                </div>
              ) : (
                <LockedNotice>Notes are read-only for the Viewer role.</LockedNotice>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ============================================================ SIMULATE MODAL */
function SimulateModal({ open, onClose, onCreated }) {
  const scenarios = useAsync(() => api.scenarios(), [], { immediate: open });
  const [selected, setSelected] = useState('random');
  const [runAgents, setRunAgents] = useState(true);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (open) scenarios.refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const run = async () => {
    setBusy(true);
    try {
      const result = await api.simulate(selected, runAgents);
      onCreated(result.ref);
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : 'Simulation failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Trigger threat simulation"
      subtitle="Generates a synthetic incident with correlated telemetry — administrator only"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" icon={IconPlay} onClick={run} disabled={busy}>
            {busy ? 'Running…' : 'Launch scenario'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Scenario">
          <Select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            options={[
              { value: 'random', label: 'Random scenario' },
              ...(scenarios.data?.scenarios || []).map((s) => ({ value: s.key, label: s.title })),
            ]}
          />
        </Field>
        <Checkbox
          checked={runAgents}
          onChange={setRunAgents}
          label="Run the 9-agent investigation immediately"
          hint="Otherwise the case is created new and un-investigated, like a real detection."
        />
      </div>
    </Modal>
  );
}

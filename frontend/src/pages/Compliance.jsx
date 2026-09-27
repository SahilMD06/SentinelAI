import { useState } from 'react';
import {
  Button,
  ControlStatusBadge,
  Empty,
  ErrorState,
  Field,
  Loading,
  LockedNotice,
  Modal,
  Panel,
  Select,
  cx,
  useToast,
} from '../components/ui';
import { Donut } from '../components/charts';
import { IconDownload, IconLink, IconShieldCheck } from '../components/icons';
import { api } from '../lib/api';
import { useAsync } from '../lib/hooks';
import { useAuth } from '../lib/auth';
import { formatDate } from '../lib/format';

const STATUS_OPTIONS = [
  { value: 'compliant', label: 'Compliant' },
  { value: 'partial', label: 'Partial' },
  { value: 'gap', label: 'Gap' },
  { value: 'na', label: 'Not applicable' },
];

export default function Compliance() {
  const { can } = useAuth();
  const toast = useToast();
  const [framework, setFramework] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [editing, setEditing] = useState(null);
  const [exporting, setExporting] = useState(null);

  const overview = useAsync(() => api.complianceOverview(), []);
  const controls = useAsync(
    () => api.complianceControls({ framework: framework || undefined, status: statusFilter || undefined }),
    [framework, statusFilter],
  );
  const linkage = useAsync(() => api.complianceLinkage(), []);

  const exportPdf = async (fw) => {
    setExporting(fw || 'all');
    try {
      await api.complianceReport(fw || undefined);
    } catch (err) {
      toast.error(err.message);
    } finally {
      setExporting(null);
    }
  };

  if (overview.error) return <ErrorState error={overview.error} onRetry={overview.refresh} />;

  return (
    <div className="p-4 space-y-4">
      <div className="grid md:grid-cols-2 gap-4">
        {(overview.data?.frameworks || []).map((fw) => (
          <Panel
            key={fw.framework}
            title={fw.framework === 'ISO27001' ? 'ISO/IEC 27001:2022' : fw.framework}
            subtitle={`${fw.total} controls in scope`}
            actions={
              <Button
                size="sm"
                icon={IconDownload}
                onClick={() => exportPdf(fw.framework)}
                disabled={exporting === fw.framework}
                locked={!can('reports:export')}
              >
                {exporting === fw.framework ? 'Exporting…' : 'Export'}
              </Button>
            }
          >
            <div className="flex items-center gap-5">
              <Donut
                segments={[
                  { label: 'compliant', value: fw.compliant },
                  { label: 'partial', value: fw.partial },
                  { label: 'gap', value: fw.gaps },
                  { label: 'na', value: fw.not_applicable },
                ].filter((s) => s.value > 0)}
                centerValue={`${fw.score}%`}
                centerLabel="score"
              />
              <div className="flex-1 space-y-1.5 text-xs">
                <Row label="Compliant" value={fw.compliant} tone="text-success" />
                <Row label="Partial" value={fw.partial} tone="text-medium" />
                <Row label="Gaps" value={fw.gaps} tone="text-critical" />
                <Row label="Not applicable" value={fw.not_applicable} tone="text-ink-3" />
              </div>
            </div>
          </Panel>
        ))}
      </div>

      <Panel
        title="Controls at risk from open incidents"
        subtitle="Cross-referenced from active case categories"
        dense
        bodyClass="p-0"
      >
        {linkage.data?.controls_under_pressure?.length ? (
          <ul className="divide-y divide-line">
            {linkage.data.controls_under_pressure.slice(0, 8).map((item) => (
              <li key={`${item.framework}:${item.control_id}`} className="px-4 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-ink">
                    {item.framework} {item.control_id} — {item.title}
                  </span>
                  <span className="badge badge-outline">{item.incidents.length} case(s)</span>
                </div>
                <p className="text-2xs text-ink-3 mt-1 flex items-center gap-1.5 flex-wrap">
                  <IconLink size={11} className="shrink-0" />
                  {item.incidents.map((i) => i.ref).join(', ')}
                </p>
              </li>
            ))}
          </ul>
        ) : (
          <Empty title="No control pressure" hint="No open incidents currently implicate a compliance control." className="py-8" />
        )}
      </Panel>

      <Panel
        title="Control register"
        actions={
          <div className="flex items-center gap-1.5">
            <Select
              value={framework}
              onChange={(e) => setFramework(e.target.value)}
              className="h-7 text-xs w-auto"
              options={[{ value: '', label: 'All frameworks' }, { value: 'ISO27001', label: 'ISO27001' }, { value: 'SOC2', label: 'SOC2' }]}
            />
            <Select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-7 text-xs w-auto"
              options={[{ value: '', label: 'All statuses' }, ...STATUS_OPTIONS]}
            />
            <Button size="sm" icon={IconDownload} onClick={() => exportPdf(framework)} disabled={!!exporting}>
              Export
            </Button>
          </div>
        }
        dense
        bodyClass="p-0"
      >
        {controls.loading && !controls.data ? (
          <Loading className="py-10" />
        ) : controls.data?.length ? (
          <table className="dtable">
            <thead>
              <tr>
                <th className="w-[90px]">Framework</th>
                <th className="w-[90px]">Control</th>
                <th>Title</th>
                <th className="w-[130px]">Owner</th>
                <th className="w-[110px]">Status</th>
                <th className="w-[100px]">Reviewed</th>
              </tr>
            </thead>
            <tbody>
              {controls.data.map((control) => (
                <tr key={control.id} className="cursor-pointer" onClick={() => setEditing(control)}>
                  <td className="text-2xs text-ink-3">{control.framework}</td>
                  <td className="font-mono text-xs">{control.control_id}</td>
                  <td className="text-xs text-ink max-w-0"><span className="block truncate">{control.title}</span></td>
                  <td className="text-2xs text-ink-3">{control.owner}</td>
                  <td><ControlStatusBadge value={control.status} /></td>
                  <td className="text-2xs text-ink-3">{formatDate(control.last_reviewed, { dateStyle: undefined, day: '2-digit', month: 'short', year: '2-digit' })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty icon={IconShieldCheck} title="No controls match" className="py-10" />
        )}
      </Panel>

      <ControlModal
        control={editing}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          controls.refresh();
          overview.refresh();
        }}
      />
    </div>
  );
}

function Row({ label, value, tone }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-ink-3">{label}</span>
      <span className={cx('tnum font-medium', tone)}>{value}</span>
    </div>
  );
}

function ControlModal({ control, onClose, onSaved }) {
  const { can } = useAuth();
  const toast = useToast();
  const [status, setStatus] = useState(control?.status || 'compliant');
  const [evidence, setEvidence] = useState(control?.evidence || '');
  const [gapNotes, setGapNotes] = useState(control?.gap_notes || '');
  const [owner, setOwner] = useState(control?.owner || '');
  const [busy, setBusy] = useState(false);

  if (!control) return null;
  const canEdit = can('compliance:write');

  const save = async () => {
    setBusy(true);
    try {
      await api.updateControl(control.id, { status, evidence, gap_notes: gapNotes, owner });
      toast.success('Control updated.');
      onSaved();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={!!control}
      onClose={onClose}
      title={`${control.framework} ${control.control_id}`}
      subtitle={control.title}
      footer={
        canEdit ? (
          <>
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" onClick={save} disabled={busy}>
              {busy ? 'Saving…' : 'Save changes'}
            </Button>
          </>
        ) : (
          <Button onClick={onClose}>Close</Button>
        )
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-ink-2 leading-relaxed">{control.description}</p>
        {!canEdit && <LockedNotice>Editing controls requires Administrator access.</LockedNotice>}
        <Field label="Status">
          <Select value={status} onChange={(e) => setStatus(e.target.value)} options={STATUS_OPTIONS} disabled={!canEdit} />
        </Field>
        <Field label="Owner">
          <input value={owner} onChange={(e) => setOwner(e.target.value)} className="field" disabled={!canEdit} />
        </Field>
        <Field label="Evidence">
          <textarea value={evidence} onChange={(e) => setEvidence(e.target.value)} rows={3} className="field resize-none py-1.5" disabled={!canEdit} />
        </Field>
        <Field label="Gap notes">
          <textarea value={gapNotes} onChange={(e) => setGapNotes(e.target.value)} rows={3} className="field resize-none py-1.5" disabled={!canEdit} />
        </Field>
      </div>
    </Modal>
  );
}

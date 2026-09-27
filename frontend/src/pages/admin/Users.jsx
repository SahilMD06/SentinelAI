import { useState } from 'react';
import {
  Button,
  Checkbox,
  Empty,
  ErrorState,
  Field,
  Loading,
  Modal,
  Panel,
  Select,
  Tabs,
  cx,
  useToast,
} from '../../components/ui';
import { IconClock, IconPlus, IconUsers } from '../../components/icons';
import { api } from '../../lib/api';
import { useAsync, useDebounced } from '../../lib/hooks';
import { useAuth } from '../../lib/auth';
import { formatFullDate, initials, relativeTime, titleCase } from '../../lib/format';

const ROLE_TONE = {
  admin: 'text-critical border-critical/30 bg-critical/8',
  manager: 'text-high border-high/30 bg-high/8',
  analyst: 'text-accent border-accent/30 bg-accent/8',
  viewer: 'text-ink-2 border-line bg-sunken',
};

export default function Users() {
  const { user: me } = useAuth();
  const toast = useToast();
  const [tab, setTab] = useState('users');
  const [q, setQ] = useState('');
  const debouncedQ = useDebounced(q, 300);
  const [roleFilter, setRoleFilter] = useState('');
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);

  const users = useAsync(
    () => api.users({ q: debouncedQ || undefined, role: roleFilter || undefined }),
    [debouncedQ, roleFilter],
  );
  const roles = useAsync(() => api.roles(), []);
  const audit = useAsync(() => api.auditLog({ limit: 100 }), [], { immediate: tab === 'audit' });

  const refreshAll = () => {
    users.refresh();
  };

  const deactivate = async (u) => {
    try {
      const res = await api.deactivateUser(u.id);
      toast.success(
        res.open_cases_still_assigned
          ? `${u.email} deactivated — ${res.open_cases_still_assigned} open case(s) remain assigned.`
          : `${u.email} deactivated.`,
      );
      refreshAll();
    } catch (err) {
      toast.error(err.message);
    }
  };

  const reactivate = async (u) => {
    try {
      await api.updateUser(u.id, { is_active: true });
      toast.success(`${u.email} reactivated.`);
      refreshAll();
    } catch (err) {
      toast.error(err.message);
    }
  };

  return (
    <div className="p-4 space-y-4">
      <div className="grid sm:grid-cols-3 gap-3">
        {(roles.data?.roles || []).map((role) => (
          <div key={role.key} className="panel px-3.5 py-3">
            <div className="flex items-center justify-between mb-1">
              <span className={cx('badge border', ROLE_TONE[role.key])}>{role.label}</span>
              <span className="text-2xs tnum text-ink-3">{role.capability_count} capabilities</span>
            </div>
            <p className="text-2xs tnum text-ink-2">
              {(users.data || []).filter((u) => u.role === role.key).length} provisioned
            </p>
          </div>
        ))}
      </div>

      <Panel dense bodyClass="p-0">
        <div className="px-4 pt-3">
          <Tabs
            tabs={[
              { key: 'users', label: 'Users', count: users.data?.length },
              { key: 'audit', label: 'Audit log' },
            ]}
            active={tab}
            onChange={(k) => {
              setTab(k);
              if (k === 'audit') audit.refresh();
            }}
          />
        </div>

        {tab === 'users' ? (
          <>
            <div className="flex items-center gap-2 flex-wrap p-3">
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search name or email…"
                className="field h-8 w-56"
              />
              <Select
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
                className="h-8 w-auto"
                options={[
                  { value: '', label: 'All roles' },
                  ...(roles.data?.roles || []).map((r) => ({ value: r.key, label: r.label })),
                ]}
              />
              <div className="flex-1" />
              <Button variant="primary" size="sm" icon={IconPlus} onClick={() => setCreating(true)}>
                Provision user
              </Button>
            </div>

            {users.error ? (
              <ErrorState error={users.error} onRetry={users.refresh} />
            ) : users.loading && !users.data ? (
              <Loading className="py-12" />
            ) : users.data?.length ? (
              <table className="dtable">
                <thead>
                  <tr>
                    <th>User</th>
                    <th className="w-[100px]">Role</th>
                    <th className="w-[130px]">Team</th>
                    <th className="w-[90px]">Status</th>
                    <th className="w-[90px]">MFA</th>
                    <th className="w-[110px]">Last login</th>
                    <th className="w-[170px]" />
                  </tr>
                </thead>
                <tbody>
                  {users.data.map((u) => (
                    <tr key={u.id}>
                      <td onClick={() => setEditing(u)} className="cursor-pointer">
                        <div className="flex items-center gap-2.5">
                          <span className="w-7 h-7 rounded-full bg-accent/15 text-accent text-2xs font-semibold flex items-center justify-center shrink-0">
                            {initials(u.full_name)}
                          </span>
                          <div className="min-w-0">
                            <p className="text-xs font-medium text-ink truncate">{u.full_name}</p>
                            <p className="text-2xs text-ink-3 truncate">{u.email}</p>
                          </div>
                        </div>
                      </td>
                      <td>
                        <span className={cx('badge border', ROLE_TONE[u.role])}>{titleCase(u.role)}</span>
                      </td>
                      <td className="text-xs text-ink-2">{u.team}</td>
                      <td>
                        <span className={cx('badge', u.is_active ? 'badge-outline' : 'bg-critical/10 text-critical border border-critical/25')}>
                          {u.is_active ? 'Active' : 'Deactivated'}
                        </span>
                      </td>
                      <td className="text-2xs text-ink-3">{u.mfa_enrolled ? 'Enrolled' : '—'}</td>
                      <td className="text-2xs text-ink-3">
                        {u.last_login_at ? relativeTime(u.last_login_at) : 'never'}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <Button size="sm" onClick={() => setEditing(u)}>
                            Edit
                          </Button>
                          {u.is_active ? (
                            <Button size="sm" variant="danger" disabled={u.id === me?.id} onClick={() => deactivate(u)}>
                              Deactivate
                            </Button>
                          ) : (
                            <Button size="sm" onClick={() => reactivate(u)}>
                              Reactivate
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty icon={IconUsers} title="No users match" className="py-12" />
            )}
          </>
        ) : (
          <div>
            {audit.loading && !audit.data ? (
              <Loading className="py-12" />
            ) : audit.data?.length ? (
              <table className="dtable">
                <thead>
                  <tr>
                    <th className="w-[130px]">When</th>
                    <th className="w-[190px]">Actor</th>
                    <th className="w-[150px]">Action</th>
                    <th>Detail</th>
                    <th className="w-[110px]">IP</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.data.map((row) => (
                    <tr key={row.id}>
                      <td className="text-2xs text-ink-3 whitespace-nowrap">{formatFullDate(row.created_at)}</td>
                      <td className="text-xs text-ink truncate">{row.actor_email}</td>
                      <td className="font-mono text-2xs text-accent">{row.action}</td>
                      <td className="text-xs text-ink-2 max-w-0"><span className="block truncate" title={row.detail}>{row.detail}</span></td>
                      <td className="font-mono text-2xs text-ink-3">{row.ip || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty icon={IconClock} title="No audit events yet" className="py-12" />
            )}
          </div>
        )}
      </Panel>

      <UserModal
        mode="create"
        open={creating}
        roles={roles.data?.roles || []}
        onClose={() => setCreating(false)}
        onSaved={() => {
          setCreating(false);
          refreshAll();
        }}
      />
      <UserModal
        mode="edit"
        open={!!editing}
        user={editing}
        roles={roles.data?.roles || []}
        onClose={() => setEditing(null)}
        onSaved={() => {
          setEditing(null);
          refreshAll();
        }}
      />
    </div>
  );
}

function UserModal({ mode, open, user, roles, onClose, onSaved }) {
  const toast = useToast();
  const isEdit = mode === 'edit';
  const [fullName, setFullName] = useState(user?.full_name || '');
  const [email, setEmail] = useState(user?.email || '');
  const [role, setRole] = useState(user?.role || 'viewer');
  const [team, setTeam] = useState(user?.team || 'SOC');
  const [jobTitle, setJobTitle] = useState(user?.job_title || 'Security Staff');
  const [password, setPassword] = useState('');
  const [isActive, setIsActive] = useState(user?.is_active ?? true);
  const [busy, setBusy] = useState(false);

  // Re-seed local state whenever a different record is opened.
  const [openedFor, setOpenedFor] = useState(null);
  if (open && openedFor !== (user?.id ?? 'new')) {
    setOpenedFor(user?.id ?? 'new');
    setFullName(user?.full_name || '');
    setEmail(user?.email || '');
    setRole(user?.role || 'viewer');
    setTeam(user?.team || 'SOC');
    setJobTitle(user?.job_title || 'Security Staff');
    setPassword('');
    setIsActive(user?.is_active ?? true);
  }

  if (!open) return null;

  const save = async () => {
    setBusy(true);
    try {
      if (isEdit) {
        await api.updateUser(user.id, {
          full_name: fullName,
          role,
          team,
          job_title: jobTitle,
          is_active: isActive,
          password: password || undefined,
        });
        toast.success('User updated.');
      } else {
        await api.createUser({
          email,
          full_name: fullName,
          password,
          role,
          team,
          job_title: jobTitle,
          is_active: isActive,
        });
        toast.success('User provisioned.');
      }
      onSaved();
    } catch (err) {
      toast.error(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? 'Edit user' : 'Provision user'}
      subtitle={isEdit ? user?.email : 'Self-registration is disabled — accounts are created here.'}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            onClick={save}
            disabled={busy || !fullName.trim() || (!isEdit && (!email.trim() || password.length < 8))}
          >
            {busy ? 'Saving…' : isEdit ? 'Save changes' : 'Create user'}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <Field label="Full name" required>
          <input value={fullName} onChange={(e) => setFullName(e.target.value)} className="field" />
        </Field>
        {!isEdit && (
          <Field label="Work email" required>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="field" />
          </Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Role">
            <Select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              options={roles.map((r) => ({ value: r.key, label: r.label }))}
            />
          </Field>
          <Field label="Team">
            <input value={team} onChange={(e) => setTeam(e.target.value)} className="field" />
          </Field>
        </div>
        <Field label="Job title">
          <input value={jobTitle} onChange={(e) => setJobTitle(e.target.value)} className="field" />
        </Field>
        <Field
          label={isEdit ? 'Reset password (optional)' : 'Temporary password'}
          required={!isEdit}
          hint="Minimum 8 characters — shared with the user out of band."
        >
          <input
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="field font-mono"
            placeholder={isEdit ? 'Leave blank to keep current password' : 'e.g. Analyst@2026'}
          />
        </Field>
        <Checkbox
          id="user-active"
          checked={isActive}
          onChange={setIsActive}
          label="Account active"
          hint="Deactivated users cannot sign in but keep their assignment and audit history."
        />
      </div>
    </Modal>
  );
}

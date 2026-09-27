import { NavLink } from 'react-router-dom';
import Logo from './Logo';
import { Tooltip, cx } from './ui';
import { useAuth } from '../lib/auth';
import { initials } from '../lib/format';
import {
  IconAlert,
  IconAnomaly,
  IconCollapse,
  IconGauge,
  IconSearch,
  IconServer,
  IconSettings,
  IconShieldCheck,
  IconSpark,
  IconStream,
  IconTrace,
  IconUsers,
} from './icons';

/**
 * Navigation is derived from the capability list the API returns with the
 * session — the sidebar cannot drift from what the backend actually allows,
 * because both read the same matrix.
 */
const SECTIONS = [
  {
    label: 'Operate',
    items: [
      { to: '/', label: 'Overview', icon: IconGauge, end: true, capability: 'incidents:read' },
      { to: '/incidents', label: 'Incidents', icon: IconAlert, capability: 'incidents:read' },
      { to: '/feed', label: 'SOC Feed', icon: IconStream, capability: 'events:read' },
      { to: '/anomalies', label: 'Anomalies', icon: IconAnomaly, capability: 'anomaly:read' },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { to: '/hunt', label: 'Threat Hunting', icon: IconSearch, capability: 'hunt:read' },
      { to: '/copilot', label: 'Copilot', icon: IconSpark, capability: 'copilot:chat' },
      { to: '/intel', label: 'Threat Intel', icon: IconServer, capability: 'intel:lookup' },
    ],
  },
  {
    label: 'Govern',
    items: [
      { to: '/compliance', label: 'Compliance', icon: IconShieldCheck, capability: 'compliance:read' },
      { to: '/observability', label: 'Observability', icon: IconTrace, capability: 'tracing:read' },
    ],
  },
  {
    label: 'Administer',
    items: [
      { to: '/admin/users', label: 'User Management', icon: IconUsers, capability: 'users:write' },
      { to: '/settings', label: 'Settings', icon: IconSettings, capability: 'incidents:read' },
    ],
  },
];

export default function Sidebar({ collapsed, onToggle }) {
  const { can, user, roleLabel } = useAuth();

  const sections = SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => !item.capability || can(item.capability)),
  })).filter((section) => section.items.length > 0);

  return (
    <aside
      className={cx(
        'shrink-0 h-full flex flex-col bg-surface border-r border-line transition-[width] duration-200',
        collapsed ? 'w-[58px]' : 'w-[228px]',
      )}
    >
      <div
        className={cx(
          'h-[52px] flex items-center border-b border-line shrink-0',
          collapsed ? 'justify-center px-2' : 'justify-between pl-3.5 pr-2',
        )}
      >
        <Logo collapsed={collapsed} size={collapsed ? 24 : 26} />
        {!collapsed && (
          <button
            type="button"
            onClick={onToggle}
            className="btn-ghost btn-sm px-1.5"
            aria-label="Collapse sidebar"
          >
            <IconCollapse size={15} />
          </button>
        )}
      </div>

      {collapsed && (
        <button
          type="button"
          onClick={onToggle}
          className="btn-ghost btn-sm mx-auto mt-2 px-1.5"
          aria-label="Expand sidebar"
        >
          <IconCollapse size={15} />
        </button>
      )}

      <nav className="flex-1 scroll-y px-2 py-3 space-y-4">
        {sections.map((section) => (
          <div key={section.label}>
            {!collapsed && (
              <p className="section-label px-2 mb-1.5">{section.label}</p>
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const link = (
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      cx(
                        'nav-item',
                        collapsed && 'justify-center px-0',
                        isActive && 'nav-item-active',
                      )
                    }
                  >
                    <item.icon size={16} className="shrink-0" />
                    {!collapsed && <span className="truncate">{item.label}</span>}
                  </NavLink>
                );
                return (
                  <li key={item.to} className={collapsed ? 'flex justify-center' : ''}>
                    {collapsed ? (
                      <Tooltip label={item.label} side="right">
                        {link}
                      </Tooltip>
                    ) : (
                      link
                    )}
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div
        className={cx(
          'border-t border-line shrink-0',
          collapsed ? 'p-2 flex justify-center' : 'p-2.5',
        )}
      >
        {collapsed ? (
          <Tooltip label={`${user?.full_name} · ${roleLabel}`} side="right">
            <span className="w-8 h-8 rounded-full bg-accent/15 text-accent text-2xs font-semibold flex items-center justify-center">
              {initials(user?.full_name)}
            </span>
          </Tooltip>
        ) : (
          <div className="flex items-center gap-2.5 min-w-0">
            <span className="w-8 h-8 rounded-full bg-accent/15 text-accent text-2xs font-semibold flex items-center justify-center shrink-0">
              {initials(user?.full_name)}
            </span>
            <span className="min-w-0 flex flex-col leading-tight">
              <span className="text-xs font-medium text-ink truncate">{user?.full_name}</span>
              <span className="text-2xs text-ink-3 truncate">{roleLabel}</span>
            </span>
          </div>
        )}
      </div>
    </aside>
  );
}

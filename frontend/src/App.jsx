import { useMemo, useState } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';
import { Spinner } from './components/ui';
import { LogoMark } from './components/Logo';
import { useAuth } from './lib/auth';
import { useAsync, useInterval } from './lib/hooks';
import { api } from './lib/api';

import Login, { SsoCallback } from './pages/Login';
import Overview from './pages/Overview';
import Incidents from './pages/Incidents';
import Feed from './pages/Feed';
import Hunt from './pages/Hunt';
import Compliance from './pages/Compliance';
import Anomalies from './pages/Anomalies';
import Intel from './pages/Intel';
import Observability from './pages/Observability';
import Copilot from './pages/Copilot';
import Settings from './pages/Settings';
import Users from './pages/admin/Users';

/**
 * Every destination declares its own title/subtitle and the capability that
 * gates it, mirroring Sidebar's SECTIONS so nothing can be reached from the
 * URL bar that isn't also reachable from the nav — capability is still
 * re-checked server-side on every request regardless.
 */
const ROUTES = [
  { path: '/', element: Overview, title: 'Overview', subtitle: 'Security posture across the last 24 hours', capability: 'incidents:read' },
  { path: '/incidents', element: Incidents, title: 'Incidents', subtitle: 'Triage console', capability: 'incidents:read' },
  { path: '/feed', element: Feed, title: 'SOC Feed', subtitle: 'Real-time ingress telemetry', capability: 'events:read' },
  { path: '/anomalies', element: Anomalies, title: 'Anomalies', subtitle: 'Behavioural detection — Isolation Forest', capability: 'anomaly:read' },
  { path: '/hunt', element: Hunt, title: 'Threat Hunting', subtitle: 'Query the raw event store', capability: 'hunt:read' },
  { path: '/copilot', element: Copilot, title: 'Security Copilot', subtitle: 'Grounded Q&A over the knowledge base', capability: 'copilot:chat' },
  { path: '/intel', element: Intel, title: 'Threat Intel', subtitle: 'Indicator reputation lookups', capability: 'intel:lookup' },
  { path: '/compliance', element: Compliance, title: 'Compliance', subtitle: 'ISO 27001 & SOC 2', capability: 'compliance:read' },
  { path: '/observability', element: Observability, title: 'Observability', subtitle: 'Agent tracing & telemetry', capability: 'tracing:read' },
  { path: '/admin/users', element: Users, title: 'User Management', subtitle: 'Provisioning & access control', capability: 'users:write' },
  { path: '/settings', element: Settings, title: 'Settings', subtitle: 'Profile, appearance & platform status', capability: 'incidents:read' },
];

export default function App() {
  const { session, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 bg-canvas">
        <LogoMark size={36} />
        <p className="flex items-center gap-2 text-sm text-ink-2">
          <Spinner /> Loading SentinelAI…
        </p>
      </div>
    );
  }

  if (!session) {
    return (
      <Routes>
        <Route path="/sso/callback" element={<SsoCallback />} />
        <Route path="*" element={<Login />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<Navigate to="/" replace />} />
      <Route path="/sso/callback" element={<Navigate to="/" replace />} />
      <Route path="/*" element={<Shell />} />
    </Routes>
  );
}

function Shell() {
  const { can } = useAuth();
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem('sentinelai.sidebar.collapsed') === '1';
    } catch {
      return false;
    }
  });

  const toggleCollapsed = () => {
    setCollapsed((current) => {
      const next = !current;
      try {
        localStorage.setItem('sentinelai.sidebar.collapsed', next ? '1' : '0');
      } catch {
        /* persistence is a convenience only */
      }
      return next;
    });
  };

  const health = useAsync(() => api.health(), []);
  useInterval(() => health.refresh(), 30000);

  const allowedRoutes = useMemo(() => ROUTES.filter((r) => can(r.capability)), [can]);
  const firstAllowedPath = allowedRoutes[0]?.path || '/';

  return (
    <div className="h-screen flex bg-canvas overflow-hidden">
      <Sidebar collapsed={collapsed} onToggle={toggleCollapsed} />
      <div className="flex-1 min-w-0 flex flex-col">
        <RoutedTopbar health={health.data} firstAllowedPath={firstAllowedPath} />
        <main className="flex-1 min-h-0 overflow-y-auto scroll-y">
          <Routes>
            {ROUTES.map(({ path, element: Element, capability }) => (
              <Route
                key={path}
                path={path}
                element={
                  <Gate capability={capability} fallback={firstAllowedPath}>
                    <Element />
                  </Gate>
                }
              />
            ))}
            <Route path="*" element={<Navigate to={firstAllowedPath} replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

function Gate({ capability, fallback, children }) {
  const { can } = useAuth();
  if (capability && !can(capability)) return <Navigate to={fallback} replace />;
  return children;
}

function RoutedTopbar({ health }) {
  const location = useLocation();
  const match =
    ROUTES.find((r) => r.path !== '/' && location.pathname.startsWith(r.path)) ||
    ROUTES.find((r) => r.path === '/');
  const title = match?.title || 'SentinelAI';
  const subtitle = match?.subtitle;
  return <Topbar title={title} subtitle={subtitle} health={health} />;
}

export { ROUTES };

/**
 * API layer.
 *
 * `installFetchInterceptor()` monkey-patches window.fetch once at boot so every
 * same-origin request to the API automatically carries the bearer token, is
 * abandoned after a timeout, and routes a 401 to a single global handler. Doing
 * it at the fetch layer rather than in a wrapper means nothing can accidentally
 * bypass auth by calling fetch directly.
 */

const TOKEN_KEY = 'sentinelai.token';
const API_BASE = import.meta.env.VITE_API_BASE || '';
const API_PREFIX = `${API_BASE}/api`;
const REQUEST_TIMEOUT_MS = 30000;

let onUnauthorized = () => {};
let installed = false;

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable — the session simply won't survive a reload */
  }
}

export function setUnauthorizedHandler(handler) {
  onUnauthorized = handler;
}

function isApiRequest(url) {
  if (typeof url !== 'string') return false;
  if (url.startsWith('/api') || url.startsWith('/health')) return true;
  if (API_BASE && url.startsWith(API_BASE)) return true;
  return false;
}

export function installFetchInterceptor() {
  if (installed) return;
  installed = true;

  const nativeFetch = window.fetch.bind(window);

  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input?.url;
    if (!isApiRequest(url)) return nativeFetch(input, init);

    const headers = new Headers(init.headers || {});
    const token = getToken();
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    if (
      init.body &&
      !(init.body instanceof FormData) &&
      !headers.has('Content-Type')
    ) {
      headers.set('Content-Type', 'application/json');
    }
    headers.set('X-Requested-With', 'SentinelAI-Console');

    // Caller-supplied signals are respected; we add our own timeout on top.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    if (init.signal) {
      init.signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    try {
      const response = await nativeFetch(input, {
        ...init,
        headers,
        signal: controller.signal,
      });

      // A 401 anywhere means the session is gone: clear it once, globally,
      // instead of letting every screen invent its own recovery.
      if (response.status === 401 && !url.includes('/auth/login')) {
        setToken(null);
        onUnauthorized();
      }
      return response;
    } finally {
      clearTimeout(timer);
    }
  };
}

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.payload = payload;
  }
}

async function parse(response) {
  const type = response.headers.get('content-type') || '';
  if (type.includes('application/json')) return response.json();
  if (type.includes('application/pdf')) return response.blob();
  return response.text();
}

async function request(path, { method = 'GET', body, signal, raw = false } = {}) {
  const url = path.startsWith('http') ? path : `${API_PREFIX}${path}`;
  const response = await fetch(url, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });

  if (raw) {
    if (!response.ok) throw new ApiError(await response.text(), response.status, null);
    return response;
  }

  const payload = await parse(response);
  if (!response.ok) {
    const detail =
      (payload && payload.detail) ||
      (typeof payload === 'string' && payload) ||
      `Request failed with ${response.status}`;
    throw new ApiError(
      Array.isArray(detail) ? detail.map((d) => d.msg || d).join('; ') : detail,
      response.status,
      payload,
    );
  }
  return payload;
}

const qs = (params = {}) => {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.append(key, value);
  });
  const string = search.toString();
  return string ? `?${string}` : '';
};

async function download(path, fallbackName) {
  const response = await request(path, { raw: true });
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/);
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = match ? match[1] : fallbackName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(href), 2000);
}

export const api = {
  // -- auth ---------------------------------------------------------------
  login: (email, password) => request('/auth/login', { method: 'POST', body: { email, password } }),
  me: () => request('/auth/me'),
  logout: () => request('/auth/logout', { method: 'POST' }),
  demoAccounts: () => request('/auth/demo-accounts'),
  ssoConfig: () => request('/auth/sso/config'),
  ssoLoginUrl: (email) => `${API_PREFIX}/auth/sso/login${qs({ email })}`,
  meta: () => request('/meta'),

  // -- dashboard ----------------------------------------------------------
  dashboard: (hours = 24) => request(`/dashboard${qs({ hours })}`),
  sla: () => request('/dashboard/sla'),

  // -- incidents ----------------------------------------------------------
  incidents: (params) => request(`/incidents${qs(params)}`),
  incidentFacets: () => request('/incidents/facets'),
  incident: (ref) => request(`/incidents/${ref}`),
  updateIncident: (ref, body) => request(`/incidents/${ref}`, { method: 'PATCH', body }),
  addNote: (ref, body) => request(`/incidents/${ref}/notes`, { method: 'POST', body: { body } }),
  togglePlaybookItem: (ref, itemId, completed) =>
    request(`/incidents/${ref}/playbook/${itemId}`, { method: 'PATCH', body: { completed } }),
  investigate: (ref) => request(`/incidents/${ref}/investigate`, { method: 'POST' }),
  threatChain: (ref) => request(`/incidents/${ref}/threat-chain`),
  incidentReport: (ref) => download(`/incidents/${ref}/report.pdf`, `${ref}-report.pdf`),
  simulate: (scenario, runAgents = true) =>
    request('/incidents/simulate', { method: 'POST', body: { scenario, run_agents: runAgents } }),
  scenarios: () => request('/incidents/simulate/scenarios'),

  // -- events -------------------------------------------------------------
  events: (params) => request(`/events${qs(params)}`),
  eventFacets: () => request('/events/facets'),
  pipeline: () => request('/events/pipeline'),
  stream: (afterId, limit = 25) => request(`/events/stream${qs({ after_id: afterId, limit })}`),
  ingest: (lines, sourceHint) =>
    request('/events/ingest', { method: 'POST', body: { lines, source_hint: sourceHint } }),
  eventAnomaly: (id) => request(`/events/${id}/anomaly`),

  // -- hunting ------------------------------------------------------------
  hunt: (body) => request('/hunt/search', { method: 'POST', body }),
  huntSchema: () => request('/hunt/schema'),
  savedHunts: () => request('/hunt/saved'),
  saveHunt: (name, query) => request('/hunt/saved', { method: 'POST', body: { name, query } }),
  deleteHunt: (id) => request(`/hunt/saved/${id}`, { method: 'DELETE' }),

  // -- compliance ---------------------------------------------------------
  complianceOverview: () => request('/compliance/overview'),
  complianceControls: (params) => request(`/compliance/controls${qs(params)}`),
  updateControl: (id, body) => request(`/compliance/controls/${id}`, { method: 'PATCH', body }),
  complianceLinkage: () => request('/compliance/incident-linkage'),
  frameworks: () => request('/compliance/frameworks'),
  complianceReport: (framework) =>
    download(
      `/compliance/report.pdf${qs({ framework })}`,
      `sentinelai-compliance-${framework || 'all'}.pdf`,
    ),

  // -- intel --------------------------------------------------------------
  intelLookup: (indicator, refresh = false) =>
    request(`/intel/lookup${qs({ refresh })}`, { method: 'POST', body: { indicator } }),
  intelHistory: () => request('/intel/history'),
  intelStatus: () => request('/intel/status'),

  // -- anomalies ----------------------------------------------------------
  anomalies: (params) => request(`/anomalies${qs(params)}`),
  anomalyStatus: () => request('/anomalies/status'),
  anomalyContext: (id) => request(`/anomalies/${id}/context`),
  modelHistory: () => request('/anomalies/model-history'),
  retrain: () => request('/anomalies/retrain', { method: 'POST' }),
  triageAnomaly: (id, status) => request(`/anomalies/${id}${qs({ status })}`, { method: 'PATCH' }),

  // -- observability ------------------------------------------------------
  tracingStats: (hours) => request(`/tracing/stats${qs({ hours })}`),
  traces: (limit = 40) => request(`/tracing/traces${qs({ limit })}`),
  trace: (id) => request(`/tracing/traces/${id}`),
  tracingConfig: () => request('/tracing/config'),

  // -- copilot / rag ------------------------------------------------------
  copilot: (message, sessionKey = 'default', incidentRef) =>
    request('/copilot/chat', {
      method: 'POST',
      body: { message, session_key: sessionKey, incident_ref: incidentRef },
    }),
  copilotHistory: (sessionKey = 'default') =>
    request(`/copilot/history${qs({ session_key: sessionKey })}`),
  ragSearch: (query, topK = 6, category) =>
    request('/rag/search', { method: 'POST', body: { query, top_k: topK, category } }),
  ragStatus: () => request('/rag/status'),
  ragReindex: () => request('/rag/reindex', { method: 'POST' }),

  // -- users --------------------------------------------------------------
  users: (params) => request(`/users${qs(params)}`),
  roles: () => request('/users/roles'),
  createUser: (body) => request('/users', { method: 'POST', body }),
  updateUser: (id, body) => request(`/users/${id}`, { method: 'PATCH', body }),
  deactivateUser: (id) => request(`/users/${id}`, { method: 'DELETE' }),
  auditLog: (params) => request(`/users/audit${qs(params)}`),

  // -- system -------------------------------------------------------------
  health: () => request(`${API_BASE}/health`),
};

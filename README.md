# SentinelAI — Intelligent SecOps & Threat Response Platform

A full-stack security operations console: a nine-agent investigation pipeline, hybrid
semantic search over MITRE ATT&CK and internal playbooks, behavioural anomaly detection,
threat-intel enrichment, agentic tracing, and ISO 27001 / SOC 2 compliance tracking — all
enforced through server-side, capability-based RBAC.

The platform is built to run **fully offline with zero configuration**: every optional
integration (vector embeddings, threat-intel providers, Redis cache, tracing exporters,
SSO) ships with a deterministic local fallback that activates automatically when the real
credentials aren't present, and swaps in the live version the moment they are.

## Stack

- **Backend** — FastAPI + SQLAlchemy 2.0, PostgreSQL in production with an automatic
  SQLite fallback for offline dev, JWT auth with bcrypt password hashing, a 9-agent
  orchestration pipeline, a hybrid TF-IDF/vector RAG engine, an Isolation Forest anomaly
  daemon, and a reportlab PDF exporter.
- **Frontend** — React 18 + Vite, react-router, Tailwind CSS with a CSS-variable design
  system for seamless dark/light theming, no UI component library — every component is
  custom-built for a dense, Datadog/Splunk-style operations console.

## Quick start (local dev, no Docker)

```bash
# 1. Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate      # or your preferred env manager
pip install -r requirements.txt
cp .env.example .env                                     # optional — defaults work as-is
uvicorn app.main:app --reload                             # → http://localhost:8000/docs

# 2. Frontend (separate terminal)
cd frontend
npm install
npm run dev                                                # → http://localhost:5173
```

The backend seeds itself automatically on first boot: 4 demo users, 130+ security events,
100+ knowledge-base documents, 50+ incidents, and 20+ full agent investigation timelines.
Seeding only runs when the database is empty, so subsequent restarts are instant.

## Quick start (Docker Compose)

```bash
docker compose up --build
# → frontend   http://localhost:3000
# → backend    http://localhost:8000/docs
```

This brings up the backend, the frontend (built and served via nginx, which also
reverse-proxies `/api` to the backend so the browser only ever talks to one origin),
Postgres, and Redis. Copy `.env.example` to `.env` at the repo root first if you want to
supply real API keys — every key is optional (see below).

## Demo accounts

Self-registration is disabled by design — accounts are provisioned by an administrator.
Four seeded accounts cover every role and are also listed in the sign-in screen:

| Role | Email | Password |
|---|---|---|
| Administrator | `admin@sentinelai.io` | `Admin@123` |
| SOC Manager | `manager@sentinelai.io` | `Manager@123` |
| Security Analyst | `analyst@sentinelai.io` | `Analyst@123` |
| Viewer | `viewer@sentinelai.io` | `Viewer@123` |

## Optional integrations

Every one of these is off by default and the platform is fully functional without them.
Set the corresponding environment variable (backend `.env`, or the repo-root `.env` when
using Docker Compose) to switch a subsystem from its offline fallback to the live version:

| Capability | Env var(s) | Offline fallback | Live when configured |
|---|---|---|---|
| Database | `DATABASE_URL` | Local SQLite file | PostgreSQL |
| Embeddings / RAG | `EMBEDDING_MODEL`, `OPENAI_API_KEY` | Deterministic hashed n-gram vectors | sentence-transformers or OpenAI embeddings |
| Vector store | `VECTOR_BACKEND` | In-process NumPy cosine search | ChromaDB / FAISS |
| Threat intel | `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Deterministic heuristic scoring | VirusTotal / AbuseIPDB lookups |
| Cache | `REDIS_URL` | In-memory cache | Redis / Upstash |
| Tracing | `TRACING_EXPORTER`, `LANGSMITH_API_KEY`, `PHOENIX_COLLECTOR_ENDPOINT` | Local trace store only | Also forwards spans to LangSmith / Arize Phoenix |
| SSO | `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_DISCOVERY_URL` | Built-in mock Okta-style IdP | Real OIDC provider |

See `backend/.env.example` for the full list with defaults.

## Testing

```bash
cd backend
pytest -q          # 68 tests: auth, RBAC, agent pipeline, RAG, hunting, compliance, tracing…
ruff check app      # lint
```

```bash
cd frontend
npm run lint
npm run build       # production build → frontend/dist
```

## CI/CD

`.github/workflows/ci.yml` runs the backend lint+test suite and the frontend lint+build
on every push and pull request against `main`. `.github/workflows/deploy.yml` auto-deploys
on a green CI run — it is a safe no-op until you add `RENDER_DEPLOY_HOOK_URL` (backend) and
`VERCEL_TOKEN` / `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` (frontend) as repository secrets.

## Project layout

```
backend/
  app/
    routers/        # one module per API surface (auth, incidents, events, hunt, ...)
    services/        # agent pipeline, RAG, anomaly detection, threat intel, tracing, ...
    models.py         # SQLAlchemy ORM schema
    schemas.py         # Pydantic request/response contracts
    seed.py              # deterministic demo-data generator
  tests/
frontend/
  src/
    pages/            # one file per route
    components/         # Sidebar, Topbar, charts, ui primitives, icons
    lib/                  # api client, auth/theme contexts, formatting, hooks
docker-compose.yml
.github/workflows/
```

## Role-based access control

Capabilities are the single source of truth (`backend/app/deps.py::ROLE_CAPABILITIES`) —
the frontend never hardcodes "if admin"; it reads the capability list returned at login
and gates navigation and controls off that, while the backend re-checks every capability
on every request regardless of what the UI shows. Viewers get read-only access across the
console (simulators, uploaders, and write actions are visibly disabled) but can still
export PDF reports — a deliberate exception for audit and compliance use.

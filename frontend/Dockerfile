# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Stage 1: install deps and produce a static production build.
# ---------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json* ./
RUN npm install

COPY . .
# VITE_API_BASE is empty by design — the served bundle calls same-origin
# /api, and nginx below proxies that to the backend container.
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: serve the static bundle from nginx and reverse-proxy /api to the
# backend service — the browser only ever talks to one origin.
# ---------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /build/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:80/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]

# ==============================================================================
# Bayora Secure AI Safety Platform - Production Container Image
# Multi-stage build with pinned base image digest and non-root execution
# ==============================================================================

# Stage 1: Dependency resolution
FROM node:20.18.0-alpine@sha256:c13b26e7e602ef2f107870505d4019183421dd1d1822c26210f8a9235e236315 AS dependencies
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# Stage 2: Final runtime container
FROM node:20.18.0-alpine@sha256:c13b26e7e602ef2f107870505d4019183421dd1d1822c26210f8a9235e236315 AS runner

RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy production node_modules from dependency stage
COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./

# Copy runtime application code (test/ excluded by design and .dockerignore)
COPY src/ ./src/
COPY public/ ./public/
COPY bayora-redteam-review.md ./

# Volume for WORM audit persistence
VOLUME ["/data"]

# Environment defaults
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV WORM_STORAGE_PATH=/data/worm_audit.jsonl

# Drop privileges to non-root node user
USER node

EXPOSE 3000

# Healthcheck against unauthenticated health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/api/status || exit 1

CMD ["node", "src/server.js"]

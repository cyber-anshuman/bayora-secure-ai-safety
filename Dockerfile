# Multi-stage minimal production image for Bayora Secure AI Testing Platform
FROM node:20-alpine AS base

# Install security updates
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

WORKDIR /app

# Copy dependency definitions
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy application code
COPY src/ ./src/
COPY public/ ./public/
COPY test/ ./test/
COPY bayora-redteam-review.md ./

# Set environment
ENV NODE_ENV=production
ENV PORT=3000

# Drop privileges to non-root node user
USER node

EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/status || exit 1

CMD ["node", "src/server.js"]

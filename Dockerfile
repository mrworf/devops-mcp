FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV CONFIG_PATH=/config/config.yaml
ENV SECRETLINT_CONFIG_PATH=/config/secretlint.yaml
ENV SENSITIVE_NAMES_CONFIG_PATH=/config/sensitive-names.yaml
ENV SECRETLINT_QUEUE_MAX=32
ENV SECRETLINT_SUBJECT_ACTIVE_MAX=1
ENV SECRETLINT_SUBJECT_QUEUE_MAX=4
ENV SECRETLINT_QUEUE_TIMEOUT_MS=5000
COPY --from=deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY assets ./assets
COPY config/secretlint.yaml /app/config/secretlint.yaml
COPY config/secretlint.yaml /config/secretlint.yaml
COPY config/sensitive-names.yaml /app/config/sensitive-names.yaml
COPY config/sensitive-names.yaml /config/sensitive-names.yaml
COPY package.json ./
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/health >/dev/null || exit 1
CMD ["node", "dist/server.js"]

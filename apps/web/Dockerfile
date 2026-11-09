# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
ARG VITE_SITE_URL=https://kingmalhare.mukuvi.tech
ARG VITE_API_BASE=/api/v1
ENV VITE_SITE_URL=$VITE_SITE_URL
ENV VITE_API_BASE=$VITE_API_BASE
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web ./
RUN npm run build

FROM caddy:2.8-alpine
COPY infrastructure/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 80 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD nc -z 127.0.0.1 80 || exit 1

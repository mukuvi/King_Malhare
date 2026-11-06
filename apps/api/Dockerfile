# syntax=docker/dockerfile:1
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY apps/api/go.mod apps/api/go.sum ./
RUN go mod download
COPY apps/api .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/king-malhare-api ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kmctl ./cmd/kmctl

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget tzdata \
    && addgroup -g 10001 -S app \
    && adduser -u 10001 -S -G app -h /app app \
    && mkdir -p /data/storage \
    && chown -R app:app /data /app
WORKDIR /app
COPY --from=build /out/king-malhare-api /app/king-malhare-api
COPY --from=build /out/kmctl /app/kmctl
USER app:app
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/v1/health || exit 1
ENTRYPOINT ["/app/king-malhare-api"]

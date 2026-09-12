# syntax=docker/dockerfile:1
FROM node:26-bookworm-slim@sha256:cd9f682fa2885cd1056e830424764158570061c59736a1da836bc3d73df095ae AS web
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build
COPY scripts/collect-web-licenses.mjs /src/scripts/collect-web-licenses.mjs
COPY scripts/license-notices/web-overrides /src/scripts/license-notices/web-overrides
RUN node /src/scripts/collect-web-licenses.mjs /out/npm-licenses

FROM node:26-bookworm-slim@sha256:cd9f682fa2885cd1056e830424764158570061c59736a1da836bc3d73df095ae AS upstream
WORKDIR /src
COPY scripts/verify-pentagi.mjs ./scripts/verify-pentagi.mjs
COPY third_party/pentagi ./third_party/pentagi
RUN node scripts/verify-pentagi.mjs

FROM golang:1.26-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY --from=upstream /src/third_party/pentagi/backend ./third_party/pentagi/backend
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./internal/webassets/dist
ARG VERSION=1.2.0
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/hunter ./cmd/hunter
RUN go run ./scripts/license-notices -out /out/licenses
COPY --from=web /out/npm-licenses /out/licenses/npm

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 hunter && useradd --uid 10001 --gid hunter --no-create-home --shell /usr/sbin/nologin hunter
COPY --from=build /out/hunter /usr/local/bin/hunter
COPY --from=build /out/licenses /usr/share/licenses/hunter
USER 10001:10001
WORKDIR /tmp
EXPOSE 8080
LABEL org.opencontainers.image.title="hunter" \
      org.opencontainers.image.description="Offline-ready continuous security validation platform" \
      org.opencontainers.image.source="https://github.com/hkjang/hunter"
ENTRYPOINT ["/usr/local/bin/hunter"]

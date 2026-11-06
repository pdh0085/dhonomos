# Dhonomos release image: static binary on empty base (only MIT/Apache code inside).
#
#   docker build -t dhonomos .
#
# HTTPS webhooks -> need CA bundle: mount the host one, e.g.
#   -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro

# Base images pinned by digest -> retagged image cannot change a release build.
# Update on purpose (`docker buildx imagetools inspect <image>` -> digest).
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS ui
WORKDIR /w
COPY ui/package.json ui/package-lock.json ./
# npm 10 (in Node 22) rejects valid lockfiles with optional peers -> use npm 11.
# Exact version: floating `npm@11` -> new release could change the UI build.
RUN npx -y npm@11.21.0 ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

# TODO: pin by digest too (rust:1.99-alpine@sha256:...); digest not at hand when node was pinned.
FROM rust:1.99-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
COPY --from=ui /w/build ui/build
# Query check vs committed .sqlx cache, no live DB.
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked -p dhonomos \
 && mkdir -p /out/data /out/files \
 && cp target/release/dhonomos /out/dhonomos

FROM scratch
COPY --from=build /out/dhonomos /dhonomos
COPY --from=build --chown=65532:65532 /out/files /var/lib/dhonomos/files
USER 65532:65532
ENV DHONOMOS_FILES_DIR=/var/lib/dhonomos/files
# ACS, file server, API/UI, USP WebSocket, STUN (UDP).
EXPOSE 7547 7548 8080 7549 3478/udp
ENTRYPOINT ["/dhonomos"]

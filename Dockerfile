# The builder stays on the build platform so the tools it go-installs and runs
# (templ, sqlc) are native; only the final compile takes the target architecture.
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS builder

# Node and pnpm match .node-version and web/package.json's packageManager pin.
# Node 26 ships without corepack, so pnpm is a pinned global npm install.
ARG NODE_VERSION=26.8.2
ARG PNPM_VERSION=12.3.4
# sha256 of node-v${NODE_VERSION}-linux-<arch>.tar.gz from
# https://nodejs.org/dist/v26.8.2/SHASUMS256.txt. The gzip archive is used
# rather than the xz one because the pinned builder base carries gzip but no
# xz, and installing xz-utils would add an unpinned fetch to every image build.
ARG NODE_SHA256_X64=badb3fe6a61b85e1352ca6564dc56b8b7bd5ecd5c474c52acc21dd0cdd586f35
ARG NODE_SHA256_ARM64=746cdbf21565b4ea06f77642bb0e85466de8bb722242be2c5e006f272c361c63
# Node lands on the system search path: the Makefile prepends a project-local
# .tools/node/bin that the build context excludes, so /usr/bin/env resolves here.
RUN set -eu; \
	case "$(uname -m)" in \
	x86_64) architecture=x64; checksum="$NODE_SHA256_X64" ;; \
	aarch64) architecture=arm64; checksum="$NODE_SHA256_ARM64" ;; \
	*) echo "Unsupported builder architecture $(uname -m)" >&2; exit 1 ;; \
	esac; \
	archive="node-v${NODE_VERSION}-linux-${architecture}.tar.gz"; \
	curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${archive}"; \
	echo "${checksum}  ${archive}" | sha256sum -c -; \
	tar -xzf "$archive" -C /usr/local --strip-components=1 --no-same-owner; \
	rm -f "$archive" /usr/local/CHANGELOG.md /usr/local/LICENSE /usr/local/README.md; \
	npm install -g "pnpm@${PNPM_VERSION}"; \
	node --version; \
	pnpm --version

WORKDIR /src

# Dependency layers before the source: a source-only change reuses both caches.
COPY go.mod go.sum ./
RUN go mod download

# .npmrc travels with the manifests so the install honours the same
# engine-strict and strict-peer-dependencies settings contributors use.
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml web/.npmrc web/
RUN pnpm --dir web install --frozen-lockfile

COPY . .

# The gates contributors run, in the image: stale checked-in generated source
# fails the build instead of producing an executable from it.
RUN make install-templ install-sqlc check-db-generated check-web-generated build-web-assets

# compile-server runs no gate and rebuilds no asset; it only cross-compiles and
# stamps the identity, so the image and a contributor stamp the same way.
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=unknown DATE=unknown
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH make compile-server VERSION=$VERSION COMMIT=$COMMIT DATE=$DATE

# Distroless static carries the CA bundle and zone data the server needs and
# neither a shell nor a package manager.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

# A FROM resets build arguments, so the labelled identity is declared again.
ARG VERSION=dev COMMIT=unknown DATE=unknown
LABEL org.opencontainers.image.source="https://github.com/heurema/clavis" \
	org.opencontainers.image.revision="$COMMIT" \
	org.opencontainers.image.version="$VERSION" \
	org.opencontainers.image.created="$DATE"

COPY --from=builder /src/bin/server /server

# The base's nonroot account, numerically: a read-only root filesystem and a
# runAsNonRoot admission check both need the id, not a passwd lookup.
USER 65532:65532
# Fixed by the image: a container must listen on a non-loopback address.
ENV CLAVIS_HTTP_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/server"]

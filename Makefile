SHELL := /bin/sh
export PATH := $(CURDIR)/.tools/node/bin:$(CURDIR)/.tools/pnpm/node_modules/.bin:$(PATH)
# Make 3.81 looks up direct recipe executables using its original PATH.
# env resolves the runtimes using the exported project-local PATH instead.
NODE := /usr/bin/env node
PNPM := /usr/bin/env pnpm

# Read only when template tooling is used, so build-cli needs only Go.
# The templ runtime dependency is also the compiler pin.
TEMPL_VERSION = $(shell go list -m -f '{{.Version}}' github.com/a-h/templ)
GOLANGCI_VERSION := 2.13.2
DEADCODE_VERSION := 0.50.0
HELM_VERSION := 4.1.4
KIND_VERSION := 0.31.0
KUBECONFORM_VERSION := 0.7.0
SQLC_VERSION = $(shell cat .sqlc-version)
TEMPL := $(CURDIR)/.tools/templ/bin/templ
GOLANGCI := $(CURDIR)/.tools/golangci-lint/bin/golangci-lint
DEADCODE := $(CURDIR)/.tools/deadcode/bin/deadcode
SQLC := $(CURDIR)/.tools/sqlc/bin/sqlc
HELM := $(CURDIR)/.tools/helm/bin/helm
KIND := $(CURDIR)/.tools/kind/bin/kind
KUBECONFORM := $(CURDIR)/.tools/kubeconform/bin/kubeconform

# Kubernetes and Gateway API JSON schemas for kubeconform, pinned by repository
# commit and per-file checksum so a verified set is reproducible and chart-lint
# needs no network after setup. The standalone-strict schemas carry no $ref, so
# only the kinds the chart renders are downloaded and _definitions.json is not
# needed. Paths are the layout kubeconform's -schema-location templates produce.
KUBE_SCHEMAS := $(CURDIR)/.tools/kube-schemas
KUBE_SCHEMA_SET := v1.34.0-standalone-strict
KUBE_SCHEMA_COMMIT := 1360e239a56dcf2e5c7f99e61ccbaca1ea07036a
KUBE_SCHEMA_URL := https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$(KUBE_SCHEMA_COMMIT)/$(KUBE_SCHEMA_SET)
CRD_SCHEMA_COMMIT := ad3b08c5045129d7bb1eeffd8e61719b2c8dd1e2
CRD_SCHEMA_URL := https://raw.githubusercontent.com/datreeio/CRDs-catalog/$(CRD_SCHEMA_COMMIT)
KUBE_SCHEMA_FILES := \
	$(KUBE_SCHEMA_SET)/deployment-apps-v1.json@92b7a333a49124f5300095d3e7786ca2038b7d6e602c309f73e90631377e4b0a \
	$(KUBE_SCHEMA_SET)/service-v1.json@8bf019854daed511e7c174896a898173fa65d88ec5937c687a37303d4cc9351b \
	$(KUBE_SCHEMA_SET)/serviceaccount-v1.json@8193d6c3561475c6d3d5c44e1faedb1df53905373d904bc17015694326d659cf \
	$(KUBE_SCHEMA_SET)/ingress-networking-v1.json@4e0f63ad84c2bf22565e489d1f4b885ddaa9f6bf7cff1ddd562553760afe4d79 \
	$(KUBE_SCHEMA_SET)/networkpolicy-networking-v1.json@f6324cc464f62228b0418f438d167208e4f86c7e3677ba30f608e79a8b26ba79 \
	$(KUBE_SCHEMA_SET)/poddisruptionbudget-policy-v1.json@da73f50ad0264d73f668eecaa9959da65afe2846602a7a5c8fd51f7799d6a258 \
	crds/gateway.networking.k8s.io/httproute_v1.json@e5692e62edd9b8a14bd2527d0a732e174a649131aa4d47159737dc6527c59ca5
# coreutils on Linux, the perl shasum macOS ships; both read "sum  path" lines.
SHA256SUM := $(shell command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo 'shasum -a 256')

# Build identity stamped into internal/buildinfo. A build that passes none of
# these falls back to the identity the Go toolchain embeds, so only a source
# export reports the defaults; release builds pass the real values.
VERSION ?= dev
COMMIT ?= unknown
DATE ?= unknown
IDENTITY := github.com/heurema/clavis/internal/buildinfo
LDFLAGS = -X $(IDENTITY).Version=$(VERSION) -X $(IDENTITY).Commit=$(COMMIT) -X $(IDENTITY).Date=$(DATE)

# The tag `make image` produces; a release pipeline overrides it.
IMAGE ?= clavis:local
# Extra `docker buildx build` arguments, so a release can ask one recipe for
# several platforms and a push without a second definition of the build. The
# recipe names buildx explicitly because a plain `docker build` may still reach
# the docker driver, which cannot produce more than one platform.
IMAGE_FLAGS ?=

.PHONY: setup dev dev-db dev-api build build-server compile-server build-cli build-web-assets install-templ install-golangci-lint install-deadcode install-helm install-kind install-kubeconform install-kube-schemas chart-lint generate-web check-web-generated install-sqlc generate-db check-db-generated check-sql-boundaries check check-go-format lint-go check-dead-code format test-mutation test-mutation-full smoke image smoke-image verify-kind down reset-db

setup:
	go mod download
	$(PNPM) --dir web install --frozen-lockfile
	$(MAKE) install-golangci-lint
	$(MAKE) install-deadcode
	$(MAKE) install-templ
	$(MAKE) install-sqlc
	$(MAKE) install-helm
	$(MAKE) install-kind
	$(MAKE) install-kubeconform
	$(MAKE) install-kube-schemas
	$(MAKE) build-web-assets

dev-db:
	$(NODE) scripts/dev.mjs db

dev: build-server
	$(NODE) scripts/dev.mjs api

dev-api: dev

build-server: check-db-generated check-web-generated
	$(MAKE) build-web-assets
	$(MAKE) compile-server

# The compile alone, for a build that has already run the gates and the asset
# script: the image builder stages them itself and cross-compiles here.
# GOOS/GOARCH come from the environment; the identity comes from the three
# variables above, so a contributor and the image stamp the same way.
compile-server:
	@mkdir -p bin
	@set -eu; output=$$(mktemp -d bin/.server-XXXXXX); \
		trap 'rm -rf "$$output"' 0; \
		trap 'exit 1' 1 2 15; \
		CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' \
			-o "$$output/server" ./cmd/server; \
		mv -f "$$output/server" bin/server

build-cli:
	@mkdir -p bin
	@set -eu; output=$$(mktemp -d bin/.clavis-XXXXXX); \
		trap 'rm -rf "$$output"' 0; \
		trap 'exit 1' 1 2 15; \
		go build -trimpath -ldflags '$(LDFLAGS)' -o "$$output/clavis" ./cmd/clavis; \
		mv -f "$$output/clavis" bin/clavis

build: build-server build-cli

install-templ:
	GOBIN='$(dir $(TEMPL))' GOWORK=off go install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)

install-golangci-lint:
	GOBIN='$(dir $(GOLANGCI))' GOWORK=off go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_VERSION)

install-deadcode:
	GOBIN='$(dir $(DEADCODE))' GOWORK=off go install golang.org/x/tools/cmd/deadcode@v$(DEADCODE_VERSION)

generate-web:
	'$(TEMPL)' generate -path internal/web
	$(MAKE) build-web-assets

build-web-assets:
	$(NODE) scripts/build-web-assets.mjs

check-web-generated:
	$(NODE) scripts/check-web-generated.mjs

install-sqlc:
	GOBIN='$(dir $(SQLC))' GOWORK=off go install github.com/sqlc-dev/sqlc/cmd/sqlc@v$(SQLC_VERSION)

install-helm:
	GOBIN='$(dir $(HELM))' GOWORK=off go install helm.sh/helm/v4/cmd/helm@v$(HELM_VERSION)

install-kind:
	GOBIN='$(dir $(KIND))' GOWORK=off go install sigs.k8s.io/kind@v$(KIND_VERSION)

install-kubeconform:
	GOBIN='$(dir $(KUBECONFORM))' GOWORK=off go install github.com/yannh/kubeconform/cmd/kubeconform@v$(KUBECONFORM_VERSION)

# Downloads each pinned schema once and verifies every run, so a second run is
# an offline re-verification and a changed pin is a checksum failure, not a
# silently different schema. A mismatching file is removed, never kept.
install-kube-schemas:
	@set -eu; \
		for entry in $(KUBE_SCHEMA_FILES); do \
			path=$${entry%@*}; sum=$${entry##*@}; \
			target='$(KUBE_SCHEMAS)'/$$path; \
			mkdir -p "$$(dirname "$$target")"; \
			if [ ! -f "$$target" ]; then \
				case "$$path" in \
					crds/*) url='$(CRD_SCHEMA_URL)'/$${path#crds/} ;; \
					*) url='$(KUBE_SCHEMA_URL)'/$${path#$(KUBE_SCHEMA_SET)/} ;; \
				esac; \
				curl -fsSL -o "$$target" "$$url"; \
			fi; \
			printf '%s  %s\n' "$$sum" "$$target" | $(SHA256SUM) -c - >/dev/null 2>&1 || \
				{ rm -f "$$target"; \
					echo "Schema checksum mismatch for $$path; the pin in Makefile and the file disagree" >&2; \
					exit 1; }; \
		done; \
		echo 'Kubernetes and Gateway API schemas verified in .tools/kube-schemas.'

chart-lint:
	$(NODE) scripts/chart-lint.mjs

# sqlc owns YAML parsing. Copy only its maintained inputs, never assets or secrets.
# Native sqlc diff misses extra files; compare the entire isolated output instead.
generate-db check-db-generated:
	@set -eu; \
		{ test ! -L internal && test ! -L internal/database; } || \
			{ echo 'Symlinks are not supported in SQL parent directories' >&2; exit 1; }; \
		for path in sqlc.yaml internal/database/migrations internal/database/queries internal/database/sqlc; do \
			test ! -L "$$path" && { test ! -d "$$path" || test -z "$$(find "$$path" -type l -print)"; } || \
				{ echo "Symlinks are not supported in SQL inputs/output: $$path" >&2; exit 1; }; \
		done; \
		output=$$(mktemp -d "$${TMPDIR:-/tmp}/clavis-sqlc.XXXXXX"); \
		trap 'rm -rf "$$output"' 0; \
		trap 'exit 1' 1 2 15; \
		mkdir -p "$$output/internal/database"; \
		cp sqlc.yaml "$$output/"; \
		cp -R internal/database/migrations internal/database/queries "$$output/internal/database/"; \
		(cd "$$output" && '$(SQLC)' generate --no-remote); \
		test -d "$$output/internal/database/sqlc"; \
		if test '$@' = check-db-generated; then \
			diff -ru internal/database/sqlc "$$output/internal/database/sqlc"; \
		else \
			rm -rf internal/database/sqlc; \
			mv "$$output/internal/database/sqlc" internal/database/sqlc; \
		fi

check-sql-boundaries: check-db-generated
	go run ./scripts/check-sql-boundaries

# Recipes, not independent prerequisites: even make -j check stays sequential.
check:
	$(MAKE) check-sql-boundaries
	$(MAKE) check-go-format
	$(MAKE) check-web-generated
	$(MAKE) build-web-assets
	$(NODE) --test scripts/*.test.mjs
	$(MAKE) lint-go
	$(MAKE) check-dead-code
	# Package binaries run serially: database-backed packages share one database
	# and its database-wide advisory lock keys, so parallel packages can stall.
	go test -p 1 ./...
	$(PNPM) --dir web format:check
	$(PNPM) --dir web lint
	$(MAKE) build
	$(MAKE) chart-lint
	@echo '[check] All checks passed.'

check-go-format:
	@set -eu; files=$$(find cmd internal scripts/check-sql-boundaries -name '*.go' ! -name '*_templ.go' -exec gofmt -l {} +); \
		test -z "$$files" || { printf '%s\n' "$$files" 'Run make format to format source explicitly.' >&2; exit 1; }

lint-go:
	'$(GOLANGCI)' run --config .golangci.yml ./...

# Functions no executable reaches are dead production code, test-only helpers
# included: the tool exits 0 whatever it finds, so any output is the failure.
check-dead-code:
	@set -eu; findings=$$('$(DEADCODE)' ./...); \
		if [ -n "$$findings" ]; then \
			echo "Unreachable Go code (deadcode $(DEADCODE_VERSION)):"; echo "$$findings"; exit 1; \
		fi; \
		echo "No unreachable Go code."

format:
	find cmd internal scripts/check-sql-boundaries -name '*.go' ! -name '*_templ.go' ! -path 'internal/database/sqlc/*' -exec gofmt -w {} +
	'$(TEMPL)' fmt internal/web
	$(MAKE) generate-web
	$(PNPM) --dir web format

test-mutation: check-db-generated check-web-generated
	$(MAKE) build-web-assets
	$(NODE) scripts/mutation.mjs

# The full scope needs the extended bound; the diff-scoped default does not.
test-mutation-full: check-db-generated check-web-generated
	$(MAKE) build-web-assets
	CLAVIS_MUTATION_DIFF= CLAVIS_MUTATION_TIMEOUT_SECONDS=$${CLAVIS_MUTATION_TIMEOUT_SECONDS:-3600} $(NODE) scripts/mutation.mjs

smoke: build
	$(NODE) scripts/smoke.mjs

# Build identity comes from a checkout that has Git; a source export, or an
# explicit VERSION/COMMIT/DATE, keeps whatever the variables already hold.
image:
	@set -eu; \
		version='$(VERSION)'; commit='$(COMMIT)'; date='$(DATE)'; \
		if git rev-parse --git-dir >/dev/null 2>&1; then \
			test "$$version" != dev || version=$$(git describe --tags --always --dirty); \
			test "$$commit" != unknown || commit=$$(git rev-parse HEAD); \
			test "$$date" != unknown || date=$$(date -u +%Y-%m-%dT%H:%M:%SZ); \
		fi; \
		docker buildx build \
			--build-arg VERSION="$$version" \
			--build-arg COMMIT="$$commit" \
			--build-arg DATE="$$date" \
			$(IMAGE_FLAGS) \
			--tag '$(IMAGE)' .

smoke-image: image
	$(NODE) scripts/smoke-image.mjs

# The kind run builds its own two tags; naming the first one here makes the
# image target the precondition, so a Docker or build failure surfaces in
# seconds instead of minutes into the cluster run, and the script's own build
# step then only restamps a cached image.
verify-kind: IMAGE = clavis:kind-a
verify-kind: image
	$(NODE) scripts/verify-kind.mjs

down:
	$(NODE) scripts/dev.mjs down

reset-db:
	$(NODE) scripts/dev.mjs reset

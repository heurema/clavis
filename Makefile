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
SQLC_VERSION = $(shell cat .sqlc-version)
TEMPL := $(CURDIR)/.tools/templ/bin/templ
GOLANGCI := $(CURDIR)/.tools/golangci-lint/bin/golangci-lint
SQLC := $(CURDIR)/.tools/sqlc/bin/sqlc

.PHONY: setup dev dev-db dev-api build build-server build-cli build-web-assets install-templ install-golangci-lint generate-web check-web-generated install-sqlc generate-db check-db-generated check-sql-boundaries check check-go-format lint-go format test-mutation smoke down reset-db

setup:
	go mod download
	$(PNPM) --dir web install --frozen-lockfile
	$(MAKE) install-golangci-lint
	$(MAKE) install-templ
	$(MAKE) install-sqlc
	$(MAKE) build-web-assets

dev-db:
	$(NODE) scripts/dev.mjs db

dev: build-server
	$(NODE) scripts/dev.mjs api

dev-api: dev

build-server: check-db-generated check-web-generated
	$(MAKE) build-web-assets
	@mkdir -p bin
	@set -eu; output=$$(mktemp -d bin/.server-XXXXXX); \
		trap 'rm -rf "$$output"' 0; \
		trap 'exit 1' 1 2 15; \
		CGO_ENABLED=0 go build -trimpath -o "$$output/server" ./cmd/server; \
		mv -f "$$output/server" bin/server

build-cli:
	@mkdir -p bin
	@set -eu; output=$$(mktemp -d bin/.clavis-XXXXXX); \
		trap 'rm -rf "$$output"' 0; \
		trap 'exit 1' 1 2 15; \
		go build -trimpath -o "$$output/clavis" ./cmd/clavis; \
		mv -f "$$output/clavis" bin/clavis

build: build-server build-cli

install-templ:
	GOBIN='$(dir $(TEMPL))' GOWORK=off go install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)

install-golangci-lint:
	GOBIN='$(dir $(GOLANGCI))' GOWORK=off go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v$(GOLANGCI_VERSION)

generate-web:
	'$(TEMPL)' generate -path internal/web
	$(MAKE) build-web-assets

build-web-assets:
	$(NODE) scripts/build-web-assets.mjs

check-web-generated:
	$(NODE) scripts/check-web-generated.mjs

install-sqlc:
	GOBIN='$(dir $(SQLC))' GOWORK=off go install github.com/sqlc-dev/sqlc/cmd/sqlc@v$(SQLC_VERSION)

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
	go test ./...
	$(PNPM) --dir web format:check
	$(PNPM) --dir web lint
	$(MAKE) build
	@echo '[check] All checks passed.'

check-go-format:
	@set -eu; files=$$(find cmd internal scripts/check-sql-boundaries -name '*.go' ! -name '*_templ.go' -exec gofmt -l {} +); \
		test -z "$$files" || { printf '%s\n' "$$files" 'Run make format to format source explicitly.' >&2; exit 1; }

lint-go:
	'$(GOLANGCI)' run --config .golangci.yml ./...

format:
	find cmd internal scripts/check-sql-boundaries -name '*.go' ! -name '*_templ.go' ! -path 'internal/database/sqlc/*' -exec gofmt -w {} +
	'$(TEMPL)' fmt internal/web
	$(MAKE) generate-web
	$(PNPM) --dir web format

test-mutation: check-db-generated check-web-generated
	$(MAKE) build-web-assets
	$(NODE) scripts/mutation.mjs

smoke: build
	$(NODE) scripts/smoke.mjs

down:
	$(NODE) scripts/dev.mjs down

reset-db:
	$(NODE) scripts/dev.mjs reset

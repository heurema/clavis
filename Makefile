SHELL := /bin/sh
export PATH := $(CURDIR)/.tools/node/bin:$(CURDIR)/.tools/pnpm/node_modules/.bin:$(PATH)
export PLAYWRIGHT_BROWSERS_PATH := $(CURDIR)/.tools/playwright
# Make 3.81 looks up direct recipe executables using its original PATH.
# env resolves the runtimes using the exported project-local PATH instead.
NODE := /usr/bin/env node
PNPM := /usr/bin/env pnpm

.PHONY: setup dev dev-db dev-api build build-server build-cli build-web-assets generate-web check-web-generated check lint-go format test-web test-mutation smoke down reset-db

setup:
	@$(NODE) scripts/check-tools.mjs
	go mod download
	$(PNPM) --dir web install --frozen-lockfile
	$(NODE) scripts/golangci-lint.mjs install
	$(NODE) scripts/templ.mjs install
	$(PNPM) --dir web exec playwright install chromium
	$(MAKE) build-web-assets

dev-db:
	$(NODE) scripts/dev.mjs db

dev: build-server
	$(NODE) scripts/dev.mjs api

dev-api: dev

build-server: check-web-generated
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

generate-web:
	$(NODE) scripts/templ.mjs generate -path internal/web
	$(MAKE) build-web-assets

build-web-assets:
	$(NODE) scripts/build-web-assets.mjs

check-web-generated:
	$(NODE) scripts/check-web-generated.mjs

check:
	$(NODE) scripts/check.mjs

lint-go:
	$(NODE) scripts/golangci-lint.mjs run --config .golangci.yml ./...

format:
	find cmd internal -name '*.go' ! -name '*_templ.go' -exec gofmt -w {} +
	$(NODE) scripts/templ.mjs fmt internal/web
	$(MAKE) generate-web
	$(PNPM) --dir web format

test-mutation: check-web-generated
	$(MAKE) build-web-assets
	$(NODE) scripts/mutation.mjs

test-web: build-server
	$(PNPM) --dir web test

smoke: build
	$(NODE) scripts/smoke.mjs

down:
	$(NODE) scripts/dev.mjs down

reset-db:
	$(NODE) scripts/dev.mjs reset

SHELL := /bin/sh
export PATH := $(CURDIR)/.tools/node/bin:$(CURDIR)/.tools/pnpm/node_modules/.bin:$(PATH)
# Make 3.81 looks up direct recipe executables using its original PATH.
# env resolves the runtimes using the exported project-local PATH instead.
NODE := /usr/bin/env node
PNPM := /usr/bin/env pnpm

.PHONY: setup setup-browser dev-db dev-api dev-web build build-server generate-web check-web-generated check lint-go format test-mutation smoke down reset-db

setup:
	@$(NODE) scripts/check-tools.mjs
	go mod download
	$(PNPM) --dir web install --frozen-lockfile
	$(NODE) scripts/golangci-lint.mjs install
	$(NODE) scripts/templ.mjs install

setup-browser:
	$(PNPM) --dir web setup:browser

dev-db:
	$(NODE) scripts/dev.mjs db

dev-api: build-server
	$(NODE) scripts/dev.mjs api

dev-web:
	$(NODE) scripts/dev.mjs web

build-server:
	go build -trimpath -o bin/server ./cmd/server

build: build-server
	go build -trimpath -o bin/clavis ./cmd/clavis
	$(PNPM) --dir web build

generate-web:
	$(NODE) scripts/templ.mjs generate -path internal/web

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

test-mutation:
	$(NODE) scripts/mutation.mjs

smoke: build
	$(NODE) scripts/smoke.mjs

down:
	$(NODE) scripts/dev.mjs down

reset-db:
	$(NODE) scripts/dev.mjs reset

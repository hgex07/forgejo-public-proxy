GO ?= go
STATICCHECK ?= honnef.co/go/tools/cmd/staticcheck@latest
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: all build test vet lint vuln fuzz check ci
all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o bin/fpp ./cmd/fpp

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...
	gofmt -l . | (! grep .)

lint: vet
	$(GO) run $(STATICCHECK) ./...
	./scripts/check-template-html.sh

vuln:
	$(GO) run $(GOVULNCHECK) ./...

fuzz:
	$(GO) test -run '^$$' -fuzz FuzzParse -fuzztime 30s ./internal/config
	$(GO) test -run '^$$' -fuzz FuzzParsers -fuzztime 30s ./internal/gitx
	$(GO) test -run '^$$' -fuzz FuzzMarkdown -fuzztime 30s ./internal/render
	$(GO) test -run '^$$' -fuzz FuzzRedact -fuzztime 30s ./internal/gates

check:
	$(GO) run ./cmd/fpp check-config -config deploy/builder/config.example.yaml

ci: lint test vuln check

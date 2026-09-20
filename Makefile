GO ?= go
OSSL ?= openssl
export GOTOOLCHAIN := local

.PHONY: build check test results figure

build:
	mkdir -p bin
	$(GO) build -buildvcs=false -o bin/filesigner-rsa ./cmd/rsa-signer
	$(GO) build -buildvcs=false -o bin/filesigner-mldsa ./cmd/mldsa-signer

check: build
	mkdir -p out
	OSSL="$$(command -v $(OSSL))" bash checker/check.sh --json out/check.json

test: check
	$(GO) test ./...
	GO="$(GO)" OSSL="$$(command -v $(OSSL))" bash checker/selftest.sh "$$(mktemp -d out/selftest.XXXXXX)/controls"

results:
	$(GO) run ./cmd/results

figure:
	python3 analysis/plot.py

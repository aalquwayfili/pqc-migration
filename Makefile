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
	python3 -m unittest discover -q -s analysis -p test_analysis.py
	GO="$(GO)" OSSL="$$(command -v $(OSSL))" bash checker/selftest.sh "$$(mktemp -d out/selftest.XXXXXX)/controls"

results:
	python3 analysis/reproduce.py

figure:
	python3 analysis/plot.py

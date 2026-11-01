# bacnet-shield — minimal build/test automation.
# The project is plain Go: `go build ./...` works without make.
# This file exists for appliance packaging convenience.

BINARY := bacnet-shield
GO     ?= go

.PHONY: all build test fmt-check vet staticcheck govulncheck race verify acceptance security peers interop soak release release-all sbom vulnscan clean

all: build

build:
	$(GO) build -o bin/$(BINARY) ./cmd/bacnet-shield

# test gates on formatting: an unformatted file must not slip into a green
# suite because nothing checked (matches the other Shield projects).
test: fmt-check
	$(GO) test ./... -race -timeout 180s

fmt-check:
	@unformatted=$$(gofmt -l . | grep -v '^vendor/' || true); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; \
	fi

vet:
	$(GO) vet ./...

staticcheck:
	~/go/bin/staticcheck ./...

govulncheck:
	~/go/bin/govulncheck ./...

race: test

# Shared quality gates across the Shield projects.
verify: build test vet

# Acceptance requires an independent BACnet stack instead of only the
# in-process fake device: a missing bacpypes3 is a failure, not a skip.
acceptance: verify interop

# Release security gate. Requires staticcheck, govulncheck, syft and grype;
# unlike individual optional tooling probes, a missing tool fails this target.
security: verify staticcheck govulncheck vulnscan

# peers provisions the third-party BACnet stack used by the interop suite
# (bacpypes3 in .venv). Exit 77 when no Python/pip is available.
peers:
	sh scripts/peers-setup.sh

# interop drives the built gateway with bacpypes3 on both legs: a real BACnet
# client reads and writes through the proxy to a real BACnet device, and a
# policy violation is refused with an Error PDU. Exit 77 when bacpypes3 is
# missing (run `make peers`).
interop: build
	sh scripts/interop-bacnet.sh

# soak runs the long tests a green `make test` cannot judge: continuous load
# (goroutines and live heap must stay flat) and the rate limiter under a flood
# of spoofed sources. Ten minutes by default; SOAK_DURATION overrides it.
soak:
	BACNET_SHIELD_SOAK=1 BACNET_SHIELD_SOAK_DURATION=$${SOAK_DURATION:-10m} \
		$(GO) test ./internal/access ./internal/proxy -run 'TestSoak' -count=1 -timeout 30m -v

# release builds a stripped static binary for appliance deployment.
release:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/$(BINARY) ./cmd/bacnet-shield

# release-all cross-builds stripped static binaries for the appliance
# platforms (amd64 + arm64 + armv7) into dist/. The project is pure Go
# with CGO disabled, so cross-compiling is exact — no ports, no ifdef.
release-all:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-amd64 ./cmd/bacnet-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-arm64 ./cmd/bacnet-shield
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "-s -w" -o dist/$(BINARY)-linux-armv7 ./cmd/bacnet-shield
	@echo "release binaries written to dist/ ($(BINARY)-linux-{amd64,arm64,armv7})"

# sbom generates SPDX + CycloneDX SBOMs for the release binary into dist/.
# Requires syft (https://github.com/anchore/syft); exits 77 when missing.
sbom: release
	@command -v syft >/dev/null 2>&1 || { echo "syft not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/syft/cmd/syft@latest)"; exit 77; }
	@mkdir -p dist
	syft bin/$(BINARY) -o spdx-json=dist/$(BINARY).spdx.json -o cyclonedx-json=dist/$(BINARY).cdx.json
	@echo "SBOMs written to dist/$(BINARY).spdx.json + dist/$(BINARY).cdx.json"

# vulnscan matches the SBOM against vulnerability databases (NVD/GHSA/OSV)
# via grype and fails on findings at severity HIGH or above.
# Requires grype (https://github.com/anchore/grype); exits 77 when missing.
vulnscan: sbom
	@command -v grype >/dev/null 2>&1 || { echo "grype not installed (GOBIN=$$HOME/go/bin go install github.com/anchore/grype/cmd/grype@latest)"; exit 77; }
	grype db update
	grype dist/$(BINARY).spdx.json --fail-on high

clean:
	rm -f bin/$(BINARY)
	rm -rf dist/

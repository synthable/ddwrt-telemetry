.PHONY: help build-armv7 build-arm64 build-mipsle build-all test demo demo-dns demo-fw run

BIN_DIR := nflogd/dist

help:
	@echo "ddwrt-telemetry targets:"
	@echo "  make demo          Run BOTH dashboards in --demo mode (:8787 & :8788)"
	@echo "  make run           Run BOTH dashboards connected to your router (:8787 & :8788)"
	@echo "  make demo-dns      Run DNS dashboard only in --demo mode (:8787)"
	@echo "  make demo-fw       Run Firewall dashboard only in --demo mode (:8788)"
	@echo "  make build-armv7   Build static nflogd for ARMv7 routers (e.g. Linksys WRT1900/3200)"
	@echo "  make build-arm64   Build static nflogd for ARM64 routers"
	@echo "  make build-mipsle  Build static nflogd for MIPS little-endian routers"
	@echo "  make build-all     Build all router architectures"
	@echo "  make test          Run Go + Python tests, JS syntax checks, and shell syntax checks"

build-armv7:
	@mkdir -p $(BIN_DIR)
	cd nflogd && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="-s -w" -o dist/nflogd-armv7 .
	@ls -lh $(BIN_DIR)/nflogd-armv7

build-arm64:
	@mkdir -p $(BIN_DIR)
	cd nflogd && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/nflogd-arm64 .
	@ls -lh $(BIN_DIR)/nflogd-arm64

build-mipsle:
	@mkdir -p $(BIN_DIR)
	cd nflogd && CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags="-s -w" -o dist/nflogd-mipsle .
	@ls -lh $(BIN_DIR)/nflogd-mipsle

build-all: build-armv7 build-arm64 build-mipsle

test:
	cd nflogd && go test -v ./...
	cd dns-dashboard && python3 -m py_compile parser.py server.py && python3 -m unittest -v test_parser.py
	cd firewall-dashboard && python3 -m py_compile parser.py server.py && python3 -m unittest -v test_parser.py
	sh -n router-scripts/archive-logs.sh
	bash -n scripts/run-dashboards.sh scripts/install-router.sh
	@if command -v node >/dev/null 2>&1; then \
		node --check dns-dashboard/static/app.js && node --check firewall-dashboard/static/app.js; \
	fi

demo:
	./scripts/run-dashboards.sh --demo

run:
	./scripts/run-dashboards.sh

demo-dns:
	python3 dns-dashboard/server.py --demo --port 8787

demo-fw:
	python3 firewall-dashboard/server.py --demo --port 8788

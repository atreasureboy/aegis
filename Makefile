# Aegis C2 - Makefile
# Targets: server, client, agent-linux, agent-windows, agent-windows-nocgo

SHELL := /usr/bin/env bash

.PHONY: all server client agent-linux agent-windows agent-windows-nocgo build-dir clean

# ---------------------------------------------------------------------------
# Paths & output
# ---------------------------------------------------------------------------
BUILD_DIR := build

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
GO      := go
GOPATH  := $(shell go env GOPATH)

# ---------------------------------------------------------------------------
# Flags
#   -ldflags="-s -w -trimpath"  strip symbol table, DWARF, and embed paths
#   -gcflags="all=-trimpath=…"  remove local GOPATH from compiled traces
# ---------------------------------------------------------------------------
LDFLAGS := -ldflags="-s -w -trimpath"
GCFLAGS := -gcflags="all=-trimpath=$(GOPATH)"
FLAGS   := $(LDFLAGS) $(GCFLAGS)

# ---------------------------------------------------------------------------
# Default: build everything
# ---------------------------------------------------------------------------
all: build-dir server client agent-linux agent-windows

# ---------------------------------------------------------------------------
# Build directory
# ---------------------------------------------------------------------------
build-dir:
	@mkdir -p $(BUILD_DIR)

# ---------------------------------------------------------------------------
# Server (native)
# ---------------------------------------------------------------------------
server: build-dir
	$(GO) build $(FLAGS) -o $(BUILD_DIR)/aegis-server ./cmd/server

# ---------------------------------------------------------------------------
# Client (native)
# ---------------------------------------------------------------------------
client: build-dir
	$(GO) build $(FLAGS) -o $(BUILD_DIR)/aegis-client ./cmd/client

# ---------------------------------------------------------------------------
# Agent  -  Linux amd64
# ---------------------------------------------------------------------------
agent-linux: build-dir
	GOOS=linux GOARCH=amd64 $(GO) build $(FLAGS) -o $(BUILD_DIR)/aegis-agent-linux ./cmd/agent

# ---------------------------------------------------------------------------
# Agent  -  Windows amd64  (CGO enabled  -  full evasion)
# ---------------------------------------------------------------------------
agent-windows: build-dir
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build $(FLAGS) -o $(BUILD_DIR)/aegis-agent.exe ./cmd/agent

# ---------------------------------------------------------------------------
# Agent  -  Windows amd64  (CGO disabled -  stub evasion, smaller binary)
# ---------------------------------------------------------------------------
agent-windows-nocgo: build-dir
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(FLAGS) -o $(BUILD_DIR)/aegis-agent-nocgo.exe ./cmd/agent

# ---------------------------------------------------------------------------
# Build-tag variants  (agent transport selection)
#
#   agent_http    -  HTTP only          (smallest)
#   agent_mtls    -  HTTP + mTLS
#   agent_full    -  All transports     (default, same as targets above)
#
#   Usage:  make agent-http  make agent-mtls  make agent-full
#   Cross-compile: prepend GOOS/GOARCH as usual.
# ---------------------------------------------------------------------------

agent-http: build-dir
	GOOS=linux GOARCH=amd64 $(GO) build -tags agent_http $(FLAGS) \
		-o $(BUILD_DIR)/aegis-agent-http ./cmd/agent

agent-mtls: build-dir
	GOOS=linux GOARCH=amd64 $(GO) build -tags agent_mtls $(FLAGS) \
		-o $(BUILD_DIR)/aegis-agent-mtls ./cmd/agent

agent-full: build-dir
	GOOS=linux GOARCH=amd64 $(GO) build -tags agent_full $(FLAGS) \
		-o $(BUILD_DIR)/aegis-agent-full ./cmd/agent

agent-http-windows: build-dir
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -tags agent_http $(FLAGS) \
		-o $(BUILD_DIR)/aegis-agent-http.exe ./cmd/agent

agent-mtls-windows: build-dir
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -tags agent_mtls $(FLAGS) \
		-o $(BUILD_DIR)/aegis-agent-mtls.exe ./cmd/agent

agent-full-windows: build-dir
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 $(GO) build -tags agent_full $(FLAGS) \
		-o $(BUILD_DIR)/aegis-agent-full.exe ./cmd/agent

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR)

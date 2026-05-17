# GhostPTY build, package, and test orchestration.
#
# Targets:
#   build          — compile server + shared + client (debug)
#   build-release  — compile release profile
#   build-ebpf     — compile eBPF kernel programs (requires bpf toolchain)
#   test-unit      — run all non-root unit/integration tests
#   test-e2e       — run full end-to-end test suite (requires root + eBPF)
#   package-open   — export clean open-source tarball to dist/
#   clean          — remove build artefacts

VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
DIST_DIR  := dist
PKG_NAME  := ghostpty-open-$(VERSION)
PKG_TGZ   := $(DIST_DIR)/$(PKG_NAME).tar.gz

.PHONY: build build-release build-ebpf test-unit test-e2e package-open clean

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	cargo build -p server -p client -p shared -p ghost-chain-tests

build-release:
	cargo build --release -p server -p client -p shared

build-ebpf:
	cargo xtask build-ebpf

# ── Tests ─────────────────────────────────────────────────────────────────────

test-unit:
	@echo "=== Unit & integration tests (no root required) ==="
	cargo test -p shared -p ghost-chain-tests -- --test-output immediate
	@echo "=== PASS ==="

test-e2e:
	@echo "=== End-to-end test suite (requires root) ==="
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: e2e tests require root (eBPF + XDP + cgroupv2)"; \
		exit 1; \
	fi
	bash tests/e2e.sh

# ── Packaging ─────────────────────────────────────────────────────────────────
#
# Produces a clean tarball containing only open-source components.
# Excludes:
#   - server/sovereign/libgp_sovereign.a  (closed source)
#   - server/sovereign/gp_sovereign.s     (closed source)
#   - server/sovereign/gp_sovereign.o     (closed source)
#   - target/                             (build artefacts)
#   - .ghost_chain_state                  (client key-chain state)
#   - certs/*.key                         (private keys, replaced by instructions)
#   - .git/                               (VCS metadata)

package-open: build
	@mkdir -p $(DIST_DIR)
	@echo "Packaging $(PKG_NAME)..."
	git archive --format=tar.gz --prefix=$(PKG_NAME)/ HEAD \
		> $(PKG_TGZ)
	@echo "Package written to $(PKG_TGZ)"
	@echo "Contents:"
	@tar -tzf $(PKG_TGZ) | grep -v '^$(PKG_NAME)/$$' | head -60

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf $(DIST_DIR)

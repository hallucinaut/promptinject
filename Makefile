.PHONY: all build test clean run-api docker-build docker-run lint

# Build binaries
all: build

build:
	@echo "Building CLI..."
	@go build -o bin/promptinject ./cmd/promptinject
	@echo "Building API Server..."
	@go build -o bin/promptinject-api ./cmd/promptinject-api
	@echo "Build complete. Binaries are in the bin/ directory."

test:
	@echo "Running tests..."
	@go test -v ./...

clean:
	@echo "Cleaning up..."
	@rm -rf bin/
	@echo "Cleaned."

run-api:
	@echo "Running API server on port 8080..."
	@go run ./cmd/promptinject-api -port 8080

docker-build:
	@echo "Building Docker image..."
	@docker build -t promptinject-api .

docker-run:
	@echo "Running Docker container on port 8080..."
	@docker run -p 8080:8080 promptinject-api

lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null; then golangci-lint run ./...; else echo "golangci-lint not installed. Please install it to run linting."; fi

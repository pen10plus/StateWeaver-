# Contributing to StateWeaver

Thank you for your interest in contributing to StateWeaver! We welcome code contributions, bug reports, documentation updates, and new policy heuristics.

## Code of Conduct

Please treat all contributors with respect, professionalism, and constructive feedback.

## Development Workflow

### Prerequisites
- Go 1.23 or newer
- Make (optional)
- Docker & Docker Compose (for containerized test lab)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/stateweaver/stateweaver.git
cd stateweaver

# Build the CLI
make build
# or: go build -buildvcs=false -o stateweaver ./cmd/stateweaver
```

### Running Tests

```bash
# Run unit tests across all packages
make test

# Run the vulnerable and secure lab integration benchmark
make integration-test
```

### Coding Standards
- Follow idiomatic Go guidelines (`effective_go`).
- Security logic must remain separated from CLI rendering and reporting.
- All new heuristics or comparators must be backed by unit tests.
- Code must pass `go vet ./...` and `go fmt ./...`.
- Avoid adding unnecessary third-party dependencies.

## Submitting Pull Requests

1. Fork the repository and create your feature branch: `git checkout -b feat/my-improvement`.
2. Commit your changes with concise, descriptive commit messages.
3. Ensure all tests pass: `go test -v ./...`.
4. Open a pull request against the `main` branch with a summary of changes, rationale, and test results.


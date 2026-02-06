# Contributing to Augustus

Thank you for your interest in contributing to Augustus! We welcome contributions from security researchers, developers, and LLM practitioners. Whether you're fixing bugs, adding new probes, or improving documentation, your help makes Augustus stronger.

## Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please read and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions.

## Getting Started

### Prerequisites

- **Go 1.21+** - Augustus is written in Go
- **Git** - For version control
- **Make** - For build automation

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/augustus.git
   cd augustus
   ```
3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/praetorian-inc/augustus.git
   ```

### Build and Test

Build the project:
```bash
go build ./cmd/augustus
```

Run tests:
```bash
go test ./...
```

Run linting (if applicable):
```bash
go fmt ./...
gofmt -l -w .
```

## Development Setup

Augustus follows standard Go project layout with the following key directories:

- `pkg/probes/` - Vulnerability probe implementations
- `pkg/detectors/` - Detection strategy implementations
- `pkg/generators/` - Request/payload generators
- `pkg/registry/` - Component registration system
- `cmd/augustus/` - CLI entry point
- `internal/` - Internal utilities and helpers

## Making Contributions

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Follow conventional commits:**
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation
   - `refactor:` - Code refactoring
   - `test:` - Test additions
   - Example: `git commit -m "feat: add new prompt injection probe"`

3. **Submit a pull request** against the `main` branch with a clear description of changes

## Adding New Features

### Adding a New Probe

1. Create a new file in `pkg/probes/`
2. Implement the probe interface
3. Register in `pkg/registry/probes/`
4. Add unit tests in `*_test.go` file
5. Update documentation with the probe name and description

### Adding a New Detector

1. Create a new file in `pkg/detectors/`
2. Implement the detector interface
3. Register in `pkg/registry/detectors/`
4. Add unit tests
5. Document detection logic and accuracy considerations

### Adding a New Generator

1. Create a new file in `pkg/generators/`
2. Implement the generator interface
3. Register in `pkg/registry/generators/`
4. Add unit tests

## Testing Requirements

- **Unit tests required** for all new features
- **80%+ code coverage** is expected
- Run tests before submitting PR: `go test ./...`
- Include edge case testing (empty inputs, malformed data, etc.)
- Test integration with registry system

## Style Guide

- **Go formatting:** Use `gofmt` for all code
- **Naming conventions:** Follow Go standards (CamelCase for exported, camelCase for internal)
- **Error handling:** Handle errors explicitly at every level with context
- **Comments:** Document exported functions and non-obvious logic
- **Line length:** Keep functions under 50 lines where possible
- **File size:** Keep files under 500 lines for maintainability

## License

By contributing to Augustus, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE). All contributions must be compatible with this license.

## Questions?

- Open an issue for bugs or feature requests
- Check existing issues before opening duplicates
- Join our community discussions for questions and ideas

Happy contributing!

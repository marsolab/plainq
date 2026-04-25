# How to contribute?

## Welcome to PlainQ!

We're excited that you're interested in contributing to PlainQ. This document provides guidelines and information about contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a welcoming, respectful, and harassment-free environment for everyone.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/plainq.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test ./...`
6. Commit your changes: `git commit -m "Add your message"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Open a Pull Request

## Development Setup

PlainQ requires:

- Go 1.23 or later
- Protocol Buffers compiler for gRPC development

## Project Structure

- `/internal/server` - Core server implementation
  - `middleware/` - HTTP/gRPC middleware
  - `schema/` - API schemas and protobuf definitions
  - `storage/` - Storage layer implementation
  - `telemetry/` - Observability components

## Pull Request Process

1. Update documentation for any new features
2. Add or update tests as needed
3. Ensure all tests pass
4. Follow existing code style and formatting
5. Keep commits atomic and well-described
6. Reference any related issues

## Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` for code formatting
- Add comments for exported functions and packages
- Use meaningful variable and function names

## Testing

- Write unit tests for new functionality
- Ensure existing tests pass
- Include integration tests where appropriate
- Use testdeep for complex assertions

## Documentation

- Update README.md for significant changes
- Document new API endpoints
- Include code examples where helpful
- Keep documentation clear and concise

## Questions?

Feel free to open an issue for:

- Bug reports
- Feature requests
- Questions about the codebase
- Contribution clarifications

Thank you for contributing to PlainQ!

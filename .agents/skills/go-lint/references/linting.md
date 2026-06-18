# Linting reference

Carved from the comprehensive Go style guide. Covers required tools
across production codebases and the common linter set.

---

## Required tools across production codebases

- **gofmt** / **goimports**: Non-negotiable formatting
- **go vet**: Catches common mistakes
- **golangci-lint**: Meta-linter running multiple checks

GitLab's CI configuration:

```yaml
lint:
  image: golangci/golangci-lint:v1.56.2
  script:
    - golangci-lint run --out-format code-climate:gl-code-quality-report.json
```

## Commonly enabled linters

- **errcheck**: Ensures errors aren't ignored
- **govet**: Official Go analyzer
- **staticcheck**: Comprehensive static analysis
- **unused**: Finds unused code
- **misspell**: Catches typos in comments and strings
- **prealloc**: Suggests slice preallocation
- **gosec**: Security-focused analysis

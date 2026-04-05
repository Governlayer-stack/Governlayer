# Contributing to GovernLayer

Thank you for your interest in contributing to GovernLayer. This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Security](#security)

## Code of Conduct

This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally.
3. Create a feature branch from `main`.
4. Make your changes and commit them with clear messages.
5. Push your branch and open a pull request.

## Development Environment

### Prerequisites

- Python 3.11
- PostgreSQL 15
- Redis
- Ollama (optional, for local LLM inference)

### Setup

Run the full local setup with a single command:

```bash
make setup
```

This creates a virtual environment, installs all dependencies, and initializes the database.

### Common Commands

| Command | Description |
|---------|-------------|
| `make dev` | Run the API server with hot reload on port 8000 |
| `make test` | Run the full test suite |
| `make test-drift` | Run drift detection tests only |
| `make test-one TEST=tests/test_drift.py::test_name` | Run a single test |
| `make lint` | Run ruff linting |
| `make format` | Auto-format code with ruff |
| `make mcp` | Run the MCP server (stdio transport) |
| `make docker-up` | Start the full stack (API + Postgres + Redis) |
| `make docker-down` | Stop all containers |
| `make db-init` | Initialize database tables |
| `make db-migrate` | Run Alembic migrations |
| `make db-revision MSG="description"` | Create a new migration |

### Running Tests

Always run the full test suite before submitting a pull request:

```bash
make test
```

For faster iteration during development, run only the tests relevant to your changes:

```bash
make test-one TEST=tests/test_drift.py::test_embedding_drift
```

## Code Style

This project uses [ruff](https://github.com/astral-sh/ruff) for both linting and formatting.

### Rules

- Follow PEP 8 conventions.
- Use type hints for all function signatures.
- Keep functions focused and under 30 lines where practical.
- Write docstrings for all public modules, classes, and functions.
- Use meaningful variable and function names.

### Linting and Formatting

Before committing, run:

```bash
make lint
make format
```

The CI pipeline enforces ruff checks on all pull requests. PRs with lint failures will not be merged.

### Import Order

Ruff enforces import sorting automatically. The expected order is:

1. Standard library imports
2. Third-party imports
3. Local application imports

## Making Changes

### Branch Naming

Use descriptive branch names with a prefix:

- `feature/` -- New functionality
- `fix/` -- Bug fixes
- `docs/` -- Documentation changes
- `refactor/` -- Code restructuring without behavior changes
- `test/` -- Test additions or modifications

Example: `feature/webhook-retry-logic`

### Commit Messages

Write clear, concise commit messages:

- Use the imperative mood ("Add feature" not "Added feature").
- Keep the subject line under 72 characters.
- Reference issue numbers where applicable (e.g., `Fix token validation (#42)`).

### Testing Requirements

- All new features must include tests.
- All bug fixes must include a regression test.
- Maintain or improve existing test coverage.
- Tests must pass locally before opening a PR.

## Pull Request Process

1. **Update documentation.** If your change affects the API, update relevant docstrings and documentation.

2. **Add tests.** Every PR must include appropriate test coverage.

3. **Pass CI.** All checks (lint, test, security scan) must pass before review.

4. **One concern per PR.** Keep pull requests focused. Large PRs are harder to review and more likely to introduce issues.

5. **Use the PR template.** Fill out all sections of the pull request template.

6. **Request review.** Tag at least one maintainer for review.

7. **Address feedback.** Respond to all review comments. Push additional commits to address feedback rather than force-pushing.

### Review Criteria

Reviewers evaluate PRs against the following:

- Correctness: Does the code do what it claims?
- Security: Are there any vulnerabilities introduced?
- Performance: Are there unnecessary allocations, queries, or loops?
- Readability: Is the code clear and well-documented?
- Testing: Are edge cases covered?

## Issue Guidelines

We provide templates for common issue types:

- **Bug reports**: Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include reproduction steps, expected behavior, and environment details.
- **Feature requests**: Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md). Describe the problem, proposed solution, and any alternatives considered.

Before opening an issue, search existing issues to avoid duplicates.

## Security

If you discover a security vulnerability, do **not** open a public issue. Instead, follow the process described in [SECURITY.md](SECURITY.md).

## License

By contributing to GovernLayer, you agree that your contributions will be licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

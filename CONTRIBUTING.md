# Contributing to KWTCyberWatch

Thank you for your interest in contributing to KWTCyberWatch! This document provides guidelines and steps for contributing.

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/SiteQ8/KWTCyberWatch/issues) to avoid duplicates
2. Use the **Bug Report** issue template
3. Include steps to reproduce, expected vs actual behavior, and environment details

### Suggesting Features

1. Open an issue using the **Feature Request** template
2. Describe the use case and expected behavior
3. Discuss the feature before starting implementation

### Submitting Code

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following our coding standards
4. **Test your changes** thoroughly
5. **Commit** with clear, descriptive messages:
   ```bash
   git commit -m "Add: brief description of change"
   ```
6. **Push** to your fork and open a **Pull Request**

## Development Setup

```bash
# Clone the repository
git clone https://github.com/SiteQ8/KWTCyberWatch.git
cd KWTCyberWatch

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the web dashboard
cd webapp
python app.py

# Run the CertStream monitor
python scripts/certstream_monitor.py
```

## Coding Standards

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions small and focused
- Write descriptive commit messages

## Commit Message Format

```
Type: Brief description

Detailed explanation if necessary.
```

**Types:** `Add`, `Fix`, `Update`, `Remove`, `Refactor`, `Docs`, `Security`

## Pull Request Process

1. Fill out the PR template completely
2. Ensure your code passes all checks
3. Request review from `@SiteQ8`
4. Address all review feedback
5. Squash commits before merging if requested

## Security Vulnerabilities

**Do NOT open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

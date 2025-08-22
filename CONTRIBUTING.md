# Contributing to BLRCS

Thank you for your interest in contributing to BLRCS! We welcome contributions from the community and are grateful for any help you can provide.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate in all interactions.

## How to Contribute

### Reporting Issues

- Check if the issue has already been reported
- Use the issue template when creating a new issue
- Provide as much detail as possible
- Include steps to reproduce the issue

### Submitting Pull Requests

1. **Fork the Repository**
   ```bash
   git clone https://github.com/shizukutanaka/BLRCS.git
   cd BLRCS
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow the coding standards
   - Write tests for new features
   - Update documentation as needed

4. **Test Your Changes**
   ```bash
   pytest
   black blrcs/
   ruff check blrcs/
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Open a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Ensure all tests pass

## Development Setup

### Prerequisites
- Python 3.8+
- Virtual environment
- Git

### Setup Instructions

```bash
# Clone the repository
git clone https://github.com/blrcs/blrcs.git
cd blrcs

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

## Coding Standards

### Python Style Guide
- Follow PEP 8
- Use Black for formatting (line length: 100)
- Use Ruff for linting
- Type hints are encouraged

### Commit Messages
We follow the Conventional Commits specification:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test changes
- `chore:` Maintenance tasks

### Testing
- Write tests for all new features
- Maintain test coverage above 80%
- Use pytest for testing
- Include both unit and integration tests

### Documentation
- Update README.md for user-facing changes
- Add docstrings to all functions and classes
- Update API documentation for endpoint changes
- Include examples where appropriate

## Project Structure

```
blrcs/
├── blrcs/             # Main package
│   ├── core/          # Core modules
│   ├── security/      # Security components
│   ├── lightning/     # Lightning Network integration
│   └── api/           # API endpoints
├── tests/             # Test suite
├── docs/              # Documentation
└── scripts/           # Utility scripts
```

## Review Process

1. All pull requests require at least one review
2. CI/CD checks must pass
3. No merge conflicts
4. Documentation updated
5. Tests included and passing

## Release Process

1. Version bump in `__init__.py`
2. Update CHANGELOG.md
3. Create release branch
4. Tag release
5. Deploy to PyPI

## Getting Help

- Check the [documentation](docs/)
- Submit issues on [GitHub](https://github.com/shizukutanaka/BLRCS/issues)

## License

By contributing to BLRCS, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project website

Thank you for contributing to BLRCS!
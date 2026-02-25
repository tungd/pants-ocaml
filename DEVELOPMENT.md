# Development Guide

This project uses [uv](https://github.com/astral-sh/uv) as the Python dependency manager.

## Prerequisites

- Python 3.8 or higher
- [uv](https://github.com/astral-sh/uv) package manager

## Installing uv

```bash
# macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or with Homebrew (macOS)
brew install uv

# Or with pip
pip install uv
```

## Setup Development Environment

```bash
# Install dependencies
uv pip install -e ".[dev]"

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=ocaml --cov-report=term
```

## Common Commands

### Installing Dependencies

```bash
uv pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run unit tests only
uv run pytest tests/unit/

# Run integration tests only
uv run pytest tests/integration/

# Run specific test file
uv run pytest tests/unit/test_target_types.py

# Run specific test
uv run pytest tests/unit/test_target_types.py::TestOCamlPlatformField::test_valid_choices

# Run with verbose output
uv run pytest -v

# Run with coverage
uv run pytest --cov=ocaml --cov-report=term --cov-report=html
```

### Backend Development

```bash
# Verify the backend loads
uv run python -c "from ocaml import register; print('Backend loads successfully')"

# Verify target types
uv run python -c "from ocaml.target_types import OCamlPackage, OCamlBinary; print('Target types imported')"

# Check syntax of all Python files
python3 -m py_compile *.py

# Run type checking (optional)
uv run mypy ocaml/ --ignore-missing-imports
```

### Code Quality Checks

```bash
# Format code with black
uv run black ocaml/ tests/

# Check import sorting with isort
uv run isort --check-only ocaml/ tests/

# Run linters
uv run pylint ocaml/
```

## Project Structure

```
.                        # Project root
├── ocaml/               # Source files (in project root for Pants backend)
│   ├── __init__.py
│   ├── register.py
│   ├── target_types.py
│   ├── rules.py
│   ├── providers.py
│   └── subsystem.py
├── tests/               # Test suite
│   ├── unit/           # Unit tests
│   │   ├── conftest.py
│   │   ├── test_target_types.py
│   │   ├── test_subsystem.py
│   │   ├── test_providers.py
│   │   └── test_rules.py
│   └── integration/    # Integration tests
│       └── test_ocaml_binary.py
├── .github/            # CI/CD workflows
│   └── workflows/
│       ├── ci.yml
│       └── code-quality.yml
├── pyproject.toml      # Project configuration with uv support
├── DEVELOPMENT.md      # This file
└── README.org          # User documentation
```

## Adding Dependencies

```bash
# Add a runtime dependency
uv pip add <package-name>

# Add a development dependency
uv pip add --dev <package-name>
```

Then update `pyproject.toml` accordingly:

```toml
[project]
dependencies = [
    "pantsbuild.pants>=2.21.0",
    "<package-name>>=<version>",
]

[dependency-groups]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "pytest-mock>=3.10.0",
    "<new-dev-package>>=<version>",
]
```

## Running with uv

`uv` provides several ways to run Python commands:

```bash
# Run Python with the virtual environment
uv run python script.py

# Run test commands
uv run pytest

# Run any installed command
uv run black .
```

## Virtual Environments

```bash
# Create a virtual environment
uv venv

# Activate the virtual environment (manual activation)
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate     # Windows

# Deactivate when done
deactivate
```

## Troubleshooting

### Backend not found

If you get "ModuleNotFoundError: No module named 'ocaml'", make sure you've installed the package:

```bash
uv pip install -e .
```

### Tests failing due to missing Pants

The tests import from Pants, which must be available. Make sure dependencies are installed:

```bash
uv pip install -e ".[dev]"
```

### uv command not found

Make sure uv is installed and in your PATH:

```bash
which uv  # Should show the uv path
# or
echo $PATH | grep -i cargo  # Should include cargo bin if installed via install.sh
```

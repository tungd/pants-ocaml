# Development Guide

## Prerequisites

- Python 3.11
- [Pants](https://www.pantsbuild.org/) (configured via `pants.toml`)
- OCaml toolchain: `ocamlfind`, `ocamldep`, `ocamlopt`
- Optional: `js_of_ocaml` (required for `platform="js_of_ocaml"` and must support `--effects=cps`)

## Plugin Testing Workflow (Recommended)

Use Pants-native plugin tests:

```bash
# Show Pants version
pants --version

# Discover targets
pants list ::

# Run all plugin tests
pants test tests::

# Run only unit tests
pants test tests/unit::

# Run only integration tests
pants test tests/integration::
```

## Repository Layout

```text
.
├── ocaml/                  # Pants backend package
│   ├── BUILD
│   ├── __init__.py
│   ├── register.py
│   ├── target_types.py
│   ├── rules.py
│   ├── providers.py
│   └── subsystem.py
├── tests/
│   ├── BUILD
│   ├── conftest.py
│   ├── unit/
│   └── integration/
├── BUILD                   # pants_requirements(name="pants")
├── pants.toml              # Pants config for plugin development
├── pyproject.toml          # Python package metadata
└── .github/workflows/ci.yml
```

## CI-Equivalent Local Checks

```bash
# Ensure removed worker artifacts are not referenced in plugin code
if grep -r "OCamlWorkerArtifact" . --include="*.py" --exclude-dir="tests" 2>/dev/null; then
  echo "Found OCamlWorkerArtifact references"
  exit 1
fi

if grep -r "worker_entry_js" . --include="*.py" --exclude-dir="tests" 2>/dev/null; then
  echo "Found worker_entry_js references"
  exit 1
fi

# Run plugin test suite
pants test tests::
```

## Optional: Pytest-only Local Runs

If you want to run pytest directly outside Pants, install dev dependencies with your preferred Python tool (for example `uv` or `pip`) and run `pytest`. This is optional and not used by CI.

## Notes

- Do **not** add `pantsbuild.pants` as a PyPI dependency in `pyproject.toml`.
- Pants plugin test dependencies are provided via `pants_requirements` and test target deps in BUILD files.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a **custom Pants backend for OCaml** that adds OCaml language support to the Pants build system. It compiles OCaml sources to bytecode executables and can package them as Cloudflare Workers via `js_of_ocaml`.

## Installation

To use this backend, add it to your `pants.toml`:

```toml
[GLOBAL]
backend_packages = [
    "pants.core",
    "pants.backend.adhoc",  # Required for generated_sources support
    "ocaml",  # This package
]
```

## Target Types

The backend defines 5 target types organized in a dependency hierarchy:

1. **`ocaml_module`** - Single OCaml module (`.ml`/`.mli`) compiled to `.cmo`/`.cmi`. Legacy compatibility target.
2. **`ocaml_library`** - Aggregates `ocaml_module` and `ocaml_library` dependencies. Logical grouping only.
3. **`ocaml_package`** - Package-level target that recursively scans sources and compiles them using `ocamldep` for correct ordering. **Primary target type for new code.**
4. **`ocaml_binary`** - Links bytecode executable from package dependencies and an entry source.
5. **`ocaml_worker_artifact`** - Packages an `ocaml_binary` as a Cloudflare Worker via `js_of_ocaml`.

### Key Fields

- `sources` - Source files (`.ml`/`.mli`)
- `dependencies` - For `ocaml_module`/`ocaml_library`: Pants target addresses
- `dependencies` (named) - For `ocaml_package`/`ocaml_binary`: Package names that resolve to `//{name}:{name}` internally or external ocamlfind packages
- `exposed` - Module names to publicly expose from a package
- `generated_sources` - Addresses of `adhoc_tool` targets that generate `.ml`/`.mli` files
- `packages` - External ocamlfind package dependencies
- `compiler_flags` - Extra flags for ocamlc compilation
- `link_flags` - Extra flags for ocamlc linking
- `entry_source` - Path to `.ml` file used as binary entrypoint
- `binary` - Address of `ocaml_binary` for worker artifacts
- `worker_entry_js` - Path to JavaScript worker wrapper
- `output_path` - Output path for worker artifact (default: `worker.js`)
- `js_of_ocaml_flags` - Extra flags for js_of_ocaml

## Build Pipeline Architecture

The build rules use Pants' engine with async/await patterns:

1. **OCamlClosure** - Transitive compilation closure containing:
   - `digest` - Merged digest of all compiled artifacts
   - `cmo_files` - Compiled `.cmo` files (transitive)
   - `include_dirs` - Include directories for compilation
   - `link_packages` - ocamlfind packages for linking

2. **BuiltOCamlPackage** - Package-level compilation result:
   - `internal_dependency_addresses` - Internal package addresses
   - `external_dependency_names` - ocamlfind package names
   - `private_include_dir` - Internal include path
   - `public_include_dir` - Public include path for dependents
   - `transitive_cmo_files` - All `.cmo` files in closure
   - `transitive_public_include_dirs` - All public include dirs in closure
   - `source_to_cmo` - Mapping of source paths to compiled `.cmo` paths

3. **BuiltOCamlBinary** - Linked bytecode executable with `bytecode_path`

## Tool Configuration

Configure tool paths via `pants.toml`:

```toml
[ocaml-tools]
ocamlfind = "ocamlfind"
ocamldep = "ocamldep"
js_of_ocaml = "js_of_ocaml"
bash = "/bin/bash"
```

The backend automatically configures `PATH`, `HOME`, and `OPAMROOT` environment variables for tool processes.

## Common Development Commands

```bash
# Check OCaml file dependencies
./pants check ::

# Compile a specific target
./pants check //path/to:target

# Build an OCaml binary
./pants package //path/to:binary_target

# Build a worker artifact
./pants package //path/to:worker_target

# List all OCaml targets
./pants filter :: --target-type=ocaml_package
./pants filter :: --target-type=ocaml_binary
```

## Key Implementation Details

### Dependency Resolution

- **Named dependencies** (`dependencies` field on packages/binaries) first try to resolve to `//{name}:{name}` internally
- Unresolved names are treated as external ocamlfind packages
- Internal dependencies must be `ocaml_package` targets

### Compilation Order

- Packages use `ocamldep -sort` to compute correct module compilation order
- Interface files (`.mli`) are compiled before implementation files (`.ml`)
- Generated sources from `adhoc_tool` targets are merged with package sources

### Output Directory Structure

Compiled artifacts are stored under `__pants_ocaml__/`:
- `__pants_ocaml__/module/{spec_path}/{target_name}/`
- `__pants_ocaml__/package_private/{spec_path}/{target_name}/`
- `__pants_ocaml__/package_public/{spec_path}/{target_name}/`
- `__pants_ocaml__/binary/{spec_path}/{target_name}/`
- `__pants_ocaml__/worker/{spec_path}/{target_name}/`

### Entry Source Resolution

Binary `entry_source` field searches for the entry module's `.cmo` file by:
1. Checking `{spec_path}/{entry_source_raw}`
2. Checking `{entry_source_raw}` directly
3. Matching against basename if paths are ambiguous

## File Structure

```
ocaml/
├── __init__.py           # Package marker
├── register.py           # Entry point: registers target types and rules
├── target_types.py       # Target type definitions
├── subsystem.py          # OCamlToolsSubsystem for tool configuration
├── providers.py          # Data classes for build outputs
└── rules.py              # Build rules (@rule decorated functions)
```

## Important Patterns

- All build rules are async functions returning `Get` results or `await MultiGet`
- Use `hydrate_sources()` with `HydrateSourcesRequest` for source files
- Use `resolve_dependencies()` for Pants dependency fields
- Use custom address resolution for named package dependencies
- Shell commands are constructed via `_shell_command()` for proper quoting
- Use `bash -c` wrapper for multi-step compilation pipelines
- Deduplication via `_dedupe()` helper for tuple/list collections

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a **custom Pants backend for OCaml** that adds OCaml language support to the Pants build system. It compiles OCaml sources to executables with support for multiple compilation platforms.

## Installation

To use this backend, add it to your `pants.toml`:

```toml
[GLOBAL]
backend_packages = [
    "pants.core",
    "ocaml",  # This package
]
```

## Target Types

The backend defines 2 target types:

1. **`ocaml_package`** - Package-level target that recursively scans sources and compiles them using `ocamldep` for correct ordering.
2. **`ocaml_binary`** - Links executables from package dependencies and an entry source with platform support.

### Key Fields

- `sources` - Source files (`.ml`/`.mli`)
- `dependencies` (named) - For `ocaml_package`/`ocaml_binary`: Package names that resolve to `//{name}:{name}` internally or external ocamlfind packages
- `exposed` - Module names to publicly expose from a package
- `packages` - External ocamlfind package dependencies
- `compiler_flags` - Extra flags for ocamlc compilation
- `link_flags` - Extra flags for linker
- `entry` - Path to `.ml` file used as binary entrypoint
- `platform` - Compilation platform for binaries: `"bytecode"` (default), `"native"`, or `"js_of_ocaml"`

## Build Pipeline Architecture

The build rules use Pants' engine with async/await patterns:

1. **BuiltOCamlPackage** - Package-level compilation result:
   - `internal_dependency_addresses` - Internal package addresses
   - `external_dependency_names` - ocamlfind package names
   - `private_include_dir` - Internal include path
   - `public_include_dir` - Public include path for dependents
   - `transitive_cmo_files` - All `.cmo` files in closure
   - `transitive_public_include_dirs` - All public include dirs in closure
   - `source_to_cmo` - Mapping of source paths to compiled `.cmo` paths

2. **BuiltOCamlBinary** - Linked executable output with platform support:
   - `digest` - Digest of compiled output
   - `output_path` - Path to compiled output (`.byte`, native exe, or `.js`)
   - `platform` - Platform used: "bytecode", "native", or "js_of_ocaml"

## Tool Configuration

Configure tool paths via `pants.toml`:

```toml
[ocaml-tools]
ocamlfind = "ocamlfind"
ocamldep = "ocamldep"
ocamlopt = "ocamlopt"
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

### Output Directory Structure

Compiled artifacts are stored under `__pants_ocaml__/`:
- `__pants_ocaml__/package_private/{spec_path}/{target_name}/`
- `__pants_ocaml__/package_public/{spec_path}/{target_name}/`
- `__pants_ocaml__/binary/{spec_path}/{target_name}/`

### Platform Support

The `ocaml_binary` target supports three compilation platforms via the `platform` field:

1. **bytecode** (default) - Uses `ocamlc`, outputs `{target_name}.byte`
   - Most compatible, faster compilation
   - Requires ocamlfind

2. **native** - Uses `ocamlopt`, outputs `{target_name}` (native executable)
   - Best performance, slower compilation
   - Requires ocamlopt

3. **js_of_ocaml** - Uses `ocamlc` + `js_of_ocaml`, outputs `{target_name}.js`
   - For web/Node.js deployment
   - Requires js_of_ocaml

### Entry Source Resolution

Binary `entry` field searches for the entry module's compiled object file by:
1. Checking `{spec_path}/{entry_raw}`
2. Checking `{entry_raw}` directly
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
- Use custom address resolution for named package dependencies
- Shell commands are constructed via `_shell_command()` for proper quoting
- Use `bash -c` wrapper for multi-step compilation pipelines
- Deduplication via `_dedupe()` helper for tuple/list collections
- Platform dispatch in binary linking: `_link_bytecode_binary()`, `_link_native_binary()`, `_link_js_of_ocaml_binary()`

"""Provider data structures for OCaml backend rules."""

from __future__ import annotations

from dataclasses import dataclass

from pants.engine.fs import Digest


@dataclass(frozen=True)
class BuiltOCamlPackage:
    """Compiled closure for package-level OCaml targets."""

    digest: Digest
    internal_dependency_addresses: tuple[str, ...]
    external_dependency_names: tuple[str, ...]
    private_include_dir: str
    public_include_dir: str
    transitive_cmo_files: tuple[str, ...]
    transitive_public_include_dirs: tuple[str, ...]
    transitive_external_dependency_names: tuple[str, ...]
    source_to_cmo: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class BuiltOCamlBinary:
    """Linked OCaml executable output (bytecode, native, or js_of_ocaml)."""

    digest: Digest
    output_path: str
    platform: str

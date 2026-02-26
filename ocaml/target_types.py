"""Custom Pants target types for OCaml build artifacts."""

from __future__ import annotations

from pants.engine.target import (
    COMMON_TARGET_FIELDS,
    MultipleSourcesField,
    StringField,
    StringSequenceField,
    Target,
)


class OCamlPackageSourcesField(MultipleSourcesField):
    alias = "sources"
    default = ("**/*.ml", "**/*.mli")
    expected_file_extensions = (".ml", ".mli")
    help = "Recursive OCaml source globs for this package target."


class OCamlDependencyNamesField(StringSequenceField):
    alias = "dependencies"
    default = ()
    help = (
        "Dependency names. Internal package names resolve to //{name}:{name}; "
        "unknown names are treated as external ocamlfind package dependencies."
    )


class OCamlExposedModulesField(StringSequenceField):
    alias = "exposed"
    default = ()
    help = (
        "Public module names exposed to dependent packages. "
        "Empty means all modules in the package are exposed."
    )


class OCamlPackagesField(StringSequenceField):
    alias = "packages"
    default = ()
    help = "ocamlfind package names required by this target."


class OCamlCompilerFlagsField(StringSequenceField):
    alias = "compiler_flags"
    default = ()
    help = "Additional flags passed to ocamlc when compiling modules/packages."


class OCamlGeneratedSourcesField(StringSequenceField):
    alias = "generated_sources"
    default = ()
    help = (
        "Addresses of adhoc_tool targets that generate `.ml`/`.mli` files to include when "
        "compiling this package."
    )


class OCamlLinkFlagsField(StringSequenceField):
    alias = "link_flags"
    default = ()
    help = "Additional flags passed to the linker when linking binaries."


class OCamlPlatformField(StringField):
    alias = "platform"
    default = "bytecode"
    valid_choices = ("bytecode", "native", "js_of_ocaml")
    help = "Compilation platform: bytecode (ocamlc), native (ocamlopt), or js_of_ocaml."


class OCamlEntryField(StringField):
    alias = "entry"
    required = True
    help = "Path to the OCaml implementation source (e.g. main.ml) used as the binary entrypoint."


class OCamlPackage(Target):
    alias = "ocaml_package"
    core_fields = (
        *COMMON_TARGET_FIELDS,
        OCamlPackageSourcesField,
        OCamlDependencyNamesField,
        OCamlExposedModulesField,
        OCamlGeneratedSourcesField,
        OCamlCompilerFlagsField,
    )
    help = "A package-level OCaml target that recursively scans sources and compiles via ocamldep order."


class OCamlBinary(Target):
    alias = "ocaml_binary"
    core_fields = (
        *COMMON_TARGET_FIELDS,
        OCamlDependencyNamesField,
        OCamlEntryField,
        OCamlPlatformField,
        OCamlPackagesField,
        OCamlLinkFlagsField,
    )
    help = "An OCaml executable built from package-level dependencies and an entry source with platform support."

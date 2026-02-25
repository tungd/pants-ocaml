"""Custom Pants target types for OCaml build artifacts."""

from __future__ import annotations

from pants.engine.target import (
    COMMON_TARGET_FIELDS,
    Dependencies,
    MultipleSourcesField,
    SingleSourceField,
    StringField,
    StringSequenceField,
    Target,
)


class OCamlSourcesField(MultipleSourcesField):
    alias = "sources"
    expected_file_extensions = (".ml", ".mli")
    help = "OCaml source files for this module (.ml and optionally .mli)."


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
    help = "Additional flags passed to ocamlc when linking binaries."


class OCamlEntrySourceField(StringField):
    alias = "entry_source"
    required = True
    help = "Path to the OCaml implementation source (e.g. main.ml) used as the binary entrypoint."


class OCamlBinaryAddressField(StringField):
    alias = "binary"
    required = True
    help = "Address of an ocaml_binary target used to build this worker artifact."


class OCamlWorkerEntryJsField(SingleSourceField):
    alias = "worker_entry_js"
    required = True
    expected_file_extensions = (".js",)
    help = "Path to the JavaScript worker entry wrapper appended after js_of_ocaml output."


class OCamlOutputPathField(StringField):
    alias = "output_path"
    default = "worker.js"
    help = "Path (relative to dist/) for the packaged worker artifact."


class OCamlJsOfOcamlFlagsField(StringSequenceField):
    alias = "js_of_ocaml_flags"
    default = ()
    help = "Additional flags passed to js_of_ocaml when producing worker JavaScript."


class OCamlModule(Target):
    alias = "ocaml_module"
    core_fields = (
        *COMMON_TARGET_FIELDS,
        OCamlSourcesField,
        Dependencies,
        OCamlPackagesField,
        OCamlCompilerFlagsField,
    )
    help = "A single OCaml module compiled to .cmo/.cmi outputs. Kept for compatibility."


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


class OCamlLibrary(Target):
    alias = "ocaml_library"
    core_fields = (
        *COMMON_TARGET_FIELDS,
        Dependencies,
        OCamlPackagesField,
    )
    help = "A logical OCaml library target that aggregates module/library dependencies."


class OCamlBinary(Target):
    alias = "ocaml_binary"
    core_fields = (
        *COMMON_TARGET_FIELDS,
        OCamlDependencyNamesField,
        OCamlEntrySourceField,
        OCamlPackagesField,
        OCamlLinkFlagsField,
    )
    help = "An OCaml bytecode executable built from package-level dependencies and an entry source."


class OCamlWorkerArtifact(Target):
    alias = "ocaml_worker_artifact"
    core_fields = (
        *COMMON_TARGET_FIELDS,
        OCamlBinaryAddressField,
        OCamlWorkerEntryJsField,
        OCamlOutputPathField,
        OCamlJsOfOcamlFlagsField,
    )
    help = "A packaged Cloudflare Worker artifact created from an ocaml_binary target."

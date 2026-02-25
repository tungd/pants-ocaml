"""Rules for compiling, linking, and packaging OCaml artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import shlex

from pants.backend.adhoc.target_types import (
    AdhocToolOutputDirectoriesField,
    AdhocToolOutputFilesField,
    AdhocToolRunnableField,
    AdhocToolSourcesField,
    AdhocToolTarget,
)
from pants.build_graph.address import Address, AddressInput
from pants.core.goals.package import (
    BuiltPackage,
    BuiltPackageArtifact,
    PackageFieldSet,
)
from pants.core.target_types import FileSourceField
from pants.engine.fs import (
    CreateDigest,
    Digest,
    MergeDigests,
)
from pants.engine.internals.graph import hydrate_sources, resolve_dependencies, resolve_target
from pants.engine.internals.selectors import Get, MultiGet, concurrently
from pants.engine.process import Process, ProcessResult
from pants.engine.rules import collect_rules, implicitly, rule
from pants.engine.target import (
    Dependencies,
    DependenciesRequest,
    HydrateSourcesRequest,
    Target,
    WrappedTarget,
    WrappedTargetRequest,
)
from pants.engine.unions import UnionRule

from ocaml.providers import BuiltOCamlBinary, BuiltOCamlPackage, OCamlClosure
from ocaml.subsystem import OCamlToolsSubsystem
from ocaml.target_types import (
    OCamlBinary,
    OCamlCompilerFlagsField,
    OCamlDependencyNamesField,
    OCamlEntrySourceField,
    OCamlExposedModulesField,
    OCamlGeneratedSourcesField,
    OCamlLibrary,
    OCamlLinkFlagsField,
    OCamlModule,
    OCamlPackage,
    OCamlPackageSourcesField,
    OCamlPackagesField,
    OCamlPlatformField,
    OCamlSourcesField,
)


@dataclass(frozen=True)
class BuildOCamlTargetRequest:
    address: Address


@dataclass(frozen=True)
class BuildOCamlModuleRequest:
    address: Address


@dataclass(frozen=True)
class BuildOCamlLibraryRequest:
    address: Address


@dataclass(frozen=True)
class BuildOCamlPackageRequest:
    address: Address


@dataclass(frozen=True)
class BuildOCamlBinaryRequest:
    address: Address


@dataclass(frozen=True)
class AdhocToolArtifactFieldSet(PackageFieldSet):
    required_fields = (AdhocToolRunnableField, AdhocToolSourcesField)

    output_files: AdhocToolOutputFilesField
    output_directories: AdhocToolOutputDirectoriesField


def _dedupe(items: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


def _target_output_dir(kind: str, address: Address) -> str:
    spec_path = address.spec_path if address.spec_path else "_root_"
    return f"__pants_ocaml__/{kind}/{spec_path}/{address.target_name}"


def _join_shell(parts: list[str]) -> str:
    return " ".join(p for p in parts if p)


def _split_command(command: str) -> tuple[str, ...]:
    parts = tuple(shlex.split(command))
    if not parts:
        raise ValueError("Tool command cannot be empty.")
    return parts


def _shell_command(command: str) -> str:
    return " ".join(shlex.quote(part) for part in _split_command(command))


def _tool_process_env(ocaml_tools: OCamlToolsSubsystem) -> dict[str, str]:
    tool_dirs: list[str] = []
    for command in (ocaml_tools.ocamlfind, ocaml_tools.ocamldep, ocaml_tools.ocamlopt, ocaml_tools.js_of_ocaml):
        binary = _split_command(command)[0]
        if os.path.isabs(binary):
            tool_dirs.append(str(Path(binary).parent))

    path_parts: list[str] = list(_dedupe(tool_dirs))
    existing_path = os.environ.get("PATH")
    if existing_path:
        path_parts.append(existing_path)

    env: dict[str, str] = {}
    if path_parts:
        env["PATH"] = ":".join(path_parts)

    home = os.environ.get("HOME")
    if home:
        env["HOME"] = home

    opam_root = os.environ.get("OPAMROOT")
    if opam_root:
        env["OPAMROOT"] = opam_root

    return env


def _module_name_from_stem(stem: str) -> str:
    return stem[:1].upper() + stem[1:] if stem else stem


async def _resolve_relative_address(raw_value: str, owner: Address, field_alias: str) -> Address:
    address_input = AddressInput.parse(
        raw_value,
        relative_to=owner.spec_path,
        description_of_origin=f"the `{field_alias}` field on `{owner}`",
    )
    return await Get(Address, AddressInput, address_input)


async def _resolve_wrapped_target(address: Address, description_of_origin: str) -> WrappedTarget:
    return await resolve_target(
        WrappedTargetRequest(address, description_of_origin=description_of_origin),
        **implicitly(),
    )


async def _resolve_module_or_library_dependencies(target: Target) -> tuple[Target, ...]:
    dep_addresses = await resolve_dependencies(**implicitly(DependenciesRequest(target[Dependencies])))
    wrapped_deps = await concurrently(
        _resolve_wrapped_target(dep_address, "<infallible>") for dep_address in dep_addresses
    )
    dep_targets = tuple(wrapped.target for wrapped in wrapped_deps)
    resolved: list[Target] = []
    for dep in dep_targets:
        if dep.alias not in {OCamlModule.alias, OCamlLibrary.alias}:
            raise ValueError(
                f"{target.address} has unsupported dependency `{dep.address}` of type `{dep.alias}`. "
                f"Allowed dependency types: {OCamlModule.alias}, {OCamlLibrary.alias}."
            )
        resolved.append(dep)
    return tuple(resolved)


async def _resolve_internal_package_by_name(name: str) -> Target | None:
    try:
        address_input = AddressInput.parse(
            f"//{name}:{name}",
            description_of_origin=f"ocaml package name `{name}`",
        )
        address = await Get(Address, AddressInput, address_input)
        wrapped = await _resolve_wrapped_target(address, f"ocaml package name `{name}`")
    except Exception:
        return None

    if wrapped.target.alias != OCamlPackage.alias:
        raise ValueError(
            f"Dependency name `{name}` resolved to `{wrapped.target.address}` but target type is "
            f"`{wrapped.target.alias}` instead of `{OCamlPackage.alias}`."
        )

    return wrapped.target


async def _resolve_named_dependencies(
    owner: Address,
    names: tuple[str, ...],
) -> tuple[tuple[Target, ...], tuple[str, ...]]:
    internal_targets: list[Target] = []
    external_packages: list[str] = []

    for name in _dedupe(list(names)):
        if not name:
            continue
        internal_target = await _resolve_internal_package_by_name(name)
        if internal_target is None:
            external_packages.append(name)
            continue

        if internal_target.address == owner:
            raise ValueError(f"{owner} cannot depend on itself via dependency name `{name}`")

        internal_targets.append(internal_target)

    return tuple(internal_targets), _dedupe(external_packages)


async def _resolve_generated_source_targets(
    owner: Address,
    generated_source_addresses: tuple[str, ...],
) -> tuple[Target, ...]:
    targets: list[Target] = []
    for raw_address in _dedupe(list(generated_source_addresses)):
        if not raw_address:
            continue

        address = await _resolve_relative_address(
            raw_address,
            owner=owner,
            field_alias=OCamlGeneratedSourcesField.alias,
        )
        wrapped = await _resolve_wrapped_target(
            address,
            f"`{OCamlGeneratedSourcesField.alias}` on `{owner}`",
        )
        if wrapped.target.alias != AdhocToolTarget.alias:
            raise ValueError(
                f"{owner} has non-`{AdhocToolTarget.alias}` generated source target "
                f"`{wrapped.target.address}` of type `{wrapped.target.alias}`."
            )
        targets.append(wrapped.target)

    return tuple(targets)


async def _merge_or_create_empty(digests: tuple[Digest, ...]) -> Digest:
    if not digests:
        return await Get(Digest, CreateDigest(()))
    if len(digests) == 1:
        return digests[0]
    return await Get(Digest, MergeDigests(digests))


def _resolve_exposed_stems(
    target_address: Address,
    stems: tuple[str, ...],
    exposed_modules: tuple[str, ...],
) -> tuple[str, ...]:
    if not exposed_modules:
        return stems

    module_by_name: dict[str, str] = {_module_name_from_stem(stem): stem for stem in stems}
    stem_set = set(stems)

    resolved: list[str] = []
    for module in exposed_modules:
        if module in module_by_name:
            resolved.append(module_by_name[module])
            continue
        if module in stem_set:
            resolved.append(module)
            continue
        known = ", ".join(sorted(module_by_name.keys()))
        raise ValueError(
            f"{target_address} has unknown module `{module}` in `exposed`. Known modules: {known}"
        )

    return _dedupe(resolved)


@rule(desc="Build OCaml transitive closure")
async def build_ocaml_target(request: BuildOCamlTargetRequest) -> OCamlClosure:
    wrapped = await _resolve_wrapped_target(request.address, f"the target `{request.address}`")
    target = wrapped.target

    if target.alias == OCamlModule.alias:
        return await Get(OCamlClosure, BuildOCamlModuleRequest(request.address))
    if target.alias == OCamlLibrary.alias:
        return await Get(OCamlClosure, BuildOCamlLibraryRequest(request.address))

    raise ValueError(
        f"`{request.address}` is `{target.alias}`. Only {OCamlModule.alias} and "
        f"{OCamlLibrary.alias} can be used in OCaml module/library closures."
    )


@rule(desc="Compile OCaml module (compatibility target)")
async def build_ocaml_module(
    request: BuildOCamlModuleRequest,
    ocaml_tools: OCamlToolsSubsystem,
) -> OCamlClosure:
    wrapped = await _resolve_wrapped_target(request.address, f"the target `{request.address}`")
    target = wrapped.target
    if target.alias != OCamlModule.alias:
        raise ValueError(f"Expected `{OCamlModule.alias}` target, got `{target.alias}` at {target.address}")

    dep_targets = await _resolve_module_or_library_dependencies(target)
    dep_closures = (
        await MultiGet(
            Get(OCamlClosure, BuildOCamlTargetRequest(dep.address))
            for dep in dep_targets
        )
        if dep_targets
        else ()
    )

    hydrated = await hydrate_sources(
        HydrateSourcesRequest(target[OCamlSourcesField]),
        **implicitly(),
    )
    source_files = tuple(sorted(hydrated.snapshot.files))
    ml_files = tuple(f for f in source_files if f.endswith(".ml"))
    mli_files = tuple(f for f in source_files if f.endswith(".mli"))

    if len(ml_files) != 1:
        raise ValueError(
            f"{target.address} must have exactly one `.ml` source in `sources`; found {len(ml_files)}."
        )
    if len(mli_files) > 1:
        raise ValueError(
            f"{target.address} can have at most one `.mli` source in `sources`; found {len(mli_files)}."
        )

    ml_file = ml_files[0]
    mli_file = mli_files[0] if mli_files else None
    module_basename = Path(ml_file).stem

    dep_include_dirs = _dedupe([inc for closure in dep_closures for inc in closure.include_dirs])
    dep_cmo_files = _dedupe([cmo for closure in dep_closures for cmo in closure.cmo_files])
    dep_link_packages = _dedupe([pkg for closure in dep_closures for pkg in closure.link_packages])

    self_packages = tuple(target[OCamlPackagesField].value or ())
    self_compiler_flags = tuple(target[OCamlCompilerFlagsField].value or ())

    output_dir = _target_output_dir("module", target.address)
    cmo_path = f"{output_dir}/{module_basename}.cmo"
    cmi_path = f"{output_dir}/{module_basename}.cmi"

    include_dirs = _dedupe([*dep_include_dirs, output_dir])

    input_digest = await _merge_or_create_empty(
        (
            hydrated.snapshot.digest,
            *tuple(closure.digest for closure in dep_closures),
        )
    )

    package_arg = f"-package {shlex.quote(','.join(self_packages))}" if self_packages else ""
    include_args = " ".join(f"-I {shlex.quote(inc)}" for inc in include_dirs)
    compiler_flags = " ".join(shlex.quote(flag) for flag in self_compiler_flags)

    compile_prefix = _join_shell(
        [
            _shell_command(ocaml_tools.ocamlfind),
            "ocamlc",
            package_arg,
            "-c",
            include_args,
            compiler_flags,
        ]
    )

    script_lines = [
        "set -euo pipefail",
        f"mkdir -p {shlex.quote(output_dir)}",
    ]

    if mli_file:
        script_lines.append(
            _join_shell([
                compile_prefix,
                shlex.quote(mli_file),
                "-o",
                shlex.quote(cmi_path),
            ])
        )

    script_lines.append(
        _join_shell([
            compile_prefix,
            shlex.quote(ml_file),
            "-o",
            shlex.quote(cmo_path),
        ])
    )

    process = Process(
        argv=(ocaml_tools.bash, "-c", "\n".join(script_lines)),
        env=_tool_process_env(ocaml_tools),
        input_digest=input_digest,
        output_files=(cmo_path, cmi_path),
        description=f"Compile OCaml module {target.address}",
    )
    process_result = await Get(ProcessResult, Process, process)

    closure_digest = await _merge_or_create_empty(
        (
            process_result.output_digest,
            *tuple(closure.digest for closure in dep_closures),
        )
    )

    return OCamlClosure(
        digest=closure_digest,
        cmo_files=_dedupe([*dep_cmo_files, cmo_path]),
        include_dirs=include_dirs,
        link_packages=_dedupe([*dep_link_packages, *self_packages]),
    )


@rule(desc="Build OCaml library closure (compatibility target)")
async def build_ocaml_library(request: BuildOCamlLibraryRequest) -> OCamlClosure:
    wrapped = await _resolve_wrapped_target(request.address, f"the target `{request.address}`")
    target = wrapped.target
    if target.alias != OCamlLibrary.alias:
        raise ValueError(f"Expected `{OCamlLibrary.alias}` target, got `{target.alias}` at {target.address}")

    dep_targets = await _resolve_module_or_library_dependencies(target)
    dep_closures = (
        await MultiGet(
            Get(OCamlClosure, BuildOCamlTargetRequest(dep.address))
            for dep in dep_targets
        )
        if dep_targets
        else ()
    )

    closure_digest = await _merge_or_create_empty(tuple(closure.digest for closure in dep_closures))

    self_packages = tuple(target[OCamlPackagesField].value or ())
    dep_cmo_files = _dedupe([cmo for closure in dep_closures for cmo in closure.cmo_files])
    dep_include_dirs = _dedupe([inc for closure in dep_closures for inc in closure.include_dirs])
    dep_link_packages = _dedupe([pkg for closure in dep_closures for pkg in closure.link_packages])

    return OCamlClosure(
        digest=closure_digest,
        cmo_files=dep_cmo_files,
        include_dirs=dep_include_dirs,
        link_packages=_dedupe([*dep_link_packages, *self_packages]),
    )


@rule(desc="Compile OCaml package")
async def build_ocaml_package(
    request: BuildOCamlPackageRequest,
    ocaml_tools: OCamlToolsSubsystem,
) -> BuiltOCamlPackage:
    wrapped = await _resolve_wrapped_target(request.address, f"the target `{request.address}`")
    target = wrapped.target
    if target.alias != OCamlPackage.alias:
        raise ValueError(f"Expected `{OCamlPackage.alias}` target, got `{target.alias}` at {target.address}")

    dependency_names = tuple(target[OCamlDependencyNamesField].value or ())
    internal_dep_targets, external_dep_names = await _resolve_named_dependencies(target.address, dependency_names)

    dep_packages = (
        await MultiGet(
            Get(BuiltOCamlPackage, BuildOCamlPackageRequest(dep.address))
            for dep in internal_dep_targets
        )
        if internal_dep_targets
        else ()
    )

    hydrated = await hydrate_sources(
        HydrateSourcesRequest(target[OCamlPackageSourcesField]),
        **implicitly(),
    )
    source_files = tuple(sorted(hydrated.snapshot.files))

    generated_source_specs = tuple(target[OCamlGeneratedSourcesField].value or ())
    generated_source_targets = await _resolve_generated_source_targets(
        target.address, generated_source_specs
    )
    generated_hydrated_sources = (
        await MultiGet(
            hydrate_sources(
                HydrateSourcesRequest(
                    generated_target[AdhocToolSourcesField],
                    for_sources_types=(FileSourceField,),
                    enable_codegen=True,
                ),
                **implicitly(),
            )
            for generated_target in generated_source_targets
        )
        if generated_source_targets
        else ()
    )

    generated_source_files: list[str] = []
    generated_path_to_target: dict[str, Address] = {}
    for generated_target, generated_hydrated in zip(
        generated_source_targets, generated_hydrated_sources
    ):
        if generated_hydrated.sources_type is None:
            raise ValueError(
                f"{target.address} failed to generate sources from `{generated_target.address}`."
            )
        for generated_file in generated_hydrated.snapshot.files:
            if not generated_file.endswith((".ml", ".mli")):
                raise ValueError(
                    f"{target.address} generated source target `{generated_target.address}` produced "
                    f"`{generated_file}`, which is not a `.ml` or `.mli` file."
                )
            generated_source_files.append(generated_file)
            existing_target = generated_path_to_target.get(generated_file)
            if existing_target is not None and existing_target != generated_target.address:
                raise ValueError(
                    f"{target.address} has multiple generated source targets producing "
                    f"`{generated_file}`: `{existing_target}` and `{generated_target.address}`."
                )
            generated_path_to_target[generated_file] = generated_target.address

    colliding_paths = sorted(set(source_files).intersection(generated_source_files))
    if colliding_paths:
        collisions = ", ".join(colliding_paths)
        raise ValueError(
            f"{target.address} has generated source path collisions with package sources: {collisions}"
        )

    all_source_files = tuple(sorted([*source_files, *generated_source_files]))

    ml_files = tuple(f for f in all_source_files if f.endswith(".ml"))
    mli_files = tuple(f for f in all_source_files if f.endswith(".mli"))

    if not ml_files:
        raise ValueError(f"{target.address} has no `.ml` files in `sources` globs")

    ml_by_stem: dict[str, str] = {}
    for ml in ml_files:
        stem = Path(ml).stem
        if stem in ml_by_stem:
            raise ValueError(
                f"{target.address} has duplicate module basename `{stem}` in package sources: "
                f"`{ml_by_stem[stem]}` and `{ml}`"
            )
        ml_by_stem[stem] = ml

    mli_by_stem: dict[str, str] = {}
    for mli in mli_files:
        stem = Path(mli).stem
        if stem in mli_by_stem:
            raise ValueError(
                f"{target.address} has duplicate interface basename `{stem}` in package sources: "
                f"`{mli_by_stem[stem]}` and `{mli}`"
            )
        mli_by_stem[stem] = mli

    own_stems = tuple(sorted(ml_by_stem.keys()))
    exposed_modules = tuple(target[OCamlExposedModulesField].value or ())
    exposed_stems = _resolve_exposed_stems(target.address, own_stems, exposed_modules)

    dep_public_include_dirs = _dedupe(
        [inc for dep in dep_packages for inc in dep.transitive_public_include_dirs]
    )
    dep_transitive_cmos = _dedupe([cmo for dep in dep_packages for cmo in dep.transitive_cmo_files])
    dep_external_names = _dedupe(
        [name for dep in dep_packages for name in dep.transitive_external_dependency_names]
    )

    compiler_dependency_names = _dedupe([*dep_external_names, *external_dep_names])

    self_compiler_flags = tuple(target[OCamlCompilerFlagsField].value or ())

    private_include_dir = _target_output_dir("package_private", target.address)
    public_include_dir = _target_output_dir("package_public", target.address)

    compile_include_dirs = _dedupe([*dep_public_include_dirs, private_include_dir])

    input_digest = await _merge_or_create_empty(
        (
            hydrated.snapshot.digest,
            *tuple(generated.snapshot.digest for generated in generated_hydrated_sources),
            *tuple(dep.digest for dep in dep_packages),
        )
    )

    ocamldep_argv = [*_split_command(ocaml_tools.ocamldep), "-sort"]
    for inc in dep_public_include_dirs:
        ocamldep_argv.extend(["-I", inc])
    ocamldep_argv.extend(ml_files)

    dep_result = await Get(
        ProcessResult,
        Process(
            argv=tuple(ocamldep_argv),
            env=_tool_process_env(ocaml_tools),
            input_digest=input_digest,
            description=f"Compute ocamldep order for {target.address}",
        ),
    )

    ordered_ml = [tok for tok in dep_result.stdout.decode().split() if tok.endswith(".ml")]
    ordered_ml = [ml for ml in ordered_ml if ml in ml_by_stem.values()]

    if not ordered_ml:
        ordered_ml = list(ml_files)

    ordered_set = set(ordered_ml)
    for ml in ml_files:
        if ml not in ordered_set:
            ordered_ml.append(ml)

    package_arg = (
        f"-package {shlex.quote(','.join(compiler_dependency_names))}"
        if compiler_dependency_names
        else ""
    )
    include_args = " ".join(f"-I {shlex.quote(inc)}" for inc in compile_include_dirs)
    compiler_flags = " ".join(shlex.quote(flag) for flag in self_compiler_flags)

    compile_prefix = _join_shell(
        [
            _shell_command(ocaml_tools.ocamlfind),
            "ocamlc",
            package_arg,
            "-c",
            include_args,
            compiler_flags,
        ]
    )

    script_lines = [
        "set -euo pipefail",
        f"mkdir -p {shlex.quote(private_include_dir)}",
        f"mkdir -p {shlex.quote(public_include_dir)}",
    ]

    own_cmo_files: list[str] = []
    own_cmi_files: list[str] = []
    public_cmi_files: list[str] = []
    source_to_cmo: list[tuple[str, str]] = []

    compiled_mli_stems: set[str] = set()

    for ml in ordered_ml:
        stem = Path(ml).stem
        cmo_path = f"{private_include_dir}/{stem}.cmo"
        cmi_path = f"{private_include_dir}/{stem}.cmi"

        mli = mli_by_stem.get(stem)
        if mli and stem not in compiled_mli_stems:
            script_lines.append(
                _join_shell([
                    compile_prefix,
                    shlex.quote(mli),
                    "-o",
                    shlex.quote(cmi_path),
                ])
            )
            compiled_mli_stems.add(stem)

        script_lines.append(
            _join_shell([
                compile_prefix,
                shlex.quote(ml),
                "-o",
                shlex.quote(cmo_path),
            ])
        )

        if stem in exposed_stems:
            public_cmi_path = f"{public_include_dir}/{stem}.cmi"
            script_lines.append(
                _join_shell(["cp", shlex.quote(cmi_path), shlex.quote(public_cmi_path)])
            )
            public_cmi_files.append(public_cmi_path)

        own_cmo_files.append(cmo_path)
        own_cmi_files.append(cmi_path)
        source_to_cmo.append((ml, cmo_path))

    output_files = tuple(_dedupe([*own_cmo_files, *own_cmi_files, *public_cmi_files]))

    process = Process(
        argv=(ocaml_tools.bash, "-c", "\n".join(script_lines)),
        env=_tool_process_env(ocaml_tools),
        input_digest=input_digest,
        output_files=output_files,
        description=f"Compile OCaml package {target.address}",
    )
    compile_result = await Get(ProcessResult, Process, process)

    closure_digest = await _merge_or_create_empty(
        (
            compile_result.output_digest,
            *tuple(dep.digest for dep in dep_packages),
        )
    )

    return BuiltOCamlPackage(
        digest=closure_digest,
        internal_dependency_addresses=tuple(str(dep.address) for dep in internal_dep_targets),
        external_dependency_names=external_dep_names,
        private_include_dir=private_include_dir,
        public_include_dir=public_include_dir,
        transitive_cmo_files=_dedupe([*dep_transitive_cmos, *own_cmo_files]),
        transitive_public_include_dirs=_dedupe([*dep_public_include_dirs, public_include_dir]),
        transitive_external_dependency_names=compiler_dependency_names,
        source_to_cmo=tuple(source_to_cmo),
    )


@rule(desc="Link OCaml binary")
async def build_ocaml_binary(
    request: BuildOCamlBinaryRequest,
    ocaml_tools: OCamlToolsSubsystem,
) -> BuiltOCamlBinary:
    wrapped = await _resolve_wrapped_target(request.address, f"the target `{request.address}`")
    target = wrapped.target
    if target.alias != OCamlBinary.alias:
        raise ValueError(f"Expected `{OCamlBinary.alias}` target, got `{target.alias}` at {target.address}")

    dependency_names = tuple(target[OCamlDependencyNamesField].value or ())
    internal_dep_targets, external_dep_names = await _resolve_named_dependencies(target.address, dependency_names)

    if not internal_dep_targets:
        raise ValueError(
            f"{target.address} must have at least one internal package dependency name resolving to `{OCamlPackage.alias}`"
        )

    dep_packages = await MultiGet(
        Get(BuiltOCamlPackage, BuildOCamlPackageRequest(dep.address))
        for dep in internal_dep_targets
    )

    all_cmo_files = _dedupe([cmo for dep in dep_packages for cmo in dep.transitive_cmo_files])
    all_include_dirs = _dedupe([inc for dep in dep_packages for inc in dep.transitive_public_include_dirs])
    dep_external_names = _dedupe(
        [name for dep in dep_packages for name in dep.transitive_external_dependency_names]
    )

    source_to_cmo: dict[str, str] = {}
    for dep in dep_packages:
        for src, cmo in dep.source_to_cmo:
            source_to_cmo[src] = cmo

    entry_source_raw = target[OCamlEntrySourceField].value
    candidate_paths = []
    if target.address.spec_path:
        candidate_paths.append(os.path.join(target.address.spec_path, entry_source_raw))
    candidate_paths.append(entry_source_raw)

    entry_cmo = None
    for candidate in candidate_paths:
        if candidate in source_to_cmo:
            entry_cmo = source_to_cmo[candidate]
            break

    if entry_cmo is None:
        basename_matches = [
            cmo
            for src, cmo in source_to_cmo.items()
            if src.endswith(f"/{entry_source_raw}") or src == entry_source_raw
        ]
        basename_matches = list(_dedupe(basename_matches))
        if len(basename_matches) == 1:
            entry_cmo = basename_matches[0]
        elif len(basename_matches) > 1:
            raise ValueError(
                f"{target.address} entry_source `{entry_source_raw}` is ambiguous across package closure. "
                "Use a more specific relative path."
            )

    if entry_cmo is None:
        known = ", ".join(sorted(source_to_cmo.keys()))
        raise ValueError(
            f"{target.address} entry_source `{entry_source_raw}` not found in dependency package sources. "
            f"Known sources: {known}"
        )

    self_packages = tuple(target[OCamlPackagesField].value or ())
    self_link_flags = tuple(target[OCamlLinkFlagsField].value or ())
    all_external_names = _dedupe([*dep_external_names, *external_dep_names, *self_packages])

    input_digest = await _merge_or_create_empty(tuple(dep.digest for dep in dep_packages))

    output_dir = _target_output_dir("binary", target.address)
    platform = target[OCamlPlatformField].value or "bytecode"

    if platform == "bytecode":
        return await _link_bytecode_binary(
            target=target,
            ocaml_tools=ocaml_tools,
            all_cmo_files=all_cmo_files,
            all_include_dirs=all_include_dirs,
            all_external_names=all_external_names,
            self_link_flags=self_link_flags,
            input_digest=input_digest,
            output_dir=output_dir,
        )
    elif platform == "native":
        return await _link_native_binary(
            target=target,
            ocaml_tools=ocaml_tools,
            all_cmo_files=all_cmo_files,
            all_include_dirs=all_include_dirs,
            all_external_names=all_external_names,
            self_link_flags=self_link_flags,
            input_digest=input_digest,
            output_dir=output_dir,
        )
    elif platform == "js_of_ocaml":
        return await _link_js_of_ocaml_binary(
            target=target,
            ocaml_tools=ocaml_tools,
            all_cmo_files=all_cmo_files,
            all_include_dirs=all_include_dirs,
            all_external_names=all_external_names,
            self_link_flags=self_link_flags,
            input_digest=input_digest,
            output_dir=output_dir,
        )
    else:
        raise ValueError(
            f"{target.address} has unknown platform `{platform}`. "
            f"Valid choices: bytecode, native, js_of_ocaml"
        )


async def _link_bytecode_binary(
    target: Target,
    ocaml_tools: OCamlToolsSubsystem,
    all_cmo_files: tuple[str, ...],
    all_include_dirs: tuple[str, ...],
    all_external_names: tuple[str, ...],
    self_link_flags: tuple[str, ...],
    input_digest: Digest,
    output_dir: str,
) -> BuiltOCamlBinary:
    """Link a bytecode executable using ocamlc."""
    output_path = f"{output_dir}/{target.address.target_name}.byte"

    package_arg = f"-package {shlex.quote(','.join(all_external_names))}" if all_external_names else ""
    include_args = " ".join(f"-I {shlex.quote(inc)}" for inc in all_include_dirs)
    link_flags = " ".join(shlex.quote(flag) for flag in self_link_flags)
    cmo_args = " ".join(shlex.quote(cmo) for cmo in all_cmo_files)

    script = "\n".join(
        [
            "set -euo pipefail",
            f"mkdir -p {shlex.quote(output_dir)}",
            _join_shell(
                [
                    _shell_command(ocaml_tools.ocamlfind),
                    "ocamlc",
                    "-linkpkg",
                    package_arg,
                    include_args,
                    link_flags,
                    cmo_args,
                    "-o",
                    shlex.quote(output_path),
                ]
            ),
        ]
    )

    process = Process(
        argv=(ocaml_tools.bash, "-c", script),
        env=_tool_process_env(ocaml_tools),
        input_digest=input_digest,
        output_files=(output_path,),
        description=f"Link OCaml bytecode binary {target.address}",
    )
    result = await Get(ProcessResult, Process, process)

    return BuiltOCamlBinary(digest=result.output_digest, output_path=output_path, platform="bytecode")


async def _link_native_binary(
    target: Target,
    ocaml_tools: OCamlToolsSubsystem,
    all_cmo_files: tuple[str, ...],
    all_include_dirs: tuple[str, ...],
    all_external_names: tuple[str, ...],
    self_link_flags: tuple[str, ...],
    input_digest: Digest,
    output_dir: str,
) -> BuiltOCamlBinary:
    """Link a native executable using ocamlopt."""
    output_path = f"{output_dir}/{target.address.target_name}"

    # For native compilation, we need to use .cmx files instead of .cmo
    # Replace .cmo extension with .cmx for object files
    cmx_files = tuple(cmo.replace(".cmo", ".cmx") for cmo in all_cmo_files)

    package_arg = f"-package {shlex.quote(','.join(all_external_names))}" if all_external_names else ""
    include_args = " ".join(f"-I {shlex.quote(inc)}" for inc in all_include_dirs)
    link_flags = " ".join(shlex.quote(flag) for flag in self_link_flags)
    cmx_args = " ".join(shlex.quote(cmx) for cmx in cmx_files)

    script = "\n".join(
        [
            "set -euo pipefail",
            f"mkdir -p {shlex.quote(output_dir)}",
            _join_shell(
                [
                    _shell_command(ocaml_tools.ocamlfind),
                    "ocamlopt",
                    "-linkpkg",
                    package_arg,
                    include_args,
                    link_flags,
                    cmx_args,
                    "-o",
                    shlex.quote(output_path),
                ]
            ),
        ]
    )

    process = Process(
        argv=(ocaml_tools.bash, "-c", script),
        env=_tool_process_env(ocaml_tools),
        input_digest=input_digest,
        output_files=(output_path,),
        description=f"Link OCaml native binary {target.address}",
    )
    result = await Get(ProcessResult, Process, process)

    return BuiltOCamlBinary(digest=result.output_digest, output_path=output_path, platform="native")


async def _link_js_of_ocaml_binary(
    target: Target,
    ocaml_tools: OCamlToolsSubsystem,
    all_cmo_files: tuple[str, ...],
    all_include_dirs: tuple[str, ...],
    all_external_names: tuple[str, ...],
    self_link_flags: tuple[str, ...],
    input_digest: Digest,
    output_dir: str,
) -> BuiltOCamlBinary:
    """Compile to bytecode then convert to JavaScript using js_of_ocaml."""
    bytecode_path = f"{output_dir}/{target.address.target_name}.byte"
    js_path = f"{output_dir}/{target.address.target_name}.js"

    # Step 1: Compile to bytecode
    package_arg = f"-package {shlex.quote(','.join(all_external_names))}" if all_external_names else ""
    include_args = " ".join(f"-I {shlex.quote(inc)}" for inc in all_include_dirs)
    link_flags = " ".join(shlex.quote(flag) for flag in self_link_flags)
    cmo_args = " ".join(shlex.quote(cmo) for cmo in all_cmo_files)

    bytecode_script = "\n".join(
        [
            "set -euo pipefail",
            f"mkdir -p {shlex.quote(output_dir)}",
            _join_shell(
                [
                    _shell_command(ocaml_tools.ocamlfind),
                    "ocamlc",
                    "-linkpkg",
                    package_arg,
                    include_args,
                    link_flags,
                    cmo_args,
                    "-o",
                    shlex.quote(bytecode_path),
                ]
            ),
        ]
    )

    bytecode_process = Process(
        argv=(ocaml_tools.bash, "-c", bytecode_script),
        env=_tool_process_env(ocaml_tools),
        input_digest=input_digest,
        output_files=(bytecode_path,),
        description=f"Link OCaml bytecode for js_of_ocaml {target.address}",
    )
    bytecode_result = await Get(ProcessResult, Process, bytecode_process)

    # Step 2: Convert bytecode to JavaScript
    js_script = "\n".join(
        [
            "set -euo pipefail",
            _join_shell(
                [
                    _shell_command(ocaml_tools.js_of_ocaml),
                    shlex.quote(bytecode_path),
                    "-o",
                    shlex.quote(js_path),
                ]
            ),
        ]
    )

    js_process = Process(
        argv=(ocaml_tools.bash, "-c", js_script),
        env=_tool_process_env(ocaml_tools),
        input_digest=bytecode_result.output_digest,
        output_files=(js_path,),
        description=f"Convert to JavaScript {target.address}",
    )
    js_result = await Get(ProcessResult, Process, js_process)

    return BuiltOCamlBinary(digest=js_result.output_digest, output_path=js_path, platform="js_of_ocaml")


@rule(desc="Package adhoc tool outputs")
async def package_adhoc_tool_artifact(
    field_set: AdhocToolArtifactFieldSet,
) -> BuiltPackage:
    wrapped = await _resolve_wrapped_target(field_set.address, f"the target `{field_set.address}`")
    target = wrapped.target
    if target.alias != AdhocToolTarget.alias:
        raise ValueError(
            f"Expected `{AdhocToolTarget.alias}` target for packaging, got `{target.alias}`"
        )

    generated_sources = await hydrate_sources(
        HydrateSourcesRequest(
            target[AdhocToolSourcesField],
            for_sources_types=(FileSourceField,),
            enable_codegen=True,
        ),
        **implicitly(),
    )
    if generated_sources.sources_type is None:
        raise ValueError(f"{field_set.address} failed to generate packageable source outputs.")
    artifact_paths = tuple(sorted(generated_sources.snapshot.files))
    if not artifact_paths:
        raise ValueError(f"{field_set.address} produced no files to package.")

    return BuiltPackage(
        digest=generated_sources.snapshot.digest,
        artifacts=tuple(BuiltPackageArtifact(relpath=path) for path in artifact_paths),
    )


def rules() -> list:
    return [
        *collect_rules(),
        UnionRule(PackageFieldSet, AdhocToolArtifactFieldSet),
    ]

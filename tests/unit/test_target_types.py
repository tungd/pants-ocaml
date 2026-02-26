"""Unit tests for OCaml target types."""

from __future__ import annotations

from pants.engine.target import StringField, StringSequenceField
from pants.engine.target import Target as PantsTarget

from ocaml import register
from ocaml.target_types import (
    OCamlBinary,
    OCamlCompilerFlagsField,
    OCamlDependencyNamesField,
    OCamlEntryField,
    OCamlExposedModulesField,
    OCamlGeneratedSourcesField,
    OCamlLinkFlagsField,
    OCamlPackage,
    OCamlPackageSourcesField,
    OCamlPackagesField,
    OCamlPlatformField,
)


class TestOCamlPlatformField:
    def test_alias(self) -> None:
        assert OCamlPlatformField.alias == "platform"

    def test_default(self) -> None:
        assert OCamlPlatformField.default == "bytecode"

    def test_valid_choices(self) -> None:
        assert OCamlPlatformField.valid_choices == ("bytecode", "native", "js_of_ocaml")

    def test_is_string_field(self) -> None:
        assert issubclass(OCamlPlatformField, StringField)


class TestOCamlPackageSourcesField:
    def test_alias(self) -> None:
        assert OCamlPackageSourcesField.alias == "sources"

    def test_default(self) -> None:
        assert OCamlPackageSourcesField.default == ("**/*.ml", "**/*.mli")

    def test_expected_file_extensions(self) -> None:
        assert OCamlPackageSourcesField.expected_file_extensions == (".ml", ".mli")


class TestOCamlDependencyNamesField:
    def test_alias(self) -> None:
        assert OCamlDependencyNamesField.alias == "dependencies"

    def test_default(self) -> None:
        assert OCamlDependencyNamesField.default == ()

    def test_is_string_sequence_field(self) -> None:
        assert issubclass(OCamlDependencyNamesField, StringSequenceField)


class TestOCamlPackagesField:
    def test_alias(self) -> None:
        assert OCamlPackagesField.alias == "packages"

    def test_default(self) -> None:
        assert OCamlPackagesField.default == ()


class TestOCamlCompilerFlagsField:
    def test_alias(self) -> None:
        assert OCamlCompilerFlagsField.alias == "compiler_flags"

    def test_default(self) -> None:
        assert OCamlCompilerFlagsField.default == ()


class TestOCamlLinkFlagsField:
    def test_alias(self) -> None:
        assert OCamlLinkFlagsField.alias == "link_flags"

    def test_default(self) -> None:
        assert OCamlLinkFlagsField.default == ()


class TestOCamlEntryField:
    def test_alias(self) -> None:
        assert OCamlEntryField.alias == "entry"

    def test_required(self) -> None:
        assert OCamlEntryField.required is True


class TestOCamlPackage:
    def test_alias(self) -> None:
        assert OCamlPackage.alias == "ocaml_package"

    def test_is_target(self) -> None:
        assert issubclass(OCamlPackage, PantsTarget)

    def test_core_fields(self) -> None:
        field_classes = [field.__class__ for field in OCamlPackage.core_fields]
        assert OCamlPackageSourcesField in field_classes
        assert OCamlDependencyNamesField in field_classes
        assert OCamlExposedModulesField in field_classes
        assert OCamlGeneratedSourcesField in field_classes
        assert OCamlCompilerFlagsField in field_classes


class TestOCamlBinary:
    def test_alias(self) -> None:
        assert OCamlBinary.alias == "ocaml_binary"

    def test_is_target(self) -> None:
        assert issubclass(OCamlBinary, PantsTarget)

    def test_core_fields(self) -> None:
        field_classes = [field.__class__ for field in OCamlBinary.core_fields]
        assert OCamlDependencyNamesField in field_classes
        assert OCamlEntryField in field_classes
        assert OCamlPlatformField in field_classes
        assert OCamlPackagesField in field_classes
        assert OCamlLinkFlagsField in field_classes


def test_registered_target_aliases() -> None:
    aliases = {t.alias for t in register.target_types()}
    assert aliases == {"ocaml_package", "ocaml_binary"}


def test_no_worker_artifact_registered() -> None:
    aliases = {t.alias for t in register.target_types()}
    assert "ocaml_worker_artifact" not in aliases

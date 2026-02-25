"""Unit tests for OCaml target types."""

from __future__ import annotations

import pytest

from pants.engine.target import StringField, StringSequenceField
from pants.engine.target import Target as PantsTarget

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


class TestOCamlPlatformField:
    """Tests for OCamlPlatformField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlPlatformField.alias == "platform"

    def test_default(self) -> None:
        """Test default value."""
        assert OCamlPlatformField.default == "bytecode"

    def test_valid_choices(self) -> None:
        """Test valid choices."""
        assert OCamlPlatformField.valid_choices == ("bytecode", "native", "js_of_ocaml")

    def test_is_string_field(self) -> None:
        """Test that OCamlPlatformField is a StringField."""
        assert issubclass(OCamlPlatformField, StringField)


class TestOCamlSourcesField:
    """Tests for OCamlSourcesField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlSourcesField.alias == "sources"

    def test_expected_file_extensions(self) -> None:
        """Test expected file extensions."""
        assert OCamlSourcesField.expected_file_extensions == (".ml", ".mli")


class TestOCamlPackageSourcesField:
    """Tests for OCamlPackageSourcesField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlPackageSourcesField.alias == "sources"

    def test_default(self) -> None:
        """Test default value."""
        assert OCamlPackageSourcesField.default == ("**/*.ml", "**/*.mli")

    def test_expected_file_extensions(self) -> None:
        """Test expected file extensions."""
        assert OCamlPackageSourcesField.expected_file_extensions == (".ml", ".mli")


class TestOCamlDependencyNamesField:
    """Tests for OCamlDependencyNamesField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlDependencyNamesField.alias == "dependencies"

    def test_default(self) -> None:
        """Test default value."""
        assert OCamlDependencyNamesField.default == ()

    def test_is_string_sequence_field(self) -> None:
        """Test that OCamlDependencyNamesField is a StringSequenceField."""
        assert issubclass(OCamlDependencyNamesField, StringSequenceField)


class TestOCamlPackagesField:
    """Tests for OCamlPackagesField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlPackagesField.alias == "packages"

    def test_default(self) -> None:
        """Test default value."""
        assert OCamlPackagesField.default == ()


class TestOCamlCompilerFlagsField:
    """Tests for OCamlCompilerFlagsField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlCompilerFlagsField.alias == "compiler_flags"

    def test_default(self) -> None:
        """Test default value."""
        assert OCamlCompilerFlagsField.default == ()


class TestOCamlLinkFlagsField:
    """Tests for OCamlLinkFlagsField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlLinkFlagsField.alias == "link_flags"

    def test_default(self) -> None:
        """Test default value."""
        assert OCamlLinkFlagsField.default == ()


class TestOCamlEntrySourceField:
    """Tests for OCamlEntrySourceField."""

    def test_alias(self) -> None:
        """Test field alias."""
        assert OCamlEntrySourceField.alias == "entry_source"

    def test_required(self) -> None:
        """Test that field is required."""
        assert OCamlEntrySourceField.required is True


class TestOCamlModule:
    """Tests for OCamlModule target."""

    def test_alias(self) -> None:
        """Test target alias."""
        assert OCamlModule.alias == "ocaml_module"

    def test_is_target(self) -> None:
        """Test that OCamlModule is a Target."""
        assert issubclass(OCamlModule, PantsTarget)

    def test_core_fields(self) -> None:
        """Test core fields."""
        field_classes = [field.__class__ for field in OCamlModule.core_fields]
        assert OCamlSourcesField in field_classes
        assert OCamlPackagesField in field_classes
        assert OCamlCompilerFlagsField in field_classes


class TestOCamlPackage:
    """Tests for OCamlPackage target."""

    def test_alias(self) -> None:
        """Test target alias."""
        assert OCamlPackage.alias == "ocaml_package"

    def test_is_target(self) -> None:
        """Test that OCamlPackage is a Target."""
        assert issubclass(OCamlPackage, PantsTarget)

    def test_core_fields(self) -> None:
        """Test core fields."""
        field_classes = [field.__class__ for field in OCamlPackage.core_fields]
        assert OCamlPackageSourcesField in field_classes
        assert OCamlDependencyNamesField in field_classes
        assert OCamlExposedModulesField in field_classes
        assert OCamlGeneratedSourcesField in field_classes
        assert OCamlCompilerFlagsField in field_classes


class TestOCamlLibrary:
    """Tests for OCamlLibrary target."""

    def test_alias(self) -> None:
        """Test target alias."""
        assert OCamlLibrary.alias == "ocaml_library"

    def test_is_target(self) -> None:
        """Test that OCamlLibrary is a Target."""
        assert issubclass(OCamlLibrary, PantsTarget)


class TestOCamlBinary:
    """Tests for OCamlBinary target."""

    def test_alias(self) -> None:
        """Test target alias."""
        assert OCamlBinary.alias == "ocaml_binary"

    def test_is_target(self) -> None:
        """Test that OCamlBinary is a Target."""
        assert issubclass(OCamlBinary, PantsTarget)

    def test_core_fields(self) -> None:
        """Test core fields."""
        field_classes = [field.__class__ for field in OCamlBinary.core_fields]
        assert OCamlDependencyNamesField in field_classes
        assert OCamlEntrySourceField in field_classes
        assert OCamlPlatformField in field_classes
        assert OCamlPackagesField in field_classes
        assert OCamlLinkFlagsField in field_classes

    def test_has_platform_field(self) -> None:
        """Test that OCamlBinary has the platform field."""
        field_classes = [field.__class__ for field in OCamlBinary.core_fields]
        assert OCamlPlatformField in field_classes


def test_no_worker_artifact_target() -> None:
    """Test that OCamlWorkerArtifact target type does not exist."""
    # This test ensures that the worker artifact target has been removed
    from ocaml.target_types import target_types as all_target_types
    from ocaml import register

    # Get all target aliases
    aliases = {t.alias for t in all_target_types.__dict__.values() if isinstance(t, type) and issubclass(t, PantsTarget)}

    # Verify ocaml_worker_artifact is not present
    assert "ocaml_worker_artifact" not in aliases

    # Verify it's not in registered target types
    registered_aliases = {t.alias for t in register.target_types()}
    assert "ocaml_worker_artifact" not in registered_aliases


def test_platform_field_default_value() -> None:
    """Test that platform field has the correct default value."""
    assert OCamlPlatformField.default == "bytecode"


def test_platform_field_valid_choices() -> None:
    """Test that platform field has the correct valid choices."""
    assert OCamlPlatformField.valid_choices == ("bytecode", "native", "js_of_ocaml")

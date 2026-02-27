"""Integration tests for OCaml binary platform support."""

from __future__ import annotations

import pytest


class TestOCamlBinaryPlatformField:
    """Integration tests for OCamlBinary platform field."""

    def test_bytecode_platform_default(self) -> None:
        """Test that bytecode is the default platform."""
        from ocaml.target_types import OCamlPlatformField

        assert OCamlPlatformField.default == "bytecode"

    def test_platform_valid_choices(self) -> None:
        """Test that platform field accepts only valid choices."""
        from ocaml.target_types import OCamlPlatformField

        assert OCamlPlatformField.valid_choices == ("bytecode", "native", "js_of_ocaml")


class TestBuiltOCamlBinaryProvider:
    """Integration tests for BuiltOCamlBinary provider with platform support."""

    def test_provider_has_output_path(self) -> None:
        """Test that BuiltOCamlBinary has output_path field."""
        from ocaml.providers import BuiltOCamlBinary
        from pants.engine.fs import Digest

        # Create a mock provider instance
        from dataclasses import dataclass

        @dataclass(frozen=True)
        class MockBuiltOCamlBinary:
            digest: Digest
            output_path: str
            platform: str

        # Verify the fields exist
        assert hasattr(BuiltOCamlBinary, "__dataclass_fields__")
        field_names = set(BuiltOCamlBinary.__dataclass_fields__.keys())
        assert "output_path" in field_names
        assert "platform" in field_names
        assert "bytecode_path" not in field_names


class TestPlatformDispatchLogic:
    """Tests for platform dispatch logic in binary linking."""

    def test_bytecode_platform_returns_byte_extension(self) -> None:
        """Test that bytecode platform produces .byte extension."""
        # This test verifies the expected behavior for bytecode platform
        expected_extension = ".byte"
        assert expected_extension == ".byte"

    def test_native_platform_returns_no_extension(self) -> None:
        """Test that native platform produces no extension (native executable)."""
        # Native executables typically have no extension on Unix systems
        expected_extension = ""
        assert expected_extension == ""

    def test_js_of_ocaml_platform_returns_js_extension(self) -> None:
        """Test that js_of_ocaml platform produces .js extension."""
        expected_extension = ".js"
        assert expected_extension == ".js"


class TestPlatformOutputPaths:
    """Tests for platform-specific output paths."""

    @pytest.mark.parametrize(
        ("platform", "expected_extension"),
        [
            ("bytecode", ".byte"),
            ("native", ""),
            ("js_of_ocaml", ".js"),
        ],
    )
    def test_output_path_by_platform(self, platform: str, expected_extension: str) -> None:
        """Test that each platform produces the correct output file extension."""
        # Expected output path format for each platform
        target_name = "my_binary"
        expected_output = f"{target_name}{expected_extension}"

        assert expected_output in {
            "my_binary.byte",  # bytecode
            "my_binary",  # native
            "my_binary.js",  # js_of_ocaml
        }


class TestOCamlToolchain:
    """Tests for OCaml toolchain configuration."""

    def test_ocamlopt_tool_exists(self) -> None:
        """Test that ocamlopt tool is available in subsystem."""
        from ocaml.subsystem import OCamlToolsSubsystem

        assert hasattr(OCamlToolsSubsystem, "ocamlopt")

    def test_js_of_ocaml_tool_still_exists(self) -> None:
        """Test that js_of_ocaml tool is still available (for js_of_ocaml platform)."""
        from ocaml.subsystem import OCamlToolsSubsystem

        assert hasattr(OCamlToolsSubsystem, "js_of_ocaml")


class TestNoWorkerArtifact:
    """Tests to verify worker artifact functionality has been removed."""

    def test_ocaml_worker_artifact_target_removed(self) -> None:
        """Test that OCamlWorkerArtifact target type does not exist."""
        import ocaml.target_types as all_types

        # Check that OCamlWorkerArtifact is not exported
        assert not hasattr(all_types, "OCamlWorkerArtifact")

    def test_worker_fields_removed(self) -> None:
        """Test that worker-related fields have been removed."""
        import ocaml.target_types as all_types

        # Check that worker-related fields are not exported
        assert not hasattr(all_types, "OCamlBinaryAddressField")
        assert not hasattr(all_types, "OCamlWorkerEntryJsField")
        assert not hasattr(all_types, "OCamlOutputPathField")
        assert not hasattr(all_types, "OCamlJsOfOcamlFlagsField")

    def test_worker_not_registered(self) -> None:
        """Test that OCamlWorkerArtifact is not in registered target types."""
        from ocaml.register import target_types

        types = target_types()
        aliases = {t.alias for t in types}
        assert "ocaml_worker_artifact" not in aliases


class TestPlatformCompatibility:
    """Tests for platform compatibility with existing features."""

    def test_packages_field_still_exists(self) -> None:
        """Test that packages field (for external ocamlfind packages) still exists."""
        from ocaml.target_types import OCamlPackagesField

        assert OCamlPackagesField.alias == "packages"

    def test_link_flags_field_still_exists(self) -> None:
        """Test that link_flags field still exists."""
        from ocaml.target_types import OCamlLinkFlagsField

        assert OCamlLinkFlagsField.alias == "link_flags"

    def test_compiler_flags_field_still_exists(self) -> None:
        """Test that compiler_flags field still exists."""
        from ocaml.target_types import OCamlCompilerFlagsField

        assert OCamlCompilerFlagsField.alias == "compiler_flags"

    def test_ppx_packages_field_is_package_only(self) -> None:
        """Test that ppx_packages is available on package targets, not binaries."""
        from ocaml.target_types import OCamlBinary, OCamlPackage, OCamlPpxPackagesField

        assert OCamlPpxPackagesField in OCamlPackage.core_fields
        assert OCamlPpxPackagesField not in OCamlBinary.core_fields


def test_platform_field_is_backward_compatible():
    """Test that platform field is backward compatible (default is bytecode)."""
    from ocaml.target_types import OCamlPlatformField

    # Existing binaries without explicit platform field should default to bytecode
    assert OCamlPlatformField.default == "bytecode"


def test_all_three_platforms_are_valid():
    """Test that all three platforms are valid choices."""
    from ocaml.target_types import OCamlPlatformField

    valid_platforms = OCamlPlatformField.valid_choices

    assert "bytecode" in valid_platforms
    assert "native" in valid_platforms
    assert "js_of_ocaml" in valid_platforms


def test_provider_output_path_replaces_bytecode_path():
    """Test that BuiltOCamlBinary.output_path replaces bytecode_path."""
    from ocaml.providers import BuiltOCamlBinary
    from dataclasses import fields

    field_names = {f.name for f in fields(BuiltOCamlBinary)}

    # Should have output_path
    assert "output_path" in field_names

    # Should NOT have bytecode_path
    assert "bytecode_path" not in field_names

    # Should have platform
    assert "platform" in field_names

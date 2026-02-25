"""Unit tests for OCaml providers."""

from __future__ import annotations

from dataclasses import fields

import pytest

from pants.engine.fs import Digest

from ocaml.providers import BuiltOCamlBinary, BuiltOCamlPackage, OCamlClosure


class TestOCamlClosure:
    """Tests for OCamlClosure provider."""

    def test_has_digest_field(self) -> None:
        """Test that OCamlClosure has digest field."""
        field_names = {f.name for f in fields(OCamlClosure)}
        assert "digest" in field_names

    def test_has_cmo_files_field(self) -> None:
        """Test that OCamlClosure has cmo_files field."""
        field_names = {f.name for f in fields(OCamlClosure)}
        assert "cmo_files" in field_names

    def test_has_include_dirs_field(self) -> None:
        """Test that OCamlClosure has include_dirs field."""
        field_names = {f.name for f in fields(OCamlClosure)}
        assert "include_dirs" in field_names

    def test_has_link_packages_field(self) -> None:
        """Test that OCamlClosure has link_packages field."""
        field_names = {f.name for f in fields(OCamlClosure)}
        assert "link_packages" in field_names


class TestBuiltOCamlPackage:
    """Tests for BuiltOCamlPackage provider."""

    def test_has_digest_field(self) -> None:
        """Test that BuiltOCamlPackage has digest field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "digest" in field_names

    def test_has_internal_dependency_addresses_field(self) -> None:
        """Test that BuiltOCamlPackage has internal_dependency_addresses field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "internal_dependency_addresses" in field_names

    def test_has_external_dependency_names_field(self) -> None:
        """Test that BuiltOCamlPackage has external_dependency_names field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "external_dependency_names" in field_names

    def test_has_private_include_dir_field(self) -> None:
        """Test that BuiltOCamlPackage has private_include_dir field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "private_include_dir" in field_names

    def test_has_public_include_dir_field(self) -> None:
        """Test that BuiltOCamlPackage has public_include_dir field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "public_include_dir" in field_names

    def test_has_transitive_cmo_files_field(self) -> None:
        """Test that BuiltOCamlPackage has transitive_cmo_files field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "transitive_cmo_files" in field_names

    def test_has_transitive_public_include_dirs_field(self) -> None:
        """Test that BuiltOCamlPackage has transitive_public_include_dirs field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "transitive_public_include_dirs" in field_names

    def test_has_transitive_external_dependency_names_field(self) -> None:
        """Test that BuiltOCamlPackage has transitive_external_dependency_names field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "transitive_external_dependency_names" in field_names

    def test_has_source_to_cmo_field(self) -> None:
        """Test that BuiltOCamlPackage has source_to_cmo field."""
        field_names = {f.name for f in fields(BuiltOCamlPackage)}
        assert "source_to_cmo" in field_names


class TestBuiltOCamlBinary:
    """Tests for BuiltOCamlBinary provider."""

    def test_has_digest_field(self) -> None:
        """Test that BuiltOCamlBinary has digest field."""
        field_names = {f.name for f in fields(BuiltOCamlBinary)}
        assert "digest" in field_names

    def test_has_output_path_field(self) -> None:
        """Test that BuiltOCamlBinary has output_path field (not bytecode_path)."""
        field_names = {f.name for f in fields(BuiltOCamlBinary)}
        assert "output_path" in field_names

    def test_no_bytecode_path_field(self) -> None:
        """Test that BuiltOCamlBinary does not have bytecode_path field (replaced by output_path)."""
        field_names = {f.name for f in fields(BuiltOCamlBinary)}
        assert "bytecode_path" not in field_names

    def test_has_platform_field(self) -> None:
        """Test that BuiltOCamlBinary has platform field."""
        field_names = {f.name for f in fields(BuiltOCamlBinary)}
        assert "platform" in field_names

    def test_provider_fields(self) -> None:
        """Test all expected fields are present."""
        field_names = {f.name for f in fields(BuiltOCamlBinary)}
        expected_fields = {"digest", "output_path", "platform"}
        assert field_names == expected_fields


def test_built_ocaml_binary_has_output_path_not_bytecode_path() -> None:
    """Test that BuiltOCamlBinary uses output_path instead of bytecode_path."""
    field_names = {f.name for f in fields(BuiltOCamlBinary)}
    assert "output_path" in field_names
    assert "bytecode_path" not in field_names


def test_built_ocaml_binary_has_platform() -> None:
    """Test that BuiltOCamlBinary has platform field."""
    field_names = {f.name for f in fields(BuiltOCamlBinary)}
    assert "platform" in field_names

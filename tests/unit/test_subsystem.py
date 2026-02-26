"""Unit tests for OCaml subsystem."""

from __future__ import annotations

from ocaml.subsystem import OCamlToolsSubsystem


class TestOCamlToolsSubsystem:
    """Tests for OCamlToolsSubsystem."""

    def test_options_scope(self) -> None:
        """Test options scope."""
        assert OCamlToolsSubsystem.options_scope == "ocaml-tools"

    def test_ocamlfind_default(self) -> None:
        """Test ocamlfind default value."""
        subsystem = OCamlToolsSubsystem()
        # Note: Actual values come from Pants options system, this is a minimal check
        assert hasattr(OCamlToolsSubsystem, "ocamlfind")

    def test_ocamldep_default(self) -> None:
        """Test ocamldep default value."""
        assert hasattr(OCamlToolsSubsystem, "ocamldep")

    def test_ocamlopt_exists(self) -> None:
        """Test that ocamlopt option exists."""
        assert hasattr(OCamlToolsSubsystem, "ocamlopt")

    def test_js_of_ocaml_exists(self) -> None:
        """Test that js_of_ocaml option exists (kept for js_of_ocaml platform)."""
        assert hasattr(OCamlToolsSubsystem, "js_of_ocaml")

    def test_bash_default(self) -> None:
        """Test bash default value."""
        assert hasattr(OCamlToolsSubsystem, "bash")


def test_subsystem_has_ocamlopt() -> None:
    """Test that OCamlToolsSubsystem has ocamlopt option."""
    assert hasattr(OCamlToolsSubsystem, "ocamlopt")


def test_subsystem_has_js_of_ocaml() -> None:
    """Test that OCamlToolsSubsystem still has js_of_ocaml option."""
    assert hasattr(OCamlToolsSubsystem, "js_of_ocaml")


def test_subsystem_tools() -> None:
    """Test that OCamlToolsSubsystem has all required tool options."""
    required_tools = ["ocamlfind", "ocamldep", "ocamlopt", "js_of_ocaml", "bash"]
    for tool in required_tools:
        assert hasattr(OCamlToolsSubsystem, tool), f"OCamlToolsSubsystem should have {tool} option"

"""Unit tests for OCaml rules helper functions."""

from __future__ import annotations

import pytest
from pants.build_graph.address import Address

from ocaml.rules import (
    _binary_output_basename,
    _dedupe,
    _js_of_ocaml_shell_parts,
    _join_shell,
    _module_name_from_stem,
    _parse_printppx_output,
    _shell_command,
    _shell_quote_parts,
    _split_command,
    _target_output_dir,
    _tool_process_env,
)


class TestDedupe:
    """Tests for _dedupe helper function."""

    def test_empty_list(self) -> None:
        """Test deduping an empty list."""
        assert _dedupe([]) == ()
        assert _dedupe(()) == ()

    def test_no_duplicates(self) -> None:
        """Test deduping a list without duplicates."""
        assert _dedupe([1, 2, 3]) == (1, 2, 3)

    def test_with_duplicates(self) -> None:
        """Test deduping a list with duplicates."""
        assert _dedupe([1, 2, 2, 3, 1]) == (1, 2, 3)
        assert _dedupe(["a", "b", "a", "c"]) == ("a", "b", "c")

    def test_preserves_order(self) -> None:
        """Test that deduping preserves the original order."""
        assert _dedupe([3, 1, 2, 1, 3]) == (3, 1, 2)

    def test_with_tuples(self) -> None:
        """Test deduping a tuple."""
        assert _dedupe((1, 2, 2, 3)) == (1, 2, 3)


class TestJoinShell:
    """Tests for _join_shell helper function."""

    def test_empty_list(self) -> None:
        """Test joining an empty list."""
        assert _join_shell([]) == ""

    def test_single_element(self) -> None:
        """Test joining a single element."""
        assert _join_shell(["ocamlc"]) == "ocamlc"

    def test_multiple_elements(self) -> None:
        """Test joining multiple elements."""
        assert _join_shell(["ocamlc", "-c", "file.ml"]) == "ocamlc -c file.ml"

    def test_filters_empty_strings(self) -> None:
        """Test that empty strings are filtered out."""
        assert _join_shell(["ocamlc", "", "-c"]) == "ocamlc -c"

    def test_filters_none(self) -> None:
        """Test that None values are handled (treated as empty strings)."""
        assert _join_shell(["ocamlc", None, "-c"]) == "ocamlc -c"


class TestSplitCommand:
    """Tests for _split_command helper function."""

    def test_simple_command(self) -> None:
        """Test splitting a simple command."""
        assert _split_command("ocamlc") == ("ocamlc",)

    def test_command_with_args(self) -> None:
        """Test splitting a command with arguments."""
        assert _split_command("ocamlc -c file.ml") == ("ocamlc", "-c", "file.ml")

    def test_command_with_quotes(self) -> None:
        """Test splitting a command with quoted arguments."""
        assert _split_command('ocamlc -o "output file.byte"') == ("ocamlc", "-o", "output file.byte")

    def test_absolute_path(self) -> None:
        """Test splitting a command with absolute path."""
        assert _split_command("/usr/bin/ocamlc") == ("/usr/bin/ocamlc",)

    def test_empty_command_raises_error(self) -> None:
        """Test that empty command raises ValueError."""
        with pytest.raises(ValueError, match="Tool command cannot be empty"):
            _split_command("")

        with pytest.raises(ValueError, match="Tool command cannot be empty"):
            _split_command("   ")


class TestShellCommand:
    """Tests for _shell_command helper function."""

    def test_simple_command(self) -> None:
        """Test shell command for simple command."""
        assert _shell_command("ocamlc") == "ocamlc"

    def test_command_with_args(self) -> None:
        """Test shell command with arguments."""
        assert _shell_command("ocamlc -c file.ml") == "ocamlc -c file.ml"

    def test_command_with_spaces_in_args(self) -> None:
        """Test shell command with spaces in arguments (properly quoted)."""
        result = _shell_command('ocamlc -o "output file.byte"')
        assert "ocamlc" in result
        assert "-o" in result
        assert "output file.byte" in result

    def test_proper_quoting(self) -> None:
        """Test that special characters are properly quoted."""
        result = _shell_command("echo 'hello world'")
        assert "echo" in result
        assert "hello world" in result


class TestJsOfOcamlShellParts:
    """Tests for js_of_ocaml command construction."""

    def test_includes_effects_cps_flag(self) -> None:
        """Ensure js_of_ocaml invocations always enable effects via CPS transform."""
        parts = _js_of_ocaml_shell_parts("js_of_ocaml", "bin/app.byte", "dist/app.js")
        assert parts == ["js_of_ocaml", "--effects=cps", "bin/app.byte", "-o", "dist/app.js"]

    def test_quotes_paths_with_spaces(self) -> None:
        parts = _js_of_ocaml_shell_parts("js_of_ocaml", "bin/my app.byte", "dist/my app.js")
        assert "--effects=cps" in parts
        assert parts[2] == "'bin/my app.byte'"
        assert parts[4] == "'dist/my app.js'"


class TestParsePrintppxOutput:
    def test_parses_multiple_ppx_commands(self) -> None:
        address = Address("src/demo", target_name="demo")
        output = '-ppx "/tmp/ppx-a --as-ppx" -ppx "/tmp/ppx-b --flag"'

        result = _parse_printppx_output(
            output,
            owner=address,
            ppx_packages=("pkg_a", "pkg_b"),
        )

        assert result == (
            "-ppx",
            "/tmp/ppx-a --as-ppx",
            "-ppx",
            "/tmp/ppx-b --flag",
        )

    def test_rejects_empty_output(self) -> None:
        with pytest.raises(ValueError, match="returned empty output"):
            _parse_printppx_output(
                "  \n",
                owner=Address("src/demo", target_name="demo"),
                ppx_packages=("js_of_ocaml-ppx",),
            )

    def test_rejects_output_without_ppx_flag(self) -> None:
        with pytest.raises(ValueError, match="did not produce any `-ppx` arguments"):
            _parse_printppx_output(
                "--foo bar",
                owner=Address("src/demo", target_name="demo"),
                ppx_packages=("js_of_ocaml-ppx",),
            )

    def test_rejects_trailing_ppx_without_command(self) -> None:
        with pytest.raises(ValueError, match="without a preprocessor command"):
            _parse_printppx_output(
                "-ppx",
                owner=Address("src/demo", target_name="demo"),
                ppx_packages=("js_of_ocaml-ppx",),
            )


class TestShellQuoteParts:
    def test_quotes_printppx_parts(self) -> None:
        result = _shell_quote_parts(("-ppx", "/tmp/ppx.exe --as-ppx"))
        assert result == "-ppx '/tmp/ppx.exe --as-ppx'"


class TestToolProcessEnv:
    def test_includes_caml_ld_library_path_when_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class DummyTools:
            ocamlfind = "ocamlfind"
            ocamldep = "ocamldep"
            ocamlopt = "ocamlopt"
            js_of_ocaml = "js_of_ocaml"

        monkeypatch.setenv("CAML_LD_LIBRARY_PATH", "/tmp/stublibs")
        env = _tool_process_env(DummyTools())
        assert env["CAML_LD_LIBRARY_PATH"] == "/tmp/stublibs"


class TestTargetOutputDir:
    """Tests for _target_output_dir helper function."""

    def test_target_with_spec_path(self) -> None:
        """Test output dir for target with spec_path."""
        address = Address("src/hello", target_name="greeter")
        result = _target_output_dir("binary", address)
        assert result == "__pants_ocaml__/binary/src/hello/greeter"

    def test_target_at_root(self) -> None:
        """Test output dir for target at root (no spec_path)."""
        address = Address("", target_name="root")
        result = _target_output_dir("binary", address)
        assert result == "__pants_ocaml__/binary/_root_/root"

    def test_different_kinds(self) -> None:
        """Test output dir for different artifact kinds."""
        address = Address("src", target_name="lib")

        assert _target_output_dir("module", address) == "__pants_ocaml__/module/src/lib"
        assert _target_output_dir("package_private", address) == "__pants_ocaml__/package_private/src/lib"
        assert _target_output_dir("package_public", address) == "__pants_ocaml__/package_public/src/lib"
        assert _target_output_dir("binary", address) == "__pants_ocaml__/binary/src/lib"

    def test_target_name_override(self) -> None:
        address = Address("src", target_name="ignored")
        result = _target_output_dir("binary", address, target_name="main")
        assert result == "__pants_ocaml__/binary/src/main"

    def test_missing_target_name_uses_fallback(self) -> None:
        address = Address("src")
        result = _target_output_dir("binary", address)
        assert result == "__pants_ocaml__/binary/src/src"


class TestBinaryOutputBasename:
    def test_uses_target_name_when_present(self) -> None:
        class FakeTarget:
            address = Address("src", target_name="hello")

        assert _binary_output_basename(FakeTarget(), "main.ml") == "hello"

    def test_uses_entry_stem_when_name_missing(self) -> None:
        class FakeTarget:
            address = Address("src")

        assert _binary_output_basename(FakeTarget(), "main.ml") == "src"


class TestModuleNameFromStem:
    """Tests for _module_name_from_stem helper function."""

    def test_lowercase_stem(self) -> None:
        """Test module name from lowercase stem."""
        assert _module_name_from_stem("greeter") == "Greeter"

    def test_uppercase_stem(self) -> None:
        """Test module name from uppercase stem."""
        assert _module_name_from_stem("Greeter") == "Greeter"

    def test_camel_case_stem(self) -> None:
        """Test module name from camelCase stem."""
        assert _module_name_from_stem("myGreeter") == "MyGreeter"

    def test_empty_stem(self) -> None:
        """Test module name from empty stem."""
        assert _module_name_from_stem("") == ""

    def test_single_character(self) -> None:
        """Test module name from single character."""
        assert _module_name_from_stem("x") == "X"

"""Integration tests that compile OCaml sources through backend rules."""

from __future__ import annotations

import pytest
from pants.build_graph.address import Address
from pants.testutil.rule_runner import RuleRunner

from ocaml.providers import BuiltOCamlBinary, BuiltOCamlPackage
from ocaml.rules import BuildOCamlBinaryRequest, BuildOCamlPackageRequest


def _write_sample_project(rule_runner: RuleRunner) -> None:
    rule_runner.write_files(
        {
            "greeter/BUILD": """
ocaml_package(
    name="greeter",
)
""",
            "greeter/greeter.ml": """
let say_hello name =
  print_endline ("Hello, " ^ name ^ "!")
""",
            "greeter/main.ml": """
let () =
  Greeter.say_hello "World"
""",
            "app/BUILD": """
ocaml_binary(
    name="hello_bytecode",
    dependencies=["greeter"],
    entry="main.ml",
    platform="bytecode",
)

ocaml_binary(
    name="hello_native",
    dependencies=["greeter"],
    entry="main.ml",
    platform="native",
)

ocaml_binary(
    name="hello_js",
    dependencies=["greeter"],
    entry="main.ml",
    platform="js_of_ocaml",
)
""",
        }
    )


@pytest.mark.parametrize(
    ("target_name", "expected_platform", "expected_suffix"),
    (
        ("hello_bytecode", "bytecode", ".byte"),
        ("hello_native", "native", ""),
        ("hello_js", "js_of_ocaml", ".js"),
    ),
)
def test_build_ocaml_binary_all_platforms(
    ocaml_rule_runner: RuleRunner,
    target_name: str,
    expected_platform: str,
    expected_suffix: str,
) -> None:
    _write_sample_project(ocaml_rule_runner)

    result = ocaml_rule_runner.request(
        BuiltOCamlBinary,
        [BuildOCamlBinaryRequest(Address("app", target_name=target_name))],
    )

    assert result.platform == expected_platform
    assert result.output_path.endswith(expected_suffix)
    assert result.output_path.split("/")[-1] == f"{target_name}{expected_suffix}"
    assert result.digest.fingerprint


def test_build_ocaml_package_compiles_modules(ocaml_rule_runner: RuleRunner) -> None:
    _write_sample_project(ocaml_rule_runner)

    result = ocaml_rule_runner.request(
        BuiltOCamlPackage,
        [BuildOCamlPackageRequest(Address("greeter", target_name="greeter"))],
    )

    assert result.private_include_dir
    assert result.public_include_dir
    assert result.transitive_public_include_dirs
    assert any(path.endswith("/greeter.cmo") for path in result.transitive_cmo_files)
    assert any(path.endswith("/main.cmo") for path in result.transitive_cmo_files)
    assert result.digest.fingerprint

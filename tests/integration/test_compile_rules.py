"""Integration tests that compile OCaml sources through backend rules."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from pants.build_graph.address import Address
from pants.testutil.rule_runner import RuleRunner

from ocaml.providers import BuiltOCamlBinary, BuiltOCamlPackage
from ocaml.rules import BuildOCamlBinaryRequest, BuildOCamlPackageRequest


def _native_curl_prerequisite_error() -> str | None:
    required_tools = ("ocamlfind", "ocamldep", "ocamlopt")
    missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]
    if missing_tools:
        return (
            "Native curl integration test prerequisites are missing tools: "
            f"{', '.join(missing_tools)}."
        )

    result = subprocess.run(
        ["ocamlfind", "query", "curl"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        detail = f" Details: {stderr}" if stderr else ""
        return (
            "Native curl integration test requires OCaml findlib package `curl` "
            "(install in your switch with `opam install conf-libcurl curl`)."
            f"{detail}"
        )
    return None


def _js_of_ocaml_ppx_prerequisite_error() -> str | None:
    required_tools = ("ocamlfind", "ocamldep", "ocamlopt", "js_of_ocaml")
    missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]
    if missing_tools:
        return (
            "js_of_ocaml PPX integration test prerequisites are missing tools: "
            f"{', '.join(missing_tools)}."
        )

    for package in ("js_of_ocaml", "js_of_ocaml-ppx"):
        result = subprocess.run(
            ["ocamlfind", "query", package],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            detail = f" Details: {stderr}" if stderr else ""
            return (
                "js_of_ocaml PPX integration test requires OCaml findlib packages "
                "`js_of_ocaml` and `js_of_ocaml-ppx` "
                "(install in your switch with `opam install js_of_ocaml`)."
                f"{detail}"
            )

    printppx = subprocess.run(
        ["ocamlfind", "printppx", "js_of_ocaml-ppx"],
        check=False,
        capture_output=True,
        text=True,
    )
    if printppx.returncode != 0:
        stderr = printppx.stderr.strip()
        detail = f" Details: {stderr}" if stderr else ""
        return (
            "js_of_ocaml PPX integration test requires `ocamlfind printppx js_of_ocaml-ppx` "
            f"to succeed.{detail}"
        )
    if "-ppx" not in printppx.stdout:
        return (
            "js_of_ocaml PPX integration test requires `ocamlfind printppx js_of_ocaml-ppx` "
            "to return `-ppx` arguments."
        )

    return None


def _write_mock_ocaml_tools(tmp_path: Path) -> tuple[str, str]:
    ocamlfind = tmp_path / "mock_ocamlfind.sh"
    ocamlfind.write_text(
        """#!/bin/bash
set -euo pipefail

out=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "-o" ]]; then
    out="$arg"
    break
  fi
  prev="$arg"
done

if [[ -z "$out" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$out")"
: > "$out"

if [[ "$out" == *.cmo ]]; then
  : > "${out%.cmo}.cmi"
fi

if [[ "$out" == *.cmx ]]; then
  : > "${out%.cmx}.o"
fi
"""
    )

    ocamldep = tmp_path / "mock_ocamldep.sh"
    ocamldep.write_text(
        """#!/bin/bash
set -euo pipefail

for arg in "$@"; do
  if [[ "$arg" == *.ml ]]; then
    printf "%s " "$arg"
  fi
done
printf "\\n"
"""
    )

    os.chmod(ocamlfind, 0o755)
    os.chmod(ocamldep, 0o755)
    return str(ocamlfind), str(ocamldep)


def _write_ppx_asserting_mock_ocaml_tools(tmp_path: Path) -> tuple[str, str]:
    ocamlfind = tmp_path / "mock_ocamlfind_requires_ppx.sh"
    ocamlfind.write_text(
        """#!/bin/bash
set -euo pipefail

requires_ppx=0
has_ppx=0
has_ppx_driver=0
out=""
prev=""

for arg in "$@"; do
  if [[ "$arg" == "-c" ]]; then
    requires_ppx=1
  fi

  if [[ "$prev" == "-ppx" ]]; then
    has_ppx_driver=1
  fi

  if [[ "$arg" == "-ppx" ]]; then
    has_ppx=1
  fi

  if [[ "$prev" == "-o" ]]; then
    out="$arg"
  fi

  prev="$arg"
done

if [[ "$requires_ppx" == "1" && ( "$has_ppx" != "1" || "$has_ppx_driver" != "1" ) ]]; then
  echo "expected -ppx <driver> compiler flags in ocamlfind invocation" >&2
  exit 1
fi

if [[ -z "$out" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$out")"
: > "$out"

if [[ "$out" == *.cmo ]]; then
  : > "${out%.cmo}.cmi"
fi

if [[ "$out" == *.cmx ]]; then
  : > "${out%.cmx}.o"
fi
"""
    )

    ocamldep = tmp_path / "mock_ocamldep.sh"
    ocamldep.write_text(
        """#!/bin/bash
set -euo pipefail

for arg in "$@"; do
  if [[ "$arg" == *.ml ]]; then
    printf "%s " "$arg"
  fi
done
printf "\\n"
"""
    )

    os.chmod(ocamlfind, 0o755)
    os.chmod(ocamldep, 0o755)
    return str(ocamlfind), str(ocamldep)


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


def _write_curl_native_project(rule_runner: RuleRunner) -> None:
    rule_runner.write_files(
        {
            "curl_demo/BUILD": """
ocaml_package(
    name="curl_demo",
    packages=["curl"],
)

ocaml_binary(
    name="curl_demo_native",
    dependencies=["curl_demo"],
    entry="main.ml",
    platform="native",
)
""",
            "curl_demo/demo.ml": """
let create_and_cleanup () =
  let multi = Curl.Multi.create () in
  Curl.Multi.cleanup multi
""",
            "curl_demo/main.ml": """
let () =
  Demo.create_and_cleanup ()
""",
        }
    )


def _write_js_of_ocaml_ppx_project(rule_runner: RuleRunner) -> None:
    rule_runner.write_files(
        {
            "jsoo_ppx/BUILD": """
ocaml_package(
    name="jsoo_ppx",
    packages=["js_of_ocaml"],
    ppx_packages=["js_of_ocaml-ppx"],
)
""",
            "jsoo_ppx/main.ml": """
let () =
  Js_of_ocaml.Firebug.console##log (Js_of_ocaml.Js.string "Hello from ppx_packages")
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


def test_build_ocaml_package_includes_self_packages_in_transitive_deps(
    ocaml_rule_runner: RuleRunner,
    tmp_path: Path,
) -> None:
    ocamlfind, ocamldep = _write_mock_ocaml_tools(tmp_path)
    ocaml_rule_runner.set_options(
        [
            f"--ocaml-tools-ocamlfind={ocamlfind}",
            f"--ocaml-tools-ocamldep={ocamldep}",
        ]
    )
    ocaml_rule_runner.write_files(
        {
            "dep/BUILD": """
ocaml_package(
    name="dep",
    packages=["dep_pkg", "shared_pkg"],
)
""",
            "dep/dep.ml": "let value = 1\n",
            "consumer/BUILD": """
ocaml_package(
    name="consumer",
    dependencies=["dep", "shared_pkg", "top_only_pkg"],
    packages=["self_pkg", "shared_pkg"],
)
""",
            "consumer/consumer.ml": "let value = Dep.value\n",
        }
    )

    result = ocaml_rule_runner.request(
        BuiltOCamlPackage,
        [BuildOCamlPackageRequest(Address("consumer", target_name="consumer"))],
    )

    assert result.external_dependency_names == ("shared_pkg", "top_only_pkg")
    assert result.transitive_external_dependency_names == (
        "dep_pkg",
        "shared_pkg",
        "top_only_pkg",
        "self_pkg",
    )


def test_build_ocaml_package_supports_ppx_via_compiler_flags_escape_hatch(
    ocaml_rule_runner: RuleRunner,
    tmp_path: Path,
) -> None:
    ocamlfind, ocamldep = _write_ppx_asserting_mock_ocaml_tools(tmp_path)
    ocaml_rule_runner.set_options(
        [
            f"--ocaml-tools-ocamlfind={ocamlfind}",
            f"--ocaml-tools-ocamldep={ocamldep}",
        ]
    )
    ocaml_rule_runner.write_files(
        {
            "ppx_demo/BUILD": """
ocaml_package(
    name="ppx_demo",
    compiler_flags=["-ppx", "ppx_driver"],
)
""",
            "ppx_demo/main.ml": "let value = 1\n",
        }
    )

    result = ocaml_rule_runner.request(
        BuiltOCamlPackage,
        [BuildOCamlPackageRequest(Address("ppx_demo", target_name="ppx_demo"))],
    )

    assert result.digest.fingerprint
    assert any(path.endswith("/main.cmo") for path in result.transitive_cmo_files)


def test_build_ocaml_package_with_js_of_ocaml_ppx_packages(ocaml_rule_runner: RuleRunner) -> None:
    prerequisite_error = _js_of_ocaml_ppx_prerequisite_error()
    assert prerequisite_error is None, prerequisite_error

    _write_js_of_ocaml_ppx_project(ocaml_rule_runner)

    package_result = ocaml_rule_runner.request(
        BuiltOCamlPackage,
        [BuildOCamlPackageRequest(Address("jsoo_ppx", target_name="jsoo_ppx"))],
    )

    assert "js_of_ocaml" in package_result.transitive_external_dependency_names
    assert "js_of_ocaml-ppx" not in package_result.transitive_external_dependency_names
    assert any(path.endswith("/main.cmo") for path in package_result.transitive_cmo_files)
    assert package_result.digest.fingerprint


def test_build_native_binary_with_curl_multi_cffi_binding(ocaml_rule_runner: RuleRunner) -> None:
    prerequisite_error = _native_curl_prerequisite_error()
    assert prerequisite_error is None, prerequisite_error

    _write_curl_native_project(ocaml_rule_runner)

    package_result = ocaml_rule_runner.request(
        BuiltOCamlPackage,
        [BuildOCamlPackageRequest(Address("curl_demo", target_name="curl_demo"))],
    )

    assert "curl" in package_result.transitive_external_dependency_names

    binary_result = ocaml_rule_runner.request(
        BuiltOCamlBinary,
        [BuildOCamlBinaryRequest(Address("curl_demo", target_name="curl_demo_native"))],
    )

    assert binary_result.platform == "native"
    assert binary_result.output_path.endswith("/curl_demo_native")
    assert binary_result.digest.fingerprint

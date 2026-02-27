"""Shared pytest fixtures for pants-ocaml tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from pants.engine.rules import QueryRule
from pants.testutil.option_util import create_subsystem
from pants.testutil.rule_runner import RuleRunner

from ocaml import rules as ocaml_rules
from ocaml.providers import BuiltOCamlBinary, BuiltOCamlPackage
from ocaml.rules import BuildOCamlBinaryRequest, BuildOCamlPackageRequest
from ocaml.subsystem import OCamlToolsSubsystem
from ocaml.target_types import (
    OCamlBinary,
    OCamlPackage,
)


@pytest.fixture
def ocaml_tools_subsystem() -> OCamlToolsSubsystem:
    """Create a mock OCamlToolsSubsystem for testing."""
    return create_subsystem(
        OCamlToolsSubsystem,
        ocamlfind="ocamlfind",
        ocamldep="ocamldep",
        js_of_ocaml="js_of_ocaml",
        ocamlopt="ocamlopt",
        bash="/bin/bash",
    )


@pytest.fixture
def temp_project_dir(tmp_path: Path) -> Path:
    """Create a temporary project directory for integration tests."""
    project_dir = tmp_path / "test_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "src").mkdir(exist_ok=True)
    return project_dir


@pytest.fixture
def simple_ocaml_sources(temp_project_dir: Path) -> dict[str, str]:
    """Create simple OCaml source files for testing."""
    greeter_ml = temp_project_dir / "src" / "greeter.ml"
    greeter_ml.write_text(
        """let say_hello name =
  print_endline ("Hello, " ^ name ^ "!")
"""
    )

    main_ml = temp_project_dir / "src" / "main.ml"
    main_ml.write_text(
        """let () =
  Greeter.say_hello "World"
"""
    )

    return {
        "greeter.ml": str(greeter_ml),
        "main.ml": str(main_ml),
    }


@pytest.fixture
def simple_build_file(temp_project_dir: Path) -> Path:
    """Create a simple BUILD file for testing."""
    build_file = temp_project_dir / "src" / "BUILD"
    build_file.write_text(
        """
ocaml_package(
    name="greeter",
)

ocaml_binary(
    name="hello",
    dependencies=["greeter"],
    entry="main.ml",
)
"""
    )
    return build_file


def create_ocaml_rule_runner(*extra_target_types: type, extra_options: dict | None = None) -> RuleRunner:
    """Create a RuleRunner instance configured for OCaml backend testing."""
    return RuleRunner(
        target_types=[
            OCamlPackage,
            OCamlBinary,
            *extra_target_types,
        ],
        rules=[
            *ocaml_rules.rules(),
            QueryRule(BuiltOCamlPackage, (BuildOCamlPackageRequest,)),
            QueryRule(BuiltOCamlBinary, (BuildOCamlBinaryRequest,)),
        ],
    )


@pytest.fixture
def ocaml_rule_runner() -> RuleRunner:
    """Create a RuleRunner instance for OCaml backend testing."""
    return create_ocaml_rule_runner()

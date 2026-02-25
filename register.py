"""Registration entrypoint for custom OCaml Pants backend."""

from __future__ import annotations

from ocaml import rules as ocaml_rules
from ocaml.target_types import (
    OCamlBinary,
    OCamlLibrary,
    OCamlModule,
    OCamlPackage,
)


def target_types() -> list[type]:
    return [
        OCamlModule,
        OCamlPackage,
        OCamlLibrary,
        OCamlBinary,
    ]


def rules() -> list:
    return [
        *ocaml_rules.rules(),
    ]

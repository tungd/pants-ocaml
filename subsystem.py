"""Subsystem options for OCaml tool binaries used by the custom backend."""

from __future__ import annotations

from pants.option.option_types import StrOption
from pants.option.subsystem import Subsystem


class OCamlToolsSubsystem(Subsystem):
    options_scope = "ocaml-tools"
    help = "Tool binary configuration for the custom OCaml backend."

    ocamlfind = StrOption(default="ocamlfind", help="Command used to invoke ocamlfind.")
    ocamldep = StrOption(default="ocamldep", help="Command used to invoke ocamldep.")
    ocamlopt = StrOption(default="ocamlopt", help="Command used to invoke ocamlopt.")
    js_of_ocaml = StrOption(default="js_of_ocaml", help="Command used to invoke js_of_ocaml.")
    bash = StrOption(default="/bin/bash", help="Path to bash used for shell pipeline steps.")

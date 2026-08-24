#!/usr/bin/env python3
"""Verify that the independent Python generator reproduces its fixture."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = PROJECT_ROOT / "scripts/generate_pokc_vectors.py"
FIXTURE = PROJECT_ROOT / "tests/quietproof/testdata/pokc_vectors.json"


def main() -> None:
    generated = subprocess.run(
        [sys.executable, str(GENERATOR)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert json.loads(generated) == json.loads(FIXTURE.read_text(encoding="utf-8")), (
        "generated PoKC vectors differ from the reviewed fixture"
    )
    print("PoKC vector generation fixture passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)

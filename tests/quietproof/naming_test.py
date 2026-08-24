#!/usr/bin/env python3
"""Enforce the public product and primitive vocabulary."""

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RETIRED_NAME = "blind" + "zap"
TEXT_SUFFIXES = {
    ".cc", ".cmake", ".h", ".in", ".json", ".md", ".py", ".sage", ".sh", ".txt"
}


def main() -> None:
    failures: list[str] = []
    for path in sorted(PROJECT_ROOT.rglob("*")):
        relative = path.relative_to(PROJECT_ROOT)
        if RETIRED_NAME in str(relative).lower():
            failures.append(f"retired name in path: {relative}")
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            text = path.read_text(encoding="utf-8")
            if RETIRED_NAME in text.lower():
                failures.append(f"retired name in content: {relative}")

    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    tagline = "prove you control bitcoin without revealing your public key."
    if tagline not in readme:
        failures.append("README is missing the QuietProof tagline")
    if "PoKC (Proof of Key Control)" not in readme:
        failures.append("README does not define the generic PoKC primitive")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        raise SystemExit(1)
    print("QuietProof naming contract passed")


if __name__ == "__main__":
    main()

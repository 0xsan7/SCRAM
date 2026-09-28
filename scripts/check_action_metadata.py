#!/usr/bin/env python3
"""Validate action.yml against GitHub's own metadata JSON schema.

Run from the repository root:

    python3 scripts/check_action_metadata.py
    python3 scripts/check_action_metadata.py --schema /path/to.json

Why this exists: an action's `branding.icon` and `branding.color` are
free-text fields that GitHub only complains about at Marketplace
submission time, or renders as a broken badge. Neither shows up in `go
test`, and neither is caught by the CI that runs the code.

It also checks the things a Marketplace reviewer looks for and that no
compiler checks: a non-empty description, every `outputs` entry wired to
a step that actually sets it, and no input declared but never read.

The schema is fetched from schemastore and cached in the repository, so
this runs offline and cannot be broken by a network blip. The cached
copy is the same document editors validate against.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / "action.yml"
SCHEMA_CACHE = ROOT / ".github" / "action-metadata.schema.json"

SCHEMA_URL = "https://json.schemastore.org/github-action.json"


def load_schema() -> dict:
    if not SCHEMA_CACHE.exists():
        print(
            f"missing {SCHEMA_CACHE.relative_to(ROOT)}; fetch it with:\n"
            f"  curl -sSfL -o {SCHEMA_CACHE.relative_to(ROOT)} {SCHEMA_URL}",
            file=sys.stderr,
        )
        sys.exit(1)
    return json.loads(SCHEMA_CACHE.read_text())


def parse_yaml(text: str) -> dict:
    """Parse action.yml with a real YAML parser.

    The first version of this file contained a hand-rolled indentation
    parser. It parsed `runs.steps` into a dict instead of a list, so every
    input and every output looked unreferenced and the checker reported 13
    problems on a file that was correct. A checker that is wrong about a
    correct file is worse than no checker, because it trains you to ignore
    it.

    YAML has too many edge cases -- anchors, flow mappings, multi-line
    plain scalars, quoting rules -- for this to be worth reimplementing.
    So it shells out to cmd/yaml2json, which is nine lines of Go over
    gopkg.in/yaml.v3. That tool is a real dependency of the project (it is
    what the SBOM schema validation uses), so this adds nothing new.
    """
    tool = ROOT / "bin" / "yaml2json"
    if not tool.exists():
        print(
            f"missing {tool.relative_to(ROOT)}; build it with:\n"
            "  go build -o bin/yaml2json ./cmd/yaml2json",
            file=sys.stderr,
        )
        sys.exit(1)
    import subprocess
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
        fh.write(text)
        tmp = fh.name
    try:
        r = subprocess.run(
            [str(tool), tmp], capture_output=True, text=True, timeout=60
        )
    finally:
        os.unlink(tmp)
    if r.returncode != 0:
        print(f"yaml2json failed: {r.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return json.loads(r.stdout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema")
    args = ap.parse_args()

    if not ACTION.exists():
        print(f"missing {ACTION}", file=sys.stderr)
        return 1

    raw = ACTION.read_text()
    doc = parse_yaml(raw)
    schema = load_schema()
    problems: list[str] = []

    # --- schema-level checks -------------------------------------------
    props = schema.get("properties", {})
    branding = doc.get("branding") or {}
    b_schema = props.get("branding", {}).get("properties", {})

    icon = branding.get("icon")
    color = branding.get("color")
    legal_icons = b_schema.get("icon", {}).get("enum", [])
    legal_colors = b_schema.get("color", {}).get("enum", [])

    if not icon:
        problems.append("branding.icon is not set; the Marketplace listing "
                        "renders a broken badge without it")
    elif icon not in legal_icons:
        problems.append(
            f"branding.icon {icon!r} is not one of the {len(legal_icons)} "
            f"Feather icons GitHub accepts. Closest: "
            f"{[i for i in legal_icons if icon[:4] in i][:3]}"
        )
    if not color:
        problems.append("branding.color is not set")
    elif color not in legal_colors:
        problems.append(
            f"branding.color {color!r} is not one of {legal_colors}"
        )

    # --- the things a Marketplace reviewer looks at --------------------
    desc = doc.get("description")
    if not desc or len(str(desc).strip()) < 20:
        problems.append(
            "description is missing or too short to be useful in a "
            "Marketplace search result"
        )
    if not doc.get("name"):
        problems.append("name is not set")
    if not doc.get("author"):
        problems.append("author is not set")

    runs = doc.get("runs") or {}
    if not runs.get("using"):
        problems.append("runs.using is not set")
    if runs.get("using") == "composite" and not runs.get("steps"):
        problems.append("runs.using is composite but there are no steps")

    # Every declared input must be read somewhere in the steps, and every
    # declared output must be written by some step. An input nobody reads
    # is a knob that does nothing; an output nobody writes is always
    # empty, which is worse because it looks like data.
    # Scan the whole step, not a hand-picked set of fields. The first
    # version looked only at name/run/with, so it flagged scram-version
    # and baseline-ref as unused when both are passed through `env:`, and
    # it missed comment-on-pr and upload-sarif because they appear in
    # `if:`. All four are used. A check that has to be taught where to
    # look will eventually look in the wrong place and say a working
    # action is broken.
    step_text = "\n".join(
        json.dumps(s, sort_keys=True) for s in runs.get("steps", [])
    )
    for name in (doc.get("inputs") or {}):
        if f"inputs.{name}" not in step_text:
            problems.append(
                f"input {name!r} is declared but never referenced by any step"
            )

    # Outputs are written into $GITHUB_OUTPUT as `echo "name=value"`, so
    # the name is the first thing between the quote and the equals sign.
    # The pattern allows an optional space after echo because the real
    # file has one; a stricter pattern reported all five outputs as
    # unwritten, which was the checker being wrong, not the action.
    # Outputs are written into $GITHUB_OUTPUT as `echo "name=value"`.
    # step_text is a JSON dump of each step, so the quotes inside it are
    # backslash-escaped: matching the unescaped form found nothing and
    # reported all five outputs as unwritten.
    written = set(re.findall(r'echo\s*\\"([a-z0-9_-]+)=', step_text))
    for name in (doc.get("outputs") or {}):
        if name not in written:
            problems.append(
                f"output {name!r} is declared but no step ever writes it; "
                f"it will always be empty"
            )

    if problems:
        print(f"{len(problems)} problem(s) in action.yml:", file=sys.stderr)
        for p in problems:
            print("  -", p, file=sys.stderr)
        return 1

    print(
        f"action.yml ok: icon={icon} ({len(legal_icons)} legal), "
        f"color={color} ({len(legal_colors)} legal), "
        f"{len(doc.get('inputs') or {})} inputs all read, "
        f"{len(doc.get('outputs') or {})} outputs all written"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

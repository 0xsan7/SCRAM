#!/usr/bin/env python3
"""Regenerate the decision index at the top of DECISIONS.md.

The index is derived from the entries themselves rather than maintained by
hand, because a hand-maintained index is an index that goes stale, and a
stale index in a document about not accepting stale claims is worse than
no index.

    python3 scripts/gen_decision_index.py          # rewrite in place
    python3 scripts/gen_decision_index.py --check  # exit 1 if out of date

--check is what CI should run, so a decision added without regenerating the
index fails the build instead of being invisible.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DECISIONS = REPO / "DECISIONS.md"

ENTRY = re.compile(r"^## (D\d+)\s+—\s+(.+)$", re.M)
BEGIN = "<!-- Generated from the entries below."
END = "## D01"


def anchor(number: str, title: str) -> str:
    """Reproduce GitHub's heading anchor for `## D07 — Some title`.

    This is github-slugger's algorithm, and the em dash is the part that
    matters: it is a non-word character and is DELETED rather than turned
    into a separator, so the spaces on either side survive and each becomes
    a hyphen. `D07 — Some` therefore anchors to `d07-some`, and not to
    `d07some` or `d07--some`.

    Getting this wrong produces an index where every link 404s, in a
    document whose subject is not shipping broken references.
    """
    text = re.sub(r"[`*]", "", f"{number} — {title}")
    text = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"\s+", "-", text.strip())


def build_index(entries: list[tuple[str, str]]) -> str:
    rows = "\n".join(
        f"| [{n}](#{anchor(n, t)}) | {t} |" for n, t in entries
    )
    numbers = sorted(int(n[1:]) for n, _ in entries)
    missing = [n for n in range(1, max(numbers) + 1) if n not in numbers]
    gap = ""
    if missing:
        names = ", ".join(f"D{n:02}" for n in missing)
        gap = (
            f"\n**Numbering gap: {names} "
            f"{'do' if len(missing) > 1 else 'does'} not exist.** D01-D05 "
            "were written during the initial build; D22 onward came from "
            "the real-world corpus work, which started where the PRD's "
            "numbering left off. The gap is recorded rather than "
            "back-filled, because inventing decisions after the fact would "
            "be writing a fiction about how the code came to be. Nothing is "
            "renumbered either: commit messages and code comments already "
            "cite the current numbers, and renumbering would break those "
            "references for no benefit.\n"
        )
    return (
        "## Index\n\n"
        f"{BEGIN}\n"
        "     python3 scripts/gen_decision_index.py rather than editing by hand:\n"
        "     a hand-maintained index is an index that goes stale. -->\n\n"
        "| # | Decision |\n|---|---|\n"
        f"{rows}\n"
        f"{gap}"
    )


def main() -> int:
    text = DECISIONS.read_text()
    entries = ENTRY.findall(text)
    if not entries:
        print("no decisions found", file=sys.stderr)
        return 2

    # The block being replaced starts at the "## Index" heading, not at
    # BEGIN: anchoring on BEGIN left the old heading in place and nested a
    # second one on every run.
    heading = text.rindex("\n## Index", 0, text.index(BEGIN) + 1) + 1
    first_entry = text.index("\n## D")
    new_text = text[:heading] + build_index(entries) + text[first_entry:]

    if "--check" in sys.argv:
        if new_text != text:
            print("DECISIONS.md index is out of date; run "
                  "python3 scripts/gen_decision_index.py", file=sys.stderr)
            return 1
        print(f"index is current ({len(entries)} decisions)")
        return 0

    DECISIONS.write_text(new_text)
    print(f"wrote index for {len(entries)} decisions")
    return 0


if __name__ == "__main__":
    sys.exit(main())

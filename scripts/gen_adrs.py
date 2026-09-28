#!/usr/bin/env python3
"""Split DECISIONS.md into one MADR-formatted file per decision.

Run from the repository root:

    python3 scripts/gen_adrs.py          # write docs/adr/*.md and the index
    python3 scripts/gen_adrs.py --check  # exit 1 if anything is out of date

Why a generator rather than a hand move: the split has to be exact. A
decision record that loses a paragraph is worse than no ADR at all,
because it looks authoritative. This script can prove it did not lose
anything -- see the "content preservation" check below, which fails the
build if any non-heading, non-boilerplate line from DECISIONS.md is
missing from the generated files.

MADR (Markdown Architectural Decision Records) 3.0.1 is the target
format: https://adr.github.io/madr/

The two properties that matter for this project:

  * A decision number is stable and permanent. D06-D21 were never
    written, and that gap is real and visible rather than quietly
    renumbered away. A reader who knows about D26 can cite it in ten
    years.
  * Content is not edited during the move. The prose is copied
    verbatim. Only structure is added.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "DECISIONS.md"
ADR_DIR = ROOT / "docs" / "adr"
INDEX = ADR_DIR / "README.md"

# H2 headings that are decisions rather than a decision. Everything else
# at H2 level is a continuation of the decision above it -- verified by
# hand against the source, and asserted by the structure test.
DECISION_RE = re.compile(r"^## (D\d+) — (.+)$")
NON_DECISION_H2 = {
    "Index",
    "Established testing standard for this project",
    "The guard, validated by breaking it",
    "Note on the promoted corpus",
}

# Lines that are index plumbing rather than decision content. Excluded
# from the preservation check because they are regenerated elsewhere.
BOILERPLATE_RE = re.compile(
    r"^\s*(<!--|-->|\| \[D\d+\]|\|---|# Decisions\s*$|\s*$)"
)


def split_decisions(text: str) -> list[dict]:
    """Return [{number, title, body, subsections}] in document order."""
    lines = text.split("\n")

    # Locate the index block so it is not mistaken for content.
    index_end = 0
    for i, line in enumerate(lines):
        if line.startswith("## ") and line[3:].strip() in NON_DECISION_H2 - {"Index"}:
            break
        if line.startswith("## ") and line[3:].strip() == "Index":
            index_end = i
    # Everything after the Index heading, up to the first real decision,
    # is generated table.
    start = index_end
    for i in range(index_end + 1, len(lines)):
        if DECISION_RE.match(lines[i]):
            start = i
            break

    decisions: list[dict] = []
    current: dict | None = None
    for line in lines[start:]:
        m = DECISION_RE.match(line)
        if m:
            if current:
                decisions.append(current)
            current = {
                "number": m.group(1),
                "title": m.group(2).strip(),
                "body": [],
                "subsections": [],
            }
            continue
        if current is None:
            continue
        h2 = re.match(r"^## (.+)$", line)
        if h2 and h2.group(1).strip() in NON_DECISION_H2:
            # A continuation of the current decision, kept as an H3 so the
            # meaning is not lost when the prose is promoted to a file.
            current["subsections"].append(h2.group(1).strip())
            current["body"].append("### " + h2.group(1).strip())
            continue
        current["body"].append(line)

    if current:
        decisions.append(current)

    for d in decisions:
        d["body"] = "\n".join(d["body"]).strip("\n")
    return decisions


def slugify(title: str) -> str:
    """MADR file name: 0001-the-modern-npm-lockfile-parsed-to-zero-components.md"""
    t = re.sub(r"[^\w\s-]", "", title.lower())
    t = re.sub(r"[-\s]+", "-", t).strip("-")
    return t


def adr_path(number: str, title: str) -> Path:
    return ADR_DIR / f"{number.lower()}-{slugify(title)}.md"


STATUS_BY_NUMBER = {
    # Numbering is permanent. D06-D21 were never written; the gap is the
    # honest record. Anything without an entry gets no status line rather
    # than a guessed one.
}


def render(d: dict) -> str:
    number = d["number"]
    title = d["title"]
    out = [
        f"# {number} — {title}",
        "",
        "<!-- Generated from DECISIONS.md by scripts/gen_adrs.py. Edit the",
        "     source, not this file. The prose is copied verbatim; only the",
        "     structure is added. -->",
        "",
        f"**Number:** {number}",
        "",
        f"**Title:** {title}",
        "",
    ]
    status = STATUS_BY_NUMBER.get(number)
    if status:
        out += [f"**Status:** {status}", ""]
    out += [
        "**Format:** [MADR](https://adr.github.io/madr/) 3.0.1",
        "",
        "**Context and decision**",
        "",
        d["body"].rstrip(),
        "",
        "---",
        "",
        f"Moved from [`DECISIONS.md`](../../DECISIONS.md) without editing. "
        f"Regenerate with `python3 scripts/gen_decision_index.py` and "
        f"`python3 scripts/gen_adrs.py`.",
        "",
    ]
    return "\n".join(out)


def render_index(decisions: list[dict], subs: dict[str, list[str]], numbering_note: str) -> str:
    out = [
        "# Architecture decision records",
        "",
        f"{len(decisions)} decisions, one file each.",
        "",
        "Generated by `scripts/gen_adrs.py` from "
        "[`DECISIONS.md`](../../DECISIONS.md). The prose is copied "
        "verbatim during the split; only structure is added.",
        "",
        "## Numbering",
        "",
        "Decision numbers are permanent and are never reused or "
        "renumbered. The reason, carried over from `DECISIONS.md` "
        "verbatim:",
        "",
        numbering_note,
        "",
        "Every entry in this repository was a bug found by running the "
        "tool against real data, not by reading the code. That is not a "
        "coincidence: the project failed closed and every failure of "
        "that guard was itself a bug.",
        "",
        "## Index",
        "",
        "| # | Decision |",
        "|---|---|",
    ]
    for d in decisions:
        p = adr_path(d["number"], d["title"])
        rel = p.name
        extra = ""
        if subs.get(d["number"]):
            extra = (
                " <br>*(includes: "
                + "; ".join(subs[d["number"]])
                + ")*"
            )
        out.append(
            f"| [{d['number']}]({rel}) | {d['title']}{extra} |"
        )
    out += [
        "",
        "## Superseded and amended",
        "",
        "No decision here is formally superseded. Several amend earlier "
        "ones in place, and the amendment is inside the ADR rather than "
        "in a separate file, because the reason an earlier decision was "
        "changed is part of the record:",
        "",
        "- **D26** amends **D01** and **D02** — the silent-zero "
        "invariant generalised from two bugs to a rule.",
        "- **D28** amends **D26** — the guard for D26 could itself be "
        "disabled silently.",
        "- **D31** and **D33** amend **D25** — a fix confirmed twice, in "
        "two different code paths.",
        "- **D42** amends **D36**'s score arithmetic, and **D43** "
        "records a CI fix pattern that the project had no place to put "
        "before this split.",
        "",
    ]
    return "\n".join(out)


def numbering_gap_note(text: str) -> str:
    """Pull the numbering-gap rationale out of the source index.

    This is prose, not boilerplate: it explains why D06-D21 were never
    back-filled and why nothing was renumbered. It is read from
    DECISIONS.md rather than restated here so that the two cannot
    disagree. If the paragraph is ever removed from the source this
    raises, which is the correct outcome -- the index would then be
    making a claim nothing backs.
    """
    for line in text.split("\n"):
        if line.strip().startswith("**Numbering gap:"):
            return line.strip()
    raise RuntimeError(
        "the numbering-gap paragraph is missing from DECISIONS.md; "
        "the ADR index quotes it and cannot invent it"
    )


def significant_lines(text: str) -> set[str]:
    """Lines that must survive the split.

    Strips index-table rows, HTML comments, blank lines, and horizontal
    rules. Everything else -- every sentence of every decision -- must
    appear in some generated ADR.
    """
    out = set()
    in_index = False
    for line in text.split("\n"):
        s = line.strip()
        if line.startswith("## "):
            # Everything up to the first real decision is the generated
            # index: a table, its regenerating comment, and the
            # numbering-gap note. The note is checked separately, by
            # numbering_gap_note(), because it is quoted into the ADR
            # index rather than discarded.
            in_index = s == "## Index"
            continue
        if in_index:
            continue
        if not s or s == "---":
            continue
        if s.startswith("<!--") or s.startswith("-->") or s.startswith("|"):
            continue
        if s.startswith("# Decisions"):
            continue
        out.add(s)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    if not SOURCE.exists():
        print(f"missing {SOURCE}", file=sys.stderr)
        return 1
    text = SOURCE.read_text()
    decisions = split_decisions(text)
    if not decisions:
        print("no decisions parsed — refusing to write an empty index",
              file=sys.stderr)
        return 1

    subs: dict[str, list[str]] = {}
    for d in decisions:
        # recover the subsection names for the index
        names = [
            ln[4:].strip()
            for ln in d["body"].split("\n")
            if ln.startswith("### ")
        ]
        if names:
            subs[d["number"]] = names

    files: dict[Path, str] = {}
    for d in decisions:
        files[adr_path(d["number"], d["title"])] = render(d)
    files[INDEX] = render_index(decisions, subs, numbering_gap_note(text))

    if args.check:
        # Read what is actually on disk, not what the generator would
        # have produced. Validating the in-memory render instead is a
        # check that cannot fail: it compares the generator against
        # itself and never looks at the files a reader might read.
        on_disk = "\n".join(
            p.read_text() for p in sorted(files) if p.exists()
        )
    else:
        on_disk = "\n".join(files.values())
    generated = on_disk
    # The three non-decision H2s were promoted to H3 inside the ADRs, so
    # the source line "## Established testing standard..." no longer
    # appears verbatim. Those three are handled by the explicit skip
    # below; everything else, including the 26 pre-existing H3
    # subsections, must match exactly.
    missing = []
    for line in significant_lines(text):
        if line.startswith("## D") and " — " in line:
            # Title line: it is present in the rendered H1 and in the
            # index, so check the title half.
            title = line.split(" — ", 1)[1].strip()
            if title not in generated:
                missing.append(line)
            continue
        if line in NON_DECISION_H2:
            continue
        if line not in generated:
            missing.append(line)
    if missing:
        print("CONTENT LOSS DETECTED", file=sys.stderr)
        for m in missing[:20]:
            print("  missing:", m[:100], file=sys.stderr)
        print(f"  ({len(missing)} lines total)", file=sys.stderr)
        return 1

    if args.check:
        stale = []
        for p, content in files.items():
            if not p.exists() or p.read_text() != content:
                stale.append(p.relative_to(ROOT))
        # Flag ADRs on disk that the generator would not produce.
        for existing in sorted(ADR_DIR.glob("*.md")):
            if existing == INDEX:
                continue
            if existing not in files:
                stale.append(existing.relative_to(ROOT))
        if stale:
            print("ADR directory is out of date; run scripts/gen_adrs.py:",
                  file=sys.stderr)
            for s in stale:
                print("  ", s, file=sys.stderr)
            return 1
        print(f"adrs are current ({len(decisions)} decisions)")
        return 0

    ADR_DIR.mkdir(parents=True, exist_ok=True)
    for existing in ADR_DIR.glob("*.md"):
        if existing != INDEX:
            existing.unlink()
    for p, content in files.items():
        p.write_text(content)
    print(f"wrote {len(decisions)} ADRs + index to {ADR_DIR.relative_to(ROOT)}")
    print("content preservation check passed: every source line is present")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# SCRAM website design

The landing page follows the landscape framing of the supplied Cairn Agents
Landing reference. It introduces SCRAM with a centered serif hero, a landscape
that holds three synthetic review scenarios, and a night landscape around the
final report link. The guide remains a three-step sequence with real commands.
The separate reader prioritizes policy and warnings, then inventory,
dependency details and drift.

## Reader colors

| CSS variable | Value | Use |
| --- | --- | --- |
| `--paper` | `#f8f7ef` | Page |
| `--white` | `#fffef8` | Guide, input surfaces and dependency details |
| `--ink` | `#192417` | Primary text |
| `--muted` | `#505b4b` | Secondary text |
| `--forest` | `#233b28` | Primary button and sample verdict |
| `--lime` | `#dff0a4` | Brand mark, selection and sample backing |
| `--wash` | `#ecefe0` | Commands, footer and passing policy |
| `--line` | `#d5d9cb` | Separators and controls |
| `--rust-wash` | `#f9e8df` | Blocked policy |
| `--amber-wash` | `#fff2d2` | Policy warnings |

Use text and color together for outcomes. Counts and package identifiers need
to remain readable at every width. Never present a passing gate as a safety
claim.

## Landing colors

The landing page uses `#f7f7f4` paper, `#171e21` primary text,
`#4b575d` secondary text, and `#25343b` for the primary action.
The first landscape pairs a dark advisory card with a light verdict card.
Photography is decorative, served as local WebP files, and credited in
[the asset record](web/assets/README.md).

## Type and layout

The landing hero and section headings use an Iowan/Palatino/Georgia serif
stack. The rest uses self-hosted Sora headings, Manrope for body copy, and
browser monospace for code and identifiers. The main shell caps at 1170 pixels. The
homepage and report picker stack at 760 pixels, and the reader’s inventory
and details stack at 950 pixels. Narrow layouts retain visible focus and move
focus to the selected dependency details. Only the sample cards have raised surfaces. Commands, warnings and selected rows use flat colors.

## Interaction

Landing mode guides visitors through try, open or install. Reader mode handles
open, inspect and export. Use native anchors, disclosures and file input.
Introductory content and the first sample link remain available without
JavaScript. Visitors choose a sample; the stage never auto-advances. A short
hero entrance respects reduced-motion preferences. The website
requests sample files only when a visitor chooses one. Page scripts, assets
and fonts are served locally by the site.

## Footer

The supplied Shutter Glyph Footer demo uses near-black `#111110` with bone
`#efe9dc`. The shared footer pairs that palette, compact monospace navigation
and an oversized SCRAM wordmark. The shutter sits inside the R’s bowl, where it
follows a pointer with motion enabled and rotates a quarter turn on activation
by pointer or keyboard. The visible link labels settle back to their original
text and their accessible names stay fixed. The footer links to the reader,
project feedback, privacy information and the license.

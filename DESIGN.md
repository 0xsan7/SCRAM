# SCRAM website design

The landing page helps a visitor choose their next action. It shows one real
synthetic verdict beside the hero, followed by a three-step guide and an About
section. A separate reader prioritizes policy and warnings, then inventory,
dependency details and drift. The footer groups GitHub, feedback and return
navigation.

## Colors

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

## Type and layout

Sora is self-hosted for headings, Manrope for explanations, and browser
monospace for code and identifiers. The main shell caps at 1170 pixels. The
homepage and report picker stack at 760 pixels, and the reader’s inventory
and details stack at 950 pixels. Narrow layouts retain visible focus and move
focus to the selected dependency details. The sample card is the only raised
surface. Commands, warnings and selected rows use flat colors.

## Interaction

Landing mode guides visitors through try, open or install. Reader mode handles
open, inspect and export. Use native anchors, disclosures and file input.
Introductory content remains available without JavaScript. The website
requests sample files only when a visitor chooses one. Page scripts, assets
and fonts are served locally by the site.

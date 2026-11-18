---
name: SCRAM Report Viewer
description: A dark dependency registry that keeps policy decisions connected to evidence.
colors:
  page: "#0b0c0e"
  rail: "#0e0f11"
  surface: "#121416"
  hover: "#1b1e22"
  line: "#2b2f35"
  text: "#eceef0"
  muted: "#a5acb6"
  accent: "#f4ba63"
  red: "#ff9d9d"
  green: "#8cd6b0"
  warning: "#f4c780"
  row-line: "#23262b"
  selected-row: "#1b1c1a"
  selected-example: "#20201c"
  selected-example-line: "#4b4334"
  file-button: "#e5e7eb"
  file-button-text: "#111214"
typography:
  display:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "clamp(25px, 3vw, 34px)"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.035em"
  policy:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "20px"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "14px"
    lineHeight: 1.65
  help:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "12px"
    lineHeight: 1.7
  detail:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "11px"
    lineHeight: 1.8
  number:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "23px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "-0.025em"
  identifier:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
    fontSize: "12px"
    lineHeight: 1.6
rounded:
  tag: "4px"
  quiet-tag: "5px"
  file-button: "6px"
  control: "7px"
  example: "8px"
  surface: "12px"
spacing:
  compact: "6px"
  small: "8px"
  control: "12px"
  row: "15px"
  standard: "16px"
  related: "20px"
  panel: "22px"
  section: "25px"
  workbench: "28px"
components:
  button-default:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
  button-hover:
    backgroundColor: "{colors.hover}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
  file-button:
    backgroundColor: "{colors.file-button}"
    textColor: "{colors.file-button-text}"
    rounded: "{rounded.file-button}"
    padding: "11px 12px"
  example-selected:
    backgroundColor: "{colors.selected-example}"
    textColor: "{colors.accent}"
    rounded: "{rounded.example}"
    padding: "11px 8px"
  search:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
  severity-tag:
    textColor: "{colors.red}"
    rounded: "{rounded.tag}"
    padding: "2px 6px"
  policy:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.surface}"
    padding: "23px 25px"
  inspector:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.surface}"
    padding: "22px"
  inventory-row-selected:
    backgroundColor: "{colors.selected-row}"
    textColor: "{colors.accent}"
---

# Design System: SCRAM Report Viewer

## Overview

**Creative North Star: "Dependency registry"**

A quiet, dark review desk: ruled dependency rows sit beside a component inspector, with report provenance and policy evidence above them. The interface gives reading, comparison and selection more weight than decoration. The registry metaphor is the implemented direction recorded in `docs/report-viewer-design.md` (Operate mode, grounded candidate 6); it is descriptive language for this build.

The user selected a dark interface matching the portfolio. Sora headings and Manrope text reuse its self-hosted font assets. Specific colors, dimensions, component arrangements and the rules below record current implementation patterns; they are not claims of separate user approval. There is no approved image comp. This document covers `web/`, not the scanner's terminal output or the root portfolio.

**Key Characteristics:**
- Near-black surfaces separated by fine rules and restrained tonal changes.
- Amber selection and focus, with explicit status words alongside status colors.
- Compact, tabular report facts and wrapping identifiers.
- A report chooser, inventory and inspector that stack as space narrows.
- Immediate report-state changes and optional short control transitions.

## Colors

The palette combines warm selection with cool dark neutrals; exact reusable values live in the frontmatter and mirror `web/styles.css`.

### Primary

- **Registry amber** (`accent`): selected report text, selected dependency names, the row's inset marker, advisory links, caret and keyboard focus. It also accents the brand shield.

### Secondary

- **Evidence amber** (`warning`): provenance, warning headings and medium-severity findings.
- **Failure rose** (`red`): failed-policy headings/icons and high or critical severity.
- **Passed mint** (`green`): passed-policy headings/icons and the corresponding example dot.

These are semantic status roles, not interchangeable decorative accents. Low severity has a local blue value in the stylesheet; it is not promoted into the primary palette.

### Neutral

- **Page black** (`page`) and **rail black** (`rail`): the application frame and report chooser.
- **Inspection charcoal** (`surface`): controls, policy and inspector backgrounds.
- **Hover charcoal** (`hover`): ordinary button hover state.
- **Rule gray** (`line`, `row-line`): outer boundaries and quieter inventory/drift separators.
- **Off-white** (`text`) and **secondary gray** (`muted`): primary and supporting text.
- **Selected row charcoal** (`selected-row`): dependency selection without obscuring its row structure.
- **Selected report olive-charcoal** (`selected-example`, `selected-example-line`): warm, restrained report-choice selection.
- **File-action paper** (`file-button`, `file-button-text`): the high-contrast native file selection action.

**The Status Has Words Rule.** Preserve the visible policy, severity and example labels when using status color; a dot or color alone does not carry the result.

## Typography

**Display Font:** Sora, with system-ui and sans-serif fallbacks.

**Body Font:** Manrope, with system-ui and sans-serif fallbacks.

**Identifier Font:** The native ui-monospace / SFMono-Regular / Consolas stack.

Both primary families are self-hosted variable WOFF2 assets under `web/assets/fonts/`; the stylesheet declares Sora weights 100–800 and Manrope weights 200–800 with swap loading. Use the source assets and retain their license notices.

Sora supplies compact heading shapes; Manrope supplies report prose, labels and controls. The frontmatter's body role is the global base. Most actual report labels, table content, metadata and finding prose use the smaller detail/help roles; do not infer a uniform body-size rule from the base alone. Numeric figures inherit tabular numerals throughout.

- **Display:** report title; the responsive clamp is overridden to 27px at the narrow breakpoint.
- **Policy:** outcome heading; reduced to 18px on narrow screens.
- **Title:** inventory, inspector and other section headings; reduced to 14px on narrow screens. The generic h2 base is 17px; component roles override it.
- **Body / help / detail:** base text, explanatory text and compact evidence respectively. Policy explanations cap at 75ch; evidence lists at 90ch.
- **Number:** summary facts; reduced to 22px on narrow screens. Unknown baseline values use smaller Manrope text rather than a numeric zero.
- **Identifier:** package identifiers and commands; PURLs and finding IDs use local 11px variants and wrap when necessary.

**The Identifier Rule.** Reserve monospace for actual identifiers, versions where represented as code, and commands; retain Manrope for human explanations.

## Layout

The desktop frame has a 76px application header and a 238px report rail beside flexible main content. The main region caps at 1720px and uses 36px top padding, fluid horizontal padding `clamp(22px, 3.5vw, 56px)` and 24px bottom padding. The rail remains part of the page grid; it is not fixed or sticky.

Policy reasons and warnings lead above a wrapping strip of summary facts. The workbench pairs inventory and inspector using `minmax(0, 1.35fr) minmax(280px, 1fr)` with a 28px gap. At widths of at least 1600px this becomes `minmax(0, 1.55fr) minmax(330px, 1fr)`.

At 1180px and below, the rail contracts to 205px and the inspector moves below the inventory. At 720px and below, the header becomes 65px tall, the rail becomes a stacked report control, examples form three columns, main padding becomes `27px 20px 23px`, controls stack and summary facts use three columns. Drift rows become stacked blocks. Secondary source-link text and the rail privacy note are visually removed on narrow screens; the source-link SVG retains its link target.

Keep flexible areas at `min-width: 0`, wrap long report strings, and allow the inventory table's local horizontal scroll rather than page overflow. Inventory and drift paginate at 15 items, finding details at 8. Pagination, filtered-empty recovery and errors remain part of the responsive structure.

## Elevation & Depth

Depth comes from tonal layering and one-pixel borders, with no drop shadows or floating overlays. The only box-shadow is the selected row's inset one-pixel amber marker; it communicates selection, not elevation. Policy and inspector share the same surface material. Avoid introducing a hierarchy of floating cards where the implemented registry uses rules and adjacency.

**The Ruled Surface Rule.** Separate evidence groups with the existing line and surface vocabulary; keep row selection legible through both the warm background and inset marker.

## Shapes

Major report surfaces use gently rounded 12px corners. Controls use 7px, example choices 8px, the file action 6px, schema tags 5px and severity tags 4px. Small provenance/example dots are circular. The frontmatter records extracted role names for these values; only the major surface radius is a CSS custom property today.

Borders are generally one pixel. Inline SVG uses a 1.5px stroke with rounded caps and joins, with no icon font. Tables retain rectangular ruled rows rather than individually rounded tiles.

## Components

### Buttons

Ordinary actions are compact outlined charcoal controls. Default padding and radius are in the frontmatter, with a 40px minimum height. Hover changes background and border; disabled buttons retain the surface and rule colors at 0.42 opacity. Pagination uses smaller padding (`5px 9px`) and a 34px minimum height, returning to 40px at the narrow breakpoint. Finding pagination has a local 32px minimum height.

The native file-selector button is the strongest light action. Its hover surface becomes white. Do not treat it as evidence that every action should be filled or light.

Keyboard focus uses a 2px amber outline with a 4px offset. When reduced motion is not requested, buttons, links, inputs and selects transition background, border and text colors for 0.14s with ease-out timing. No entrance motion delays report content.

### Report selection

Example choices combine a status dot, a title, an explicit policy description and a chevron. Their selected state uses `aria-pressed`, a warm outlined surface and amber title. Narrow-screen examples have visible borders, no chevron and a 73px minimum height. Selection indicates the currently opened report, not a safety judgment.

### Inputs / Fields

Search combines an inline SVG with a surface-colored field and a single rounded border. Focus-within makes the wrapper border amber; the input retains visible keyboard focus. The native select shares the control material and becomes full width below the search on narrow screens. Labels and accessible names remain available when visible field labels are compacted.

### Chips

Schema and severity tags are quiet outlined labels. Severity text carries its status color and includes a word and CVSS value; these tags are not filter buttons. The schema label remains muted.

### Cards / Containers

The policy panel and inspector share the major surface shape and rule. The policy panel has `23px 25px` padding; the inspector uses 22px. On narrow screens these become `20px 17px` and `19px 17px`. Warnings sit inside the policy panel behind a top divider; they do not become a competing summary tile.

### Navigation

The application header combines the shield, SCRAM name, divider and report-viewer label. Source navigation is a quiet external link with an inline arrow. The report rail is a chooser, not a route navigation menu. A keyboard-visible skip link leads directly to the report.

### Dependency inventory and inspector

Inventory rows use human-readable names as real buttons, then compact version/relationship metadata, ecosystem and explicit finding counts. A selected row has a warm background, amber name and inset marker; its name button exposes `aria-pressed`. Selecting a row updates the adjacent inspector without moving the page; on narrow layouts the inspector follows the inventory.

The inspector keeps the PURL, version, relationship and license distinct from score terms and known findings. Score terms are ruled text rows, not gauges. Finding IDs remain monospace, summaries wrap, and source/EPSS/fixed-version caveats stay in supporting text. New findings are listed before others. Error and empty states use plain explanations and a recovery action where applicable.

## Do's and Don'ts

### Do:

- **Do** use the near-black surface hierarchy, fine rules and Sora/Manrope pairing already implemented.
- **Do** keep provenance, policy explanations and missing-evidence warnings visible before interpreting scores.
- **Do** pair semantic colors with explicit words and preserve the amber keyboard focus outline.
- **Do** preserve identifier wrapping, responsive stacking and local table overflow.
- **Do** keep selected report and selected dependency states distinguishable from policy outcomes.

### Don't:

- **Don't** turn a passed policy or zero known findings into a visual claim of repository safety.
- **Don't** replace unknown baseline values with zeros or successful status decoration.
- **Don't** turn these extracted implementation details into claims of user-approved composition or an approved image comp.
- **Don't** add decorative graph data, artificial live activity or entrance motion to this saved-report registry.

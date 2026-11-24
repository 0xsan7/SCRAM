---
name: SCRAM Report Viewer — Glass Trial
description: Branch-scoped adjustable glass trial over the existing dependency registry.
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
  glass-ground: "#0b1016"
  glass-material-base: "#17191d"
  glass-scenery-shade: "#06090db3"
  glass-tint: "#eadbc7"
  glass-secondary: "#bbc6d1"
  glass-inner: "#0a10182e"
  glass-field: "#0a101847"
  glass-tag: "#0a101826"
  glass-line: "#b0c4d526"
  glass-field-line: "#b0c4d52e"
  glass-strong-line: "#b0c4d54a"
  glass-action: "#ffffff08"
  glass-action-hover: "#ffffff12"
  glass-action-line: "#b0c4d533"
  glass-selected: "#f4ba6314"
  glass-selected-line: "#f4ba634d"
  glass-row-selected: "#f4ba6312"
  glass-solid: "#18212b"
  glass-settings-panel: "#171e27"
typography:
  display:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "clamp(27px, 2.6vw, 36px)"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.035em"
  policy:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "23px"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  title:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 500
    lineHeight: 1.3
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "16px"
    lineHeight: 1.65
  help:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "13px"
    lineHeight: 1.7
  detail:
    fontFamily: "Manrope, system-ui, sans-serif"
    fontSize: "14px"
    lineHeight: 1.8
  number:
    fontFamily: "Sora, system-ui, sans-serif"
    fontSize: "28px"
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
  example: "10px"
  surface: "12px"
  glass-action: "9px"
  glass-control: "10px"
  glass-panel: "16px"
  glass-frame: "20px"
  glass-workspace: "24px"
  glass-workspace-mobile: "18px"
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
  frame-gap: "18px"
  frame-inset: "24px"
components:
  button-default:
    backgroundColor: "{colors.glass-action}"
    textColor: "{colors.text}"
    rounded: "{rounded.glass-action}"
    padding: "8px 12px"
  button-hover:
    backgroundColor: "{colors.glass-action-hover}"
    textColor: "{colors.text}"
    rounded: "{rounded.glass-action}"
  file-button:
    backgroundColor: "{colors.file-button}"
    textColor: "{colors.file-button-text}"
    rounded: "{rounded.file-button}"
    padding: "10px"
  example-selected:
    backgroundColor: "{colors.glass-selected}"
    textColor: "{colors.accent}"
    rounded: "{rounded.example}"
    padding: "12px 10px"
  search:
    backgroundColor: "{colors.glass-field}"
    textColor: "{colors.text}"
    rounded: "{rounded.glass-control}"
  severity-tag:
    textColor: "{colors.red}"
    rounded: "{rounded.tag}"
    padding: "2px 6px"
  policy:
    backgroundColor: "{colors.glass-inner}"
    rounded: "{rounded.glass-panel}"
    padding: "24px"
  inspector:
    backgroundColor: "{colors.glass-inner}"
    textColor: "{colors.text}"
    rounded: "{rounded.glass-panel}"
    padding: "24px"
  inventory-row-selected:
    backgroundColor: "{colors.glass-row-selected}"
    textColor: "{colors.accent}"
---

# Design System: SCRAM Report Viewer — Glass Trial

## Overview

**Creative North Star: "Frosted dependency registry"**

This document describes the styling trial on `codex/scram-glass-preview` only. Production remains on `codex/scram-usability` and is unchanged. The user explicitly chose to apply the supplied adjustable-glass styling to the existing viewer; this is authorization for the trial, not approval to replace production. There is no approved image comp.

The existing dependency registry now sits inside a floating frosted header, rail and workspace over the reference room photograph (`web/assets/glass-room.jpg`). Fixed viewport scenery and a dark shade supply visible detail for the actual backdrop blur; the photograph is not pre-blurred. Inner evidence panels stay quiet and unblurred. Sora, Manrope, amber selection and explicit policy/severity semantics retain their established roles. `web/glass.css`, loaded after `web/styles.css`, owns this trial's overrides; `web/glass.mjs` controls session-only material settings. The corrected trial follows the supplied 21st adjustable-glass-dashboard reference. It adds the local reference room image while retaining native HTML/CSS/JavaScript, without a framework migration or new dependency.

**Key Characteristics:**
- Translucent dark outer surfaces, illuminated edges and quiet inner evidence panels.
- Amber selection and focus, with explicit status words alongside status colors.
- Readable tabular report facts and wrapping identifiers.
- A report chooser, inventory and inspector that stack as space narrows.
- Immediate report-state changes, optional short control transitions and adjustable session-only glass.

## Colors

The palette combines warm selection with cool dark neutrals; exact reusable values live in the frontmatter and reflect the base stylesheet plus effective trial overrides.

### Primary

- **Registry amber** (`accent`): selected report text, selected dependency names, the row's inset marker, advisory links, caret and keyboard focus. It also accents the brand shield.

### Secondary

- **Evidence amber** (`warning`): provenance, warning headings and medium-severity findings.
- **Failure rose** (`red`): failed-policy headings/icons and high or critical severity.
- **Passed mint** (`green`): passed-policy headings/icons and the corresponding example dot.

These are semantic status roles, not interchangeable decorative accents. Low severity has a local blue value in the stylesheet; it is not promoted into the primary palette.

### Neutral

The `glass-*` colors are the trial layer: a shaded photographic ground, neutral dark material, warm ivory tint, cool secondary text, transparent inner panels/fields, translucent rules and low-opacity amber selection. Base tokens remain available for inherited controls and semantic text; they do not imply a return to the production flat frame. The default glass tint is separately adjustable and never replaces status colors.

- **Base page/rail black** (`page`, `rail`): retained inherited values; the trial’s outer frame uses the adjustable glass material over `glass-ground`.
- **Base inspection charcoal** (`surface`): retained inherited controls; trial policy/inspector panels use `glass-inner` and search/filter fields use `glass-field`.
- **Base hover charcoal** (`hover`): inherited button hover; trial report actions use the translucent `glass-action-hover`.
- **Base rule gray** (`line`, `row-line`): inherited boundary values; trial report separators use `glass-line`.
- **Off-white** (`text`): primary text. Base `muted` remains available; trial supporting prose uses `glass-secondary`.
- **Base selected-row charcoal** (`selected-row`): retained base value; the trial uses `glass-row-selected`.
- **Base selected-report values** (`selected-example`, `selected-example-line`): retained base values; the trial uses `glass-selected` and `glass-selected-line`.
- **File-action paper** (`file-button`, `file-button-text`): the high-contrast native file selection action.

**The Status Has Words Rule.** Preserve the visible policy, severity and example labels when using status color; a dot or color alone does not carry the result.

## Typography

**Display Font:** Sora, with system-ui and sans-serif fallbacks.

**Body Font:** Manrope, with system-ui and sans-serif fallbacks.

**Identifier Font:** The native ui-monospace / SFMono-Regular / Consolas stack.

Both primary families are self-hosted variable WOFF2 assets under `web/assets/fonts/`; the stylesheet declares Sora weights 100–800 and Manrope weights 200–800 with swap loading. Use the source assets and retain their license notices.

Sora supplies compact heading shapes; Manrope supplies report prose, labels and controls. The frontmatter's body role is the 16px global base. Regular report and control text uses 14–15px, with secondary labels and metadata at 12–13px. The final readability overrides at the end of `web/styles.css` are authoritative over its original compact rules. Numeric figures inherit tabular numerals throughout.

- **Display:** report title; the responsive clamp is overridden to 27px at the narrow breakpoint.
- **Policy:** outcome heading; reduced to 21px on narrow screens.
- **Title:** inventory, inspector and other section headings; reduced to 16px on narrow screens. Component roles override the generic h2 base.
- **Body / help / detail:** base text, explanatory text and compact evidence respectively. Policy explanations cap at 75ch; evidence lists at 90ch.
- **Number:** summary facts; reduced to 26px on narrow screens. Unknown baseline values use smaller Manrope text rather than a numeric zero.
- **Identifier:** package identifiers and commands; PURLs use 13px (12px narrow) and finding IDs use 13px variants and wrap when necessary.

**The Identifier Rule.** Reserve monospace for actual identifiers, versions where represented as code, and commands; retain Manrope for human explanations.

## Layout

The trial floats inside a 1680px maximum frame with `calc(100% - 48px)` width. The 72px header has a 24px top margin and 18px gap below; the rail/workspace grid uses a 252px rail and 18px gap. Main padding is 30px, rail padding `25px 22px`. The workbench retains `minmax(0, 1.2fr) minmax(320px, 1fr)` and a 28px gap.

At 1240px and below, the rail becomes 235px, main padding becomes 26px and the inspector stacks. At 720px and below, the frame uses 12px side margins, a 65px header, a stacked rail with `22px 18px` padding, and main padding `24px 18px`. Header/rail corners become 16px, workspace corners 18px. Examples, summary facts and refinements retain two-column narrow grids. The compact header hides the report-viewer sublabel/divider while retaining SCRAM, Adjust glass and the text source link.

Keep flexible areas at `min-width: 0`, wrap long report strings, and allow the inventory table's local horizontal scroll rather than page overflow. Inventory and drift paginate at 15 items, finding details at 8. Pagination, filtered-empty recovery and errors remain part of the responsive structure.

## Elevation & Depth

The trial uses blur only on the three outer surfaces: header, report rail and main workspace. Default material settings are blur 22px, opacity 0.30, saturation 1.2, edge light 0.6 and tint `glass-tint`. Opacity controls the dark material independently of the separate 12% tint wash, so changes remain visible against the scenery. The exact dynamic color-mix formulas and shadows are in the sidecar. Outer surfaces combine an inset illuminated top edge, a fine inset rule and a soft ambient shadow; the opaque appearance panel has its own soft shadow. Inner policy/inspector panels have no shadow or backdrop blur.

**The Ruled Surface Rule.** Keep inner evidence legible with quiet translucent fills and fine rules; reserve backdrop blur and ambient lift for the outer workspace surfaces.

Solid mode removes blur/transparency. Unsupported backdrop-filter and reduced-transparency preferences use the solid surface; forced colors removes the photographic backdrop and shadows and uses Canvas/CanvasText borders. Reduced-transparency or forced-colors preferences also disable appearance controls. Existing reduced-motion behavior remains unchanged.

## Shapes

The floating header and rail use 20px corners, the workspace 24px, and inner policy/inspector panels 16px. Narrow outer corners are 16px for header/rail and 18px for the workspace. Search/filter controls and examples use 10px, common report actions 9px, the drop zone 12px, schema tags 7px and severity tags retain 4px. Native file selection retains its existing shape. Small provenance/example dots remain circular.

Borders are generally one pixel. Inline SVG uses a 1.5px stroke with rounded caps and joins, with no icon font. Tables retain rectangular ruled rows rather than individually rounded tiles.

## Components

### Buttons

Report actions use faint translucent fills and cool outlines; the native file action retains its light treatment. Default padding and radius are in the frontmatter, with a 40px minimum height. Hover changes background and border; disabled buttons retain the surface and rule colors at 0.42 opacity. Pagination uses smaller padding (`5px 9px`) and a 44px minimum height. Search and primary filter controls have a 46px minimum height; refinement controls use 44px.

The native file-selector button remains the strongest light action. Its hover surface becomes white. Do not treat it as evidence that every action should be filled or light.

Keyboard focus uses a 2px amber outline with a 4px offset. When reduced motion is not requested, buttons, links, inputs and selects transition background, border and text colors for 0.14s with ease-out timing. No entrance motion delays report content.

### Report selection

Example choices combine a status dot, a title, an explicit policy description and a chevron. Their selected state uses `aria-pressed`, a translucent amber outlined surface and amber title. Examples retain a 66px minimum height in this trial, including narrow screens; narrow choices hide chevrons. Selection indicates the currently opened report, not a safety judgment.

### Inputs / Fields

The dashed, rounded drop zone surrounds native file selection and highlights on file drag. A native Create your own report disclosure holds the scan command, copy feedback and install link. Four production-verified synthetic examples remain explicitly labeled; optional CLI opening serves only the selected report on loopback.

Search combines an inline SVG with a surface-colored field and a single rounded border. Focus-within makes the wrapper border amber; the input retains visible keyboard focus. The native select shares the control material and becomes full width below the search on narrow screens. Ecosystem, severity and sort refinements wrap on desktop and use a two-column narrow grid, with a Reset action. Labels and accessible names remain available when visible field labels are compacted.

### Chips

Schema and severity tags are quiet outlined labels. Severity text carries its status color and includes a word and CVSS value; these tags are not filter buttons. The schema label remains muted.

### Cards / Containers

The policy panel and inspector share the major surface shape and rule. The policy panel and inspector use 24px padding. On narrow screens these become `20px 16px` and `21px 16px`. Warnings sit inside the policy panel behind a top divider; they do not become a competing summary tile.

The Generated review summary disclosure uses horizontal rules, wrapping monospace text in a scrollable surface capped at 280px, and Copy summary / Download text actions. Export captures the filtered inventory while retaining full policy reasons and warnings.

### Navigation

The application header combines the shield, SCRAM name, divider and report-viewer label. Source navigation is a quiet, text-only external link. A native Adjust glass disclosure opens a 320px opaque settings panel, constrained to the viewport on mobile. Four ranges control blur (0–40px), opacity (8–100%), saturation (50–200%) and edge light (0–100%); a color input supplies tint. Clear, Frosted and Solid presets plus Reset appearance affect material only and reset on reload. Close, Escape and outside-pointer dismissal are implemented; closing with the button/Escape returns focus to the disclosure. A 94px-minimum live material sample inside the appearance panel uses the same room image, material, filter and edge variables. Clear uses blur 8px / opacity 12% / saturation 110% / edge 80%; Frosted uses 22px / 30% / 120% / 60%. Solid intentionally uses true opaque 100% material and no blur, rather than the reference’s 86% preset, to preserve the accessibility fallback. The sidecar records exact presets and fallbacks. The report rail is a chooser, not a route navigation menu. A keyboard-visible skip link leads directly to the report.

### Dependency inventory and inspector

Inventory rows use human-readable names as real buttons, then compact version/relationship metadata, ecosystem and explicit finding counts. A selected row has a warm background, amber name and inset marker; its name button exposes `aria-pressed`. Selecting a row updates the adjacent inspector. At 1240px and below, selection focuses the detail heading and scrolls the stacked inspector into view; its Back to inventory link returns to the inventory heading.

The inspector keeps the PURL, version, relationship and license distinct from score terms and known findings. Score terms are ruled text rows, not gauges. Finding IDs remain monospace, summaries wrap, and source/EPSS/fixed-version caveats stay in supporting text. New findings are listed before others. Error and empty states use plain explanations and a recovery action where applicable.

## Do's and Don'ts

### Do:

- **Do** use this branch’s frosted outer frame, quiet inner evidence, fine rules and existing Sora/Manrope pairing.
- **Do** keep provenance, policy explanations and missing-evidence warnings visible before interpreting scores.
- **Do** pair semantic colors with explicit words and preserve the amber keyboard focus outline.
- **Do** preserve identifier wrapping, responsive stacking and local table overflow.
- **Do** keep selected report and selected dependency states distinguishable from policy outcomes.

### Don't:

- **Don't** turn a passed policy or zero known findings into a visual claim of repository safety.
- **Don't** replace unknown baseline values with zeros or successful status decoration.
- **Don't** treat this styling trial as production approval or claim an approved image comp.
- **Don't** add decorative graph data, artificial live activity or entrance motion to this saved-report registry.

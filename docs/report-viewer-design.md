> Historical design notes for the original report viewer. See [the current design](../DESIGN.md) for the guided site.

# Report viewer direction

Mode: Operate. The approved functional brief is
`examples/report-viewer/README.md`; product truth is in `PRODUCT.md`.
The user chose a dark interface matching the existing portfolio and
authorized implementation to proceed.

## Direction contract

THESIS: Keep the policy decision connected to its evidence in a dependency
review desk. The primary action is opening a report, followed by selecting
and inspecting a dependency.

OWN-WORLD: Near-black registry surfaces, ruled rows, off-white text and
restrained amber selection, with Sora headings and Manrope text.

STORY: Open a local or synthetic report, understand its policy and limitations,
then search dependencies and inspect findings without sending report data away.

FIRST VIEWPORT: A persistent left report chooser frames the main report.
Provenance and policy reasons lead above inline summary facts. Below them,
the dependency inventory sits beside its inspector; drift follows below.
The signature interaction is selection connecting a row to its evidence.
State changes are immediate; no entrance motion conceals content.

FORM: Grounded candidate 6 of seven, dependency registry. The direction roll
used seed `d06c141d` in Operate mode. The other alternatives are listed below.
This implementation has no approved image comp or supplied QUALITY BAR card.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

Build a dependency review desk: a quiet black registry with ruled inventory
rows, a persistent report selector and an adjacent component inspector.
The report's policy result and missing evidence lead; the score follows.
Reading and comparing are the signature interactions, with no decorative
network graph or invented live activity. Sora headings and Manrope text reuse
the portfolio's self-hosted assets and licenses.

Use near-black page and rail surfaces, a slightly raised inspection surface,
off-white primary text and comfortably legible secondary text. Amber carries
warnings/selection, red marks policy failure and green marks a passed policy.
Every status also has an explicit text label. Compact numbers are tabular;
monospace is reserved for actual package identifiers, versions and commands.

Hierarchy: application header, report title/provenance, policy and evidence,
inline summary facts, search/filter controls, component inventory, component
details, then full drift history. On narrow screens, the report selector
becomes a stacked control and the inspector moves below the inventory. Keep
pagination and empty/error recovery available at every width.

## Structural alternatives considered

The grounded alternatives were a terminal incident console, code-review diff,
event journal, signal bench, audit dossier, dependency registry and release
checklist. The registry carries both sparse examples and large imported
inventories without implying an executable workflow or graph data.

A split-flap board's fixed-column clarity is useful, but artificial live
updates do not fit saved reports. Transit diagrams imply absent dependency
edges. A light design annual conflicts with the chosen dark direction. Ticket
wallets impose a sequential journey. Poster walls hide critical metadata.
Acetate-manual layers reduce legibility. Preserve their disciplines of clear
column priorities, context, attribution and persistent state while retaining
one coherent dark review interface.

## Verification target

Check desktop and mobile together: readable warning/reason content, visible
keyboard focus, complete details, no horizontal page overflow, file switching
that clears prior state and all three synthetic outcomes. Report content is
text, advisory navigation is explicit and imported data triggers no network
requests. The first version does not publish or scan repositories.

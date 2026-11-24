# Glass styling trial

Mode: Operate. This is a styling trial of the existing report viewer, on
`codex/scram-glass-preview`. The user supplied an adjustable glass React
dashboard, then explicitly chose to apply its styling to the existing viewer.
Keep native HTML/CSS/JavaScript; no React, finance data or framework migration.

## Direction contract

THESIS: Let the existing dependency review desk sit inside a coherent frosted
workspace while preserving the connection between policy, inventory and evidence.

OWN-WORLD: Floating rounded header, translucent dark rail and workspace,
the reference's warm room photograph, fine illuminated edges, existing Sora and
Manrope fonts, amber selection and explicit status colors. Inner evidence stays
quiet and readable rather than multiplying blur layers.

STORY: Open the same local report or example, read its policy, then inspect
dependencies. Appearance controls adjust only the material, never report data.

FIRST VIEWPORT: A floating top bar contains brand, appearance and source links.
A compact report rail sits beside the frosted main workspace. The policy leads
the existing facts and two-column inventory/inspector. Narrow screens stack the
same controls and evidence; keyboard focus and errors remain visible.

FORM: User-pinned adjustable glass workspace from the supplied component,
adapted onto the established dependency registry. No new structural tournament
or approved image comp; the explicit styling choice takes precedence.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Boundaries and checks

The live Cloudflare production branch remains `codex/scram-usability`. Publish
only a branch preview for review. Preserve file validation, local imports,
filtering, summary export, examples and raw-score/policy semantics. Bundle the
reference's room photograph locally with its origin metadata; no third-party
image request is needed. Use native appearance
controls with bounded blur, opacity, saturation, edge light and tint; include
solid/no-blur fallback, reduced-transparency and forced-color behavior. Verify
desktop/mobile together, appearance keyboard interaction and existing flows.

## Reference behavior correction

The user reported that the first trial's blur and saturation did not behave
like the reference. The controls changed CSS values, but 82% opacity over an
already smooth gradient obscured their visible effect. Use a detailed, sharp
backdrop and the reference's 30% default surface opacity, with a separate 12%
tint layer. Match 0–40 px blur and 50–200% saturation; expose 8–100% opacity.
Clear uses 8 px / 12% / 110%; Frosted uses 22 px / 30% / 120%. Solid remains
truly opaque with no blur for accessibility. The live material sample shares
the workspace filter. Verify actual rendered changes at both ends of each
range rather than checking slider labels alone.

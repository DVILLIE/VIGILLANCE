# Distinct D/V animation samples

Creative samples for owner selection; the application identity is unchanged.
Each preview uses clearly separate D and V letterforms, metallic gradients,
a full vertical-axis bitmap turn, then two lights on the existing oval.
These are rendered 2D animation concepts, not true 3D mesh renders or telemetry.

1. Chrome D / Sapphire V: compact V inside the D.
2. Interlocking D + V: large silver V against blue D.
3. Twin-letter Vigil: separate letters for strongest small-icon legibility.

Both supplied naming options appear in every sample:
“D’Vielle — Intelligent Vigilance” and “Vigilia — Always Watching”.
The final name and logo require the owner's selection before installation.

`render_samples.py` creates the PNG masters, static previews, and animated GIFs
using existing Pillow and Windows font resources. No paid API or new dependency
is required. Each GIF was decoded and checked for its frame count and size,
and each static composition was visually inspected.

For final interactive use, retain a motion-off control as recommended by
[W3C animation guidance](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions).

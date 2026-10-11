# Quantum Key — glowing D / dual cube sample

Animated selection preview only; application branding is unchanged.

The built-in image tool edited `../radical-ten/art-02.png` with this prompt:
preserve black ceramic D and existing carved amber V, its shape/perspective/
placement, and navy background; add a thin continuous amber glow to the actual
outer silhouette of D; no rings, infinity, extra enclosing geometry, sparks,
captions, watermark, or baked cubes. Result: `glowing-d-master.png`.

`animate_cubes.py` draws exactly two native isometric cubes. Gold follows the
outer carved-V contour clockwise; cyan follows a separate inner-V contour
anticlockwise. Both paths are closed, traced against this artwork, and traversed
by distance for constant speed. Signed-area checks verify opposite directions
in screen coordinates. Native preview captures form the GIF. The GIF is decoded
and checked for dimensions/frame count and actual pixel movement; a static
capture is visually inspected. These cubes are decorative graphic elements.

For eventual app integration, retain Motion off and hidden-window stopping,
consistent with [Fluent motion guidance](https://fluent2.microsoft.design/motion).

## Cool-blue communication revision

`cool-blue-d-master.png` is a sibling generated edit: change only the D's outer
glow to cool blue, preserve its ceramic face and warm gold V. The built-in image
tool was used; the amber master is retained.

`animate_communicating_cubes.py` renders glowing gold/blue cubes, keeping gold
on the clockwise outer-V contour and blue on the anticlockwise inner contour.
The loop is now 28.8 seconds versus the previous 6.4 seconds. Four eased travel
legs include brief inspection pauses. Each cube carries progressively animated
Wi-Fi arcs and a speaker/sound-bar graphic; their talking phases alternate.
This is a silent decorative preview: no Wi-Fi connection, investigation,
communication, protection state, or audio is being asserted or generated.

Output: `quantum-key-communicating-cubes.gif`, with a corresponding static
capture. Verification decodes the GIF, checks at least 28 seconds of total
duration and changing pixels, confirms opposite contour orientation, and checks
that the inspection pauses hold position. The application is unchanged.

## Glass / continuous rim revision

`animate_glass_cubes.py` and `quantum-key-glass-cubes-v3.gif` are a new sibling
preview to avoid overwriting or caching the earlier animation. One full cube
circuit now takes **96 seconds**, compared with 28.8 seconds previously.
Direction and eased inspection pauses are retained. The D rim breathes gently
and has traveling blue highlights in a continuous **8-second** light loop.

Cube faces now have sparse native translucent-style tint so the logo beneath
remains visible, polished bright edges, and glass-like specular accents. This
is a stylized glass rendering, not a ray-traced glass model. Wi-Fi and speaking
symbols remain silent decorative animation. GIF verification checks the actual
encoded 96,000 ms duration, frame count, visible pixel movement, and opposite
closed contour directions. Static native preview capture is visually reviewed.

## Live preview: stronger lightning and proximity communication
Only live-preview.html was refined: five stronger blue edge filaments and layered bloom, plus a blue/gold energy bridge with a violet/sea-green glow when cube centres are within 135 artwork pixels. Original artwork, contours, 45-second circuit and five-second surge interval are retained. All communication is decorative and silent. Canvas additive blending reference: https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/globalCompositeOperation . JavaScript parsing and actual contour proximity calculation were checked; this revision has not been visually verified in-browser because file navigation was blocked by browser policy.


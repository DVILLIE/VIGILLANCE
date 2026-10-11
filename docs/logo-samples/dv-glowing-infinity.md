# Glowing infinity DV sample

Preview only; application assets and runtime have not been changed.
The chrome D and sapphire V artwork was edited with the built-in image tool
to remove the oval entirely and preserve the nested DV identity. Prompt:
remove all rings, restore clean letter contours, preserve chrome/blue materials
and the distinct inset V, transparent background, no extra shapes or text.

The replacement infinity is a native drawn thin cyan line with a soft glow;
it has no metallic material or bevel. Two lights follow the same mathematical
figure-eight path. Rear sections pass behind the letters and front sections
pass in front. `preview_infinity.py` draws the concept in a native Tk window
and captures the animation as `dv-glowing-infinity.gif`. The static capture
was visually inspected. Duplicate occluded frames may be coalesced by GIF
encoding; decoded frame count and visible pixel movement are checked.

Motion-off remains required for eventual app integration, consistent with
[Fluent motion guidance](https://fluent2.microsoft.design/motion).

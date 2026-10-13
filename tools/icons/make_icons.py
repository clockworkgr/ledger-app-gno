"""Derives the app's icons from the gnolang GitHub avatar.

Usage, inside the ledger-app-dev-tools image (it has Pillow):

    curl -sSL -o avatar.png "https://avatars.githubusercontent.com/u/75237105?s=280&v=4"
    python3 tools/icons/make_icons.py avatar.png out/

then copy gno_14x14.gif, gno_32x32.gif, gno_40x40.gif and gno_32x32.png to icons/, and
gno_48x48.png and gno_64x64.gif to glyphs/. Formats follow the boilerplate's icons: 1-bit
white-on-black for Nano, 1-bit black-on-white for Apex P, 16-level grey on white for Stax and
Flex. Area resampling avoids the halo LANCZOS leaves around the shape. The files are encoded
the way Ledger's guidelines enforcer checks them: Stax/Flex greys need 8-bit depth, Apex P PNGs
are 1-bit black/white palettes.
"""
import sys
from PIL import Image, ImageOps

src, out = sys.argv[1], sys.argv[2]
lum = Image.open(src).convert("L")

# Crop to the gnome, then pad to a centred square.
bbox = lum.point(lambda v: 255 if v > 20 else 0).getbbox()
gnome = lum.crop(bbox)
side = max(gnome.size)


def square(margin: float) -> Image.Image:
    s = int(side * (1 + 2 * margin))
    canvas = Image.new("L", (s, s), 0)
    canvas.paste(gnome, ((s - gnome.width) // 2, (s - gnome.height) // 2))
    return canvas


def device_level(v: int) -> int:
    """The 4-bit level include_gif stores for an 8-bit grey."""
    return min(15, (v + 8) // 16)


def off_by_one(level: int) -> int:
    """Grey for one of 16 levels, never a multiple of 17 for mid levels.

    Exact multiples of 17 fit in 4 bits, and the guidelines enforcer wants 8-bit depth; the
    nudge keeps the level the device ends up with.
    """
    v = level * 17
    if 0 < level < 15:
        v = next(c for c in (v + 1, v - 1) if device_level(c) == device_level(v))
    return v


def grey16_on_white(size: int, margin: float) -> Image.Image:
    im = ImageOps.invert(square(margin).resize((size, size), Image.BOX))
    return im.point(lambda v: off_by_one(v // 17)).convert("P", palette=Image.ADAPTIVE, colors=16)


def mono(size: int, margin: float, threshold: int, invert: bool) -> Image.Image:
    im = square(margin).resize((size, size), Image.BOX)
    if invert:
        im = ImageOps.invert(im)
        return im.point(lambda v: 255 if v > 255 - threshold else 0).convert("1")
    return im.point(lambda v: 255 if v >= threshold else 0).convert("1")


print("bbox", bbox)
def save_bilevel_png(im: Image.Image, path: str) -> None:
    bilevel = Image.new("P", im.size)
    bilevel.putpalette([0, 0, 0, 255, 255, 255])
    bilevel.putdata([1 if v else 0 for v in im.convert("L").tobytes()])
    bilevel.save(path, bits=1, optimize=False)


mono(14, 0.06, 70, invert=False).convert("P").save(f"{out}/gno_14x14.gif")
grey16_on_white(32, 0.08).save(f"{out}/gno_32x32.gif")
grey16_on_white(40, 0.08).save(f"{out}/gno_40x40.gif")
save_bilevel_png(mono(32, 0.08, 60, invert=True), f"{out}/gno_32x32.png")
save_bilevel_png(mono(48, 0.06, 60, invert=True), f"{out}/gno_48x48.png")
grey16_on_white(64, 0.06).save(f"{out}/gno_64x64.gif")

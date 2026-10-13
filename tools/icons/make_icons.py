"""Derives the app's icons from the gnolang GitHub avatar.

Usage, inside the ledger-app-dev-tools image (it has Pillow):

    curl -sSL -o avatar.png "https://avatars.githubusercontent.com/u/75237105?s=280&v=4"
    python3 tools/icons/make_icons.py avatar.png out/

then copy gno_14x14.gif, gno_32x32.gif, gno_40x40.gif and gno_32x32.png to icons/, and
gno_48x48.png and gno_64x64.gif to glyphs/. Formats follow the boilerplate's icons: 1-bit
white-on-black for Nano, 1-bit black-on-white for Apex P, 16-level grey on white for Stax and
Flex. Area resampling avoids the halo LANCZOS leaves around the shape.
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


def grey16_on_white(size: int, margin: float) -> Image.Image:
    im = ImageOps.invert(square(margin).resize((size, size), Image.BOX))
    return im.point(lambda v: (v // 17) * 17).convert("P", palette=Image.ADAPTIVE, colors=16)


def mono(size: int, margin: float, threshold: int, invert: bool) -> Image.Image:
    im = square(margin).resize((size, size), Image.BOX)
    if invert:
        im = ImageOps.invert(im)
        return im.point(lambda v: 255 if v > 255 - threshold else 0).convert("1")
    return im.point(lambda v: 255 if v >= threshold else 0).convert("1")


print("bbox", bbox)
mono(14, 0.06, 70, invert=False).convert("P").save(f"{out}/gno_14x14.gif")
grey16_on_white(32, 0.08).save(f"{out}/gno_32x32.gif")
grey16_on_white(40, 0.08).save(f"{out}/gno_40x40.gif")
mono(32, 0.08, 60, invert=True).convert("P").save(f"{out}/gno_32x32.png")
mono(48, 0.06, 60, invert=True).convert("L").save(f"{out}/gno_48x48.png")
grey16_on_white(64, 0.06).save(f"{out}/gno_64x64.gif")

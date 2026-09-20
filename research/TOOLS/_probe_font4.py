"""Probe: dump the font atlas to PNG.

Decides the one thing that blocks any glyph work: is the 4096x4096 8-bit data
block stored LINEAR, or in Xbox 360 tiled/swizzled order?  If it renders as
readable glyphs it is linear and we can blit into it directly; if it looks
shredded we have to implement the X360 untiler first.
"""

import struct
import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
OUT = Path(__file__).resolve().parent.parent / "ANALYSIS"


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def dump(stem: str, w: int, h: int) -> None:
    f = GAME / "FONT" / f"{stem}.xpr"
    data = bytes(buffer_xor_decrypt(bytearray(f.read_bytes()), name_hash(f.stem)))
    hdr_size, dat_size = be32(data, 4), be32(data, 8)
    blob = data[12 + hdr_size:]
    print(f"{stem}: data={len(blob)} expect w*h={w * h} match={len(blob) == w * h}")

    img = Image.frombytes("L", (w, h), blob[:w * h])

    crop = img.crop((0, 0, min(1200, w), 150))
    crop.save(OUT / f"_font_{stem}_crop.png")

    over = img.crop((0, 0, w, 800)).resize((w // 4, 200), Image.LANCZOS)
    over.save(OUT / f"_font_{stem}_used.png")

    # whole atlas at half scale: shows the shipped rows AND the free space left
    img.resize((w // 2, h // 2), Image.LANCZOS).save(OUT / f"_font_{stem}_atlas.png")

    print(f"  wrote _font_{stem}_crop.png (1:1, top-left), "
          f"_font_{stem}_used.png (used region, 1/4 scale) and "
          f"_font_{stem}_atlas.png (whole atlas, 1/2 scale)")


def main() -> None:
    dump("0007ccd8", 4096, 4096)
    dump("000ebbe8", 2048, 1024)


if __name__ == "__main__":
    main()

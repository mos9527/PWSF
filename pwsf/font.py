"""PWSF font (Xbox 360 ATG-style) inside an XPR2 package.

FontData layout, from font_load_xpr @ 0x140042C60 (big-endian throughout):

    +0   u32 version           must be 5, font_load_xpr bails out otherwise
    +4   u32 metrics[4]        metrics[0] = float cell height (67.0 shipped)
    +20  u16 cMaxGlyph
    +22  u16 translator[cMaxGlyph + 1]   Unicode BMP code point -> glyph index
    p = 22 + 2*(cMaxGlyph+1)
    p+22 u32 num_glyphs
    p+26 GLYPH_ATTR[num_glyphs], 16 B each:
         u16 tu1, tv1, tu2, tv2   PIXEL coords in the atlas
         u16 off, width, advance, mask

Note the 22-byte gap between the translator table and num_glyphs: the loader
computes the second struct's base as FontData + 2*(cMaxGlyph+1) and then reads
num_glyphs at +22 of that, so the first 22 bytes there overlap the header it
already parsed.  Keep it byte-exact by slicing rather than re-serialising.

Atlas: the data block is an 8-bit single-channel image, stored LINEAR (verified
by dumping it to PNG -- no Xbox 360 tiling).  Dimensions come from the TX2D
fetch constant: dword[9] holds (width-1) in bits 0..12 and (height-1) in 13..25.

Glyph rows sit on a fixed grid: tv1 = 1 + CELL*k, tv2 = tv1 + CELL - 1.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from .xpr import XprPackage

FONT_DATA = "FontData"
FONT_TEX = "FontTexture"
VERSION = 5
GLYPH_SIZE = 16


@dataclass
class Glyph:
    tu1: int
    tv1: int
    tu2: int
    tv2: int
    off: int
    width: int
    advance: int
    mask: int = 0

    def pack(self) -> bytes:
        return struct.pack(">8H", self.tu1, self.tv1, self.tu2, self.tv2,
                           self.off, self.width, self.advance, self.mask)


class PwsfFont:
    def __init__(self, pkg: XprPackage):
        self.pkg = pkg
        fd = bytes(pkg.blob(FONT_DATA))
        self.version, = struct.unpack_from(">I", fd, 0)
        if self.version != VERSION:
            raise ValueError(f"FontData version {self.version}, expected {VERSION}")
        self.metrics = list(struct.unpack_from(">4I", fd, 4))
        self.max_glyph, = struct.unpack_from(">H", fd, 20)

        n = self.max_glyph + 1
        self.translator = list(struct.unpack_from(f">{n}H", fd, 22))

        p = 2 * n
        self.num_glyphs, = struct.unpack_from(">I", fd, p + 22)
        self._gap = fd[22 + 2 * n:p + 22]  # the 22-byte overlap region, kept verbatim
        g = p + 26
        self.glyphs = [Glyph(*struct.unpack_from(">8H", fd, g + GLYPH_SIZE * i))
                       for i in range(self.num_glyphs)]
        self._tail = fd[g + GLYPH_SIZE * self.num_glyphs:]

        tx = bytes(pkg.blob(FONT_TEX))
        size, = struct.unpack_from(">I", tx, 36)
        self.width = (size & 0x1FFF) + 1
        self.height = ((size >> 13) & 0x1FFF) + 1
        if self.width * self.height != len(pkg.data):
            raise ValueError(f"atlas {self.width}x{self.height} != "
                             f"{len(pkg.data)} bytes of data")
        self.atlas = Image.frombytes("L", (self.width, self.height), bytes(pkg.data))

    # ---------------------------------------------------------------- layout

    @property
    def cell(self) -> int:
        """Row pitch, derived from the shipped glyphs rather than assumed."""
        return max(g.tv2 - g.tv1 for g in self.glyphs) + 1

    def used_rows(self) -> int:
        """Number of occupied rows on the tv1 = 1 + cell*k grid."""
        return max((g.tv2 - 1) // self.cell for g in self.glyphs) + 1

    def free_rows(self) -> int:
        first_free_top = 1 + self.cell * self.used_rows()
        return max(0, (self.height - first_free_top) // self.cell)

    def row_top(self, k: int) -> int:
        return 1 + self.cell * k

    # ---------------------------------------------------------------- edit

    def add_glyph(self, bitmap: Image.Image, advance: int, cursor: list) -> int:
        """Blit `bitmap` into free atlas space and append a GLYPH_ATTR.

        `cursor` is a mutable [row, x] pair so a batch of calls packs densely.
        Returns the new glyph index.
        """
        w, h = bitmap.size
        if h > self.cell:
            raise ValueError(f"glyph {w}x{h} taller than the {self.cell}px cell")
        row, x = cursor
        if x + w > self.width:
            row, x = row + 1, 0
        if row >= self.height // self.cell:
            raise ValueError("atlas full")
        top = self.row_top(row)
        if top + self.cell > self.height:
            raise ValueError("atlas full")

        self.atlas.paste(bitmap, (x, top))
        self.glyphs.append(Glyph(tu1=x, tv1=top, tu2=x + w, tv2=top + self.cell - 1,
                                 off=0, width=w, advance=advance))
        cursor[0], cursor[1] = row, x + w + 1
        return len(self.glyphs) - 1

    def map_char(self, codepoint: int, glyph_index: int) -> None:
        if codepoint > self.max_glyph:
            raise ValueError(f"U+{codepoint:04X} exceeds cMaxGlyph "
                             f"U+{self.max_glyph:04X}")
        self.translator[codepoint] = glyph_index

    def coverage(self) -> set:
        return {c for c, g in enumerate(self.translator) if g}

    # ---------------------------------------------------------------- build

    def font_data_bytes(self) -> bytes:
        n = self.max_glyph + 1
        out = bytearray()
        out += struct.pack(">I", self.version)
        out += struct.pack(">4I", *self.metrics)
        out += struct.pack(">H", self.max_glyph)
        out += struct.pack(f">{n}H", *self.translator)
        out += self._gap
        out += struct.pack(">I", len(self.glyphs))
        for g in self.glyphs:
            out += g.pack()
        out += self._tail
        return bytes(out)

    def flush(self) -> None:
        """Push the model back into the package (FontData + atlas)."""
        self.pkg.replace_tail_resource(FONT_DATA, self.font_data_bytes())
        self.pkg.data = bytearray(self.atlas.tobytes())

    def save(self, path) -> int:
        self.flush()
        return self.pkg.save(path)

    @classmethod
    def load(cls, path) -> "PwsfFont":
        return cls(XprPackage.load(path))

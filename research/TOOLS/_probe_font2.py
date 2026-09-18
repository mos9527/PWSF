"""Probe: FONT/*.xpr = XPR2 package holding an Xbox 360 ATG-style font.

Layout, read straight off the two loaders:

  xpr_package_load @ 0x140042630
      +0   'XPR2'  (BE dword 0x58505232, checked against 1481658930)
      +4   u32 BE header_size
      +8   u32 BE data_size
      header block and data block follow, both decrypted with the SAME
      continuous MT keystream as the 12-byte prologue (name_hash(stem))
      header[0]      = u32 BE resource count
      header[4...]   = directory, 24 B/entry:
                         +0  u32 BE type tag ('TX2D' / 'USER')
                         +4  u32 BE offset into the HEADER block
                         +8  u32 BE size
                         +16 u32 BE offset of the name string (header block)
                                    (fixed up in place to a pointer; the loader
                                     byte-swaps only the low dword of the qword)

  font_load_xpr @ 0x140042C60 looks up two resources by name:
      "FontTexture"  -> D3D texture header (texels live in the data block)
      "FontData"     -> everything below, all big-endian:
          +0   u32 version, must be 5
          +4   u32 x4          (font metrics, kept at font+96..+108)
          +20  u16 cMaxGlyph   (highest character code in the translator table)
          +22  u16[cMaxGlyph+1] translator: char code -> glyph index
          then at p = FontData + 2*(cMaxGlyph+1):
          p+22 u32 num_glyphs
          p+26 GLYPH_ATTR[num_glyphs], 16 B each = 8 x u16
               (tu1, tv1, tu2, tv2, offset, width, advance, mask)
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")

XPR2 = 0x58505232


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def be16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def cstr(b, o):
    end = b.find(b"\x00", o)
    return b[o:end].decode("ascii", "replace")


def ranges(codes):
    """Collapse a sorted list of ints into contiguous [lo, hi] runs."""
    out = []
    for c in codes:
        if out and c == out[-1][1] + 1:
            out[-1][1] = c
        else:
            out.append([c, c])
    return out


def dump(f: Path) -> None:
    data = bytes(buffer_xor_decrypt(bytearray(f.read_bytes()), name_hash(f.stem)))
    assert be32(data, 0) == XPR2, f"{f.name}: bad magic {data[:4]!r}"
    hdr_size, dat_size = be32(data, 4), be32(data, 8)
    assert 12 + hdr_size + dat_size == len(data), f"{f.name}: size mismatch"

    header = data[12:12 + hdr_size]
    count = be32(header, 0)
    print(f"=== {f.name}  header={hdr_size:#x} data={dat_size:#x} resources={count}")

    res = {}
    for i in range(count):
        e = 4 + 24 * i
        tag = struct.pack(">I", be32(header, e)).decode("ascii", "replace")
        off, size = be32(header, e + 4), be32(header, e + 8)
        name = cstr(header, be32(header, e + 16))
        res[name] = off
        print(f"    [{i}] {name:<16} tag={tag} off={off:#x} size={size:#x}")

    if "FontData" not in res:
        print("    (no FontData)\n")
        return

    p = res["FontData"]
    version = be32(header, p)
    max_glyph = be16(header, p + 20)
    tbl = p + 22
    q = p + 2 * (max_glyph + 1)
    num_glyphs = be32(header, q + 22)
    glyphs = q + 26

    print(f"    FontData: version={version} cMaxGlyph={max_glyph:#x} "
          f"num_glyphs={num_glyphs}")
    print(f"    metrics dwords: " + " ".join(f"{be32(header, p + 4 + 4 * i):#010x}"
                                             for i in range(4)))
    print(f"    translator table {2 * (max_glyph + 1)} B, "
          f"glyph array {16 * num_glyphs} B, "
          f"ends at {glyphs + 16 * num_glyphs:#x} of {hdr_size:#x}")

    mapped = [c for c in range(max_glyph + 1) if be16(header, tbl + 2 * c) != 0]
    print(f"    mapped codes: {len(mapped)}")
    rs = ranges(mapped)
    print(f"    code ranges ({len(rs)}):")
    for lo, hi in rs[:24]:
        print(f"        U+{lo:04X}..U+{hi:04X}  ({hi - lo + 1})")
    if len(rs) > 24:
        print(f"        ... {len(rs) - 24} more")

    cjk = [c for c in mapped if 0x4E00 <= c <= 0x9FFF]
    kana = [c for c in mapped if 0x3040 <= c <= 0x30FF]
    print(f"    CJK ideographs U+4E00..U+9FFF: {len(cjk)}")
    print(f"    kana U+3040..U+30FF:           {len(kana)}")

    g = glyphs
    print("    first 4 GLYPH_ATTR:")
    for i in range(min(4, num_glyphs)):
        vals = struct.unpack_from(">8H", header, g + 16 * i)
        print(f"        [{i}] tu1={vals[0]} tv1={vals[1]} tu2={vals[2]} tv2={vals[3]} "
              f"off={vals[4]} w={vals[5]} adv={vals[6]} mask={vals[7]:#06x}")

    # Atlas occupancy: how far down the sheet do the glyphs actually reach?
    attrs = [struct.unpack_from(">8H", header, g + 16 * i) for i in range(num_glyphs)]
    max_u, max_v = max(a[2] for a in attrs), max(a[3] for a in attrs)
    row_h = max(a[3] - a[1] for a in attrs)
    masks = {a[7] for a in attrs}
    print(f"    atlas reach: tu2_max={max_u} tv2_max={max_v} "
          f"tallest_glyph={row_h}px masks={sorted(masks)}")

    # TX2D header (52 B) as raw dwords -- texture dimensions live here.
    tx = res["FontTexture"]
    print("    TX2D header dwords: " + " ".join(f"{be32(header, tx + 4 * i):#010x}"
                                                for i in range(13)))
    print()


def main() -> None:
    for f in sorted((GAME / "FONT").glob("*.xpr")):
        dump(f)


if __name__ == "__main__":
    main()

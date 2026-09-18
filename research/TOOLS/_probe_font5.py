"""Probe: XPR2 / FontData round-trip must be byte-identical.

Loads each shipped font, rebuilds it without touching anything, and compares
against the original file on disk -- both the decrypted plaintext and the
re-encrypted bytes.  Nothing else in the font pipeline is trustworthy until
this passes.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt
from pwsf_font import PwsfFont
from pwsf_xpr import XprPackage

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")


def check(stem: str) -> bool:
    src = GAME / "FONT" / f"{stem}.xpr"
    raw = src.read_bytes()
    plain = bytes(buffer_xor_decrypt(bytearray(raw), name_hash(stem)))

    pkg = XprPackage.parse(plain)
    ok_container = pkg.build() == plain

    font = PwsfFont(XprPackage.parse(plain))
    ok_fontdata = font.font_data_bytes() == bytes(
        XprPackage.parse(plain).blob("FontData"))
    font.flush()
    ok_full = font.pkg.build() == plain

    cipher = bytes(buffer_xor_decrypt(bytearray(font.pkg.build()), name_hash(stem)))
    ok_cipher = cipher == raw

    print(f"{stem}:")
    print(f"  atlas {font.width}x{font.height}  cell={font.cell}px  "
          f"glyphs={len(font.glyphs)}  cMaxGlyph={font.max_glyph:#x}")
    print(f"  rows used={font.used_rows()} free={font.free_rows()} "
          f"(first free top y={font.row_top(font.used_rows())})")
    print(f"  container round-trip : {'OK' if ok_container else 'FAIL'}")
    print(f"  FontData round-trip  : {'OK' if ok_fontdata else 'FAIL'}")
    print(f"  full rebuild         : {'OK' if ok_full else 'FAIL'}")
    print(f"  re-encrypt == on disk: {'OK' if ok_cipher else 'FAIL'}")

    # what a CJK glyph looks like, so the PoC can match its size
    for cp in (0x4E00, 0x6B66, 0x30A2, 0x0041):
        gi = font.translator[cp] if cp <= font.max_glyph else 0
        if gi:
            g = font.glyphs[gi]
            print(f"  U+{cp:04X} glyph[{gi}] box=({g.tu1},{g.tv1})-({g.tu2},{g.tv2}) "
                  f"w={g.width} adv={g.advance} off={g.off}")
    print()
    return ok_container and ok_fontdata and ok_full and ok_cipher


def main() -> None:
    results = [check("0007ccd8"), check("000ebbe8")]
    if not all(results):
        raise SystemExit(1)
    print("all round-trips byte-identical")


if __name__ == "__main__":
    main()

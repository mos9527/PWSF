"""Probe: does the shipped font cover the shipped text, code point for code point?

This is the decisive test for "does the game resolve glyphs by Unicode code
point?".  font_glyph_rect_for_char @ 0x140043B10 indexes translator[u16], so if
the engine fed it raw UTF-8 bytes instead of decoded code points, the shipped
non-ASCII text could not render.  Therefore: decode every olang string as UTF-8,
collect the code points, and intersect with the translator tables of the two
shipped fonts.  Near-total coverage proves the decode step exists.
"""

import struct
import sys
import unicodedata
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ANALYSIS = Path(__file__).resolve().parent.parent / "ANALYSIS"


def be32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def be16(b, o):
    return struct.unpack_from(">H", b, o)[0]


def font_coverage(stem: str) -> set:
    """Set of code points with a non-zero translator entry."""
    f = GAME / "FONT" / f"{stem}.xpr"
    data = bytes(buffer_xor_decrypt(bytearray(f.read_bytes()), name_hash(f.stem)))
    hdr = data[12:12 + be32(data, 4)]
    fd = None
    for i in range(be32(hdr, 0)):
        e = 4 + 24 * i
        end = hdr.find(b"\x00", be32(hdr, e + 16))
        if hdr[be32(hdr, e + 16):end] == b"FontData":
            fd = be32(hdr, e + 4)
    assert fd is not None
    max_glyph = be16(hdr, fd + 20)
    tbl = fd + 22
    return {c for c in range(max_glyph + 1) if be16(hdr, tbl + 2 * c)}


def unesc(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\"}.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def main() -> None:
    large = font_coverage("0007ccd8")
    small = font_coverage("000ebbe8")
    both = large | small
    print(f"font coverage: large={len(large)} small={len(small)} union={len(both)}")

    per_lang = {}
    rows = 0
    for line in (ANALYSIS / "_dump_olang.tsv").read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        rows += 1
        lang, text = parts[4], unesc(parts[6])
        per_lang.setdefault(lang, Counter()).update(text)

    print(f"\nolang rows scanned: {rows}\n")
    print(f"{'lang':<6} {'chars':>7} {'distinct':>9} {'missing':>8}  {'in large':>9} {'in small':>9}")
    all_missing = Counter()
    for lang in sorted(per_lang):
        cnt = per_lang[lang]
        distinct = set(ord(c) for c in cnt if c not in "\n\r\t")
        miss = {c for c in distinct if c not in both}
        for c in miss:
            all_missing[c] += sum(v for k, v in cnt.items() if ord(k) == c)
        total = sum(v for k, v in cnt.items() if k not in "\n\r\t")
        print(f"{lang:<6} {total:>7} {len(distinct):>9} {len(miss):>8}  "
              f"{len(distinct & large):>9} {len(distinct & small):>9}")

    print(f"\nmissing code points overall: {len(all_missing)}")
    for cp, n in all_missing.most_common(20):
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            name = "?"
        print(f"    U+{cp:04X} {chr(cp)!r:<8} x{n:<6} {name}")

    cjk_have = len([c for c in both if 0x4E00 <= c <= 0x9FFF])
    print(f"\nCJK ideographs already in the fonts: {cjk_have}")

    # Total distinct code points across EVERY extracted text source, per language.
    # The Japanese figure is the best available proxy for how many glyphs a
    # Chinese translation of the same content would need.
    sources = [
        ("_dump_olang.tsv", 4, 6),
        ("subtitle_ingame.tsv", 5, 7),
        ("_briefing_lines.tsv", 1, 10),
    ]
    totals = {}
    for name, lang_col, text_col in sources:
        p = ANALYSIS / name
        if not p.exists():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
            parts = line.split("\t")
            if len(parts) <= text_col:
                continue
            if i == 0 and parts[text_col] == "text":
                continue
            totals.setdefault(parts[lang_col], set()).update(
                ord(c) for c in unesc(parts[text_col]) if c not in "\n\r\t")

    print("\ndistinct code points across all extracted text:")
    for lang in sorted(totals):
        s = totals[lang]
        han = len([c for c in s if 0x4E00 <= c <= 0x9FFF])
        print(f"    {lang:<4} {len(s):>5} distinct  ({han} ideographs, "
              f"{len(s - both)} not in the shipped fonts)")

    # Falsify the "engine indexes raw UTF-8 bytes" hypothesis: under that model
    # every multi-byte character needs glyphs at its continuation byte values
    # (0x80..0xBF).  If the fonts have none of those, byte indexing is impossible.
    cont = {c for c in both if 0x80 <= c <= 0xBF}
    print(f"\nglyphs in the UTF-8 continuation-byte range U+0080..U+00BF: "
          f"{len(cont)} {sorted(cont)}")
    need_cont = set()
    for lang in ("de", "es", "fr", "it"):
        for cp in totals.get(lang, ()):
            if cp > 0x7F:
                need_cont.update(b for b in chr(cp).encode("utf-8")[1:])
    print(f"continuation bytes the EU text would need under that model: "
          f"{len(need_cont)} (e.g. {sorted(need_cont)[:8]})")
    print(f"of those, present in the fonts: {len(need_cont & both)}")


if __name__ == "__main__":
    main()

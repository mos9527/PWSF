"""_probe_font10.py — 小字体 `000ebbe8.xpr` 到底装得下多少汉字。

05_font.md §6.5 推翻了「g_font_index 恒为 0」的结论，`g_font_small` 是可达的，
但 §12.2 只给了纸面估算（2048x1024 -> 15 行 x 34 = 510 槽），而且 §7 第 2 条
「小字体不参与查找」的错误结论至今还写在 config.FONT_SMALL 的注释里。

本探针在实机文件上实测：

1. 两个字体的 metrics / cell / 行数 / 容量，确认小字体的格子是否也是 67px
2. TX2D 头里那个决定图集尺寸的常量（决定能不能扩图集）
3. 当前 .po 语料用到的码点，小字体差多少
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config                                    # noqa: E402
from pwsf.font import PwsfFont                             # noqa: E402
from pwsf.font_build import CELL_W, WHITESPACE             # noqa: E402

config.require_game()


def describe(stem: str, wanted: set = None) -> PwsfFont:
    src = config.pristine(config.FONT_DIR / f"{stem}.xpr")
    f = PwsfFont.load(src)
    floats = [struct.unpack(">f", struct.pack(">I", m))[0] for m in f.metrics]
    cov = f.coverage()
    cjk = [c for c in cov if 0x3400 <= c <= 0x9FFF]
    per_row = f.width // (CELL_W + 1)

    print(f"\n=== {stem}.xpr  ({src.stat().st_size:,} B) ===")
    print(f"  metrics       {[hex(m) for m in f.metrics]} -> {floats}")
    print(f"  cMaxGlyph     U+{f.max_glyph:04X}    num_glyphs {f.num_glyphs}")
    print(f"  covered       {len(cov)} code points (CJK {len(cjk)})")
    print(f"  atlas         {f.width} x {f.height}  cell {f.cell}")
    print(f"  rows          {f.rows()} total, {f.used_rows()} used, "
          f"{f.free_rows()} free")
    print(f"  full-width    {per_row}/row -> capacity {f.rows() * per_row}, "
          f"free-row capacity {f.free_rows() * per_row}")

    tx = bytes(f.pkg.blob("FontTexture"))
    print(f"  FontTexture   {len(tx)} B: " + " ".join(
        f"+{4*i}:{struct.unpack_from('>I', tx, 4*i)[0]:08X}"
        for i in range(len(tx) // 4)))

    if wanted:
        need = wanted - WHITESPACE
        missing = sorted(need - cov)
        over = [c for c in missing if c > f.max_glyph]
        print(f"  corpus needs  {len(need)} code points; missing here: "
              f"{len(missing)} (over cMaxGlyph: {len(over)})")
        by_cp = {c: f.glyphs[g].width for c, g in enumerate(f.translator) if g}
        by_cp.update({c: CELL_W for c in missing})
        row, x = 0, 0
        for c in sorted(by_cp):
            w = by_cp[c]
            if x + w > f.width:
                row, x = row + 1, 0
            x += w + 1
        print(f"  full rebuild  would need {row + 1} rows of {f.rows()}")
    return f


# corpus: every code point the current translations use
from pwsf import po_lint                                   # noqa: E402
rep = po_lint.lint(check_font=False)
codepoints = {ord(c) for t in rep.translations.values() for c in t}
print(f"corpus: {len(rep.translations)} translated strings, "
      f"{len(codepoints)} distinct code points")

large = describe(config.FONT_LARGE, codepoints)
small = describe(config.FONT_SMALL, codepoints)

# --- 语料按来源分组：假如小字体只服务一小撮界面，那撮文本的字符集有多大
print("\n=== 语料按来源分组 ===")
print(f"  sample refs: {list(rep.translations)[:3]}")
fam = {}
for ref, text in rep.translations.items():
    parts = ref.split("/")
    key = "/".join(parts[:2]) if len(parts) > 2 else "/".join(parts[:1])
    g = fam.setdefault(key, dict(strings=0, cps=set()))
    g["strings"] += 1
    g["cps"].update(ord(c) for c in text if c not in WHITESPACE)
for key in sorted(fam):
    g = fam[key]
    cjk = [c for c in g["cps"] if 0x3400 <= c <= 0x9FFF]
    print(f"  {key:26} {g['strings']:6} strings  {len(g['cps']):5} code points  "
          f"{len(cjk):5} CJK")

by_family = {}
for key, g in fam.items():
    e = by_family.setdefault(key.split("/")[0], dict(strings=0, cps=set()))
    e["strings"] += g["strings"]
    e["cps"] |= g["cps"]
print("  --- 按族汇总 ---")
for f in sorted(by_family):
    e = by_family[f]
    cjk = [c for c in e["cps"] if 0x3400 <= c <= 0x9FFF]
    print(f"  {f:8} {e['strings']:6} strings  {len(e['cps']):5} code points  "
          f"{len(cjk):5} CJK")

# 若小字体只服务少数几个界面，那几个界面的并集有多大？按表从小到大贪心累加
order = sorted(((len(g["cps"]), k) for k, g in fam.items() if "/" in k))
acc, seen = set(), []
print("  --- 若小字体只服务 k 个最小的表：累计需要多少字形 ---")
for i, (_n, key) in enumerate(order[:15], 1):
    acc |= fam[key]["cps"]
    seen.append(key)
    print(f"  k={i:2}  {len(acc):5} code points "
          f"({len([c for c in acc if 0x3400 <= c <= 0x9FFF]):5} CJK)   + {key}")

print("\n=== 交集 ===")
both = large.coverage() & small.coverage()
print(f"  large {len(large.coverage())}  small {len(small.coverage())}  "
      f"both {len(both)}  small-only "
      f"{len(small.coverage() - large.coverage())}  large-only "
      f"{len(large.coverage() - small.coverage())}")

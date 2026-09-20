"""_probe_font13.py — 哪些 olang 文本走那张 512x512 像素字图集。

RenderDoc 那边解出来的那行是 `PRESS[   ]BUTTON`（eventId 317，14 个 quad，
中间 3 个格位留给按键图标），它正是

    MLG/Text/005184e3.olang  槽 0xfb5d7b  flags 0x1   "PRESS START BUTTON"

而 flags 0x402 是普通 UI 文本（§13.6 那批）。看起来 **olang 槽位的 flags 就是
字体选择器**：0x1 -> `Text/*.txp` 里那张像素字图集，0x402 -> FONT/*.xpr。
本探针按 flags 把语料分开，量一量"像素字体那批"到底有多大。
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def scan(path: Path, idx_lang: int, idx_flags: int, idx_text: int,
         sep: str = "\t") -> dict:
    """en rows only, grouped by flags -> (count, code points)."""
    out = {}
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split(sep)
            if len(f) <= idx_text:
                continue
            if f[idx_lang] != "en":
                continue
            try:
                flags = int(f[idx_flags], 16)
            except ValueError:
                continue
            g = out.setdefault(flags, dict(n=0, cps=set(), sample=[]))
            g["n"] += 1
            g["cps"].update(ord(c) for c in f[idx_text] if not c.isspace())
            if len(g["sample"]) < 25:
                g["sample"].append(f[idx_text][:70])
    return out


def report(title: str, data: dict) -> None:
    print(f"\n=== {title} ===")
    for flags in sorted(data):
        g = data[flags]
        cps = g["cps"]
        cjk = [c for c in cps if 0x3400 <= c <= 0x9FFF]
        print(f"  flags {flags:#06x}  {g['n']:6} en strings  "
              f"{len(cps):5} code points  {len(cjk):5} CJK")


def main() -> None:
    ol = scan(ROOT / "ANALYSIS" / "_dump_olang.tsv", 4, 5, 6)
    sl = scan(ROOT / "ANALYSIS" / "_slot_olang_lines.tsv", 1, 4, 7)
    report("_dump_olang.tsv", ol)
    report("_slot_olang_lines.tsv", sl)

    one = ol.get(1)
    if one:
        print(f"\npixel-font strings (flags 0x1): {one['n']}")
        print(f"  distinct code points: {len(one['cps'])}")
        print(f"  ascii-only: "
              f"{all(c < 0x100 for c in one['cps'])}")
        for s in one["sample"][:25]:
            print(f"    {s}")
    if 1 in sl:
        g = sl[1]
        print(f"\nSLOT.DAT pixel-font strings (flags 0x1): {g['n']}, "
              f"{len(g['cps'])} code points")
        for s in g["sample"][:15]:
            print(f"    {s}")


if __name__ == "__main__":
    main()

"""语料翻译覆盖率盘点：区分「没翻」和「没提取」。

实机看到漏翻时，第一件事是判断这条到底在不在语料里：
在语料里 msgstr 为空 = 还没翻；不在语料里 = 提取/过滤的覆盖缺口。
本探针按子目录统计条目数、未译条目数，并可反查一句英文在不在语料里。

    python research\\TOOLS\\_probe_pocov.py              # 各目录覆盖率
    python research\\TOOLS\\_probe_pocov.py --find "recovery point"
    python research\\TOOLS\\_probe_pocov.py --untranslated codec   # 列出未译条目
"""
import argparse
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config  # noqa: E402

def po_files(root: Path):
    return sorted(root.glob("*/*.po"))


def _field(block: str, key: str) -> str:
    """取出 msgid / msgstr 的拼接值（支持多行 gettext 形式）。"""
    out = []
    on = False
    for ln in block.splitlines():
        if ln.startswith(key + " "):
            on = True
            out.append(ln[len(key) + 1:].strip())
        elif on and ln.startswith('"'):
            out.append(ln.strip())
        elif on:
            break
    val = "".join(out)
    return val[1:-1] if val.startswith('"') and val.endswith('"') else val


def entries(text: str):
    """yield (msgid, msgstr_raw) —— 空行分隔的 entry 块。"""
    for block in text.split("\n\n"):
        if "msgid " not in block:
            continue
        yield _field(block, "msgid"), _field(block, "msgstr")


def untranslated(text: str):
    """msgstr 没有任何内容（含多行形式）。"""
    for msgid, msgstr in entries(text):
        if not msgstr:
            yield msgid


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--find", metavar="TEXT", help="在语料里反查一句英文")
    ap.add_argument("--untranslated", metavar="DIR", help="列出某子目录的未译条目")
    args = ap.parse_args()

    root = config.PO_DIR
    files = po_files(root)

    if args.find:
        pat = args.find.lower()
        hits = []
        for f in files:
            text = f.read_text(encoding="utf-8")
            for msgid, msgstr in entries(text):
                if pat in msgid.lower():
                    hits.append((f, msgid, msgstr))
        print(f"命中 {len(hits)} 条：")
        for f, msgid, tr in hits[:50]:
            print(f"  {f.relative_to(root)}\n    msgid  {msgid!r}\n    msgstr {tr!r}")
        return 0

    if args.untranslated:
        total = 0
        for f in files:
            if f.parent.name != args.untranslated:
                continue
            for msgid in untranslated(f.read_text(encoding="utf-8")):
                total += 1
                print(f"  {f.name}: {msgid[:90]!r}")
        print(f"-- {args.untranslated} 未译 {total} 条")
        return 0

    agg = {}
    for f in files:
        d = f.parent.name
        text = f.read_text(encoding="utf-8")
        n = sum(1 for _ in entries(text))
        e = sum(1 for _ in untranslated(text))
        a, b = agg.get(d, (0, 0))
        agg[d] = (a + n, b + e)
    print(f"{'目录':<8}{'条目':>8}{'未译':>8}{'覆盖率':>10}")
    tn = te = 0
    for d in sorted(agg):
        n, e = agg[d]
        tn += n
        te += e
        print(f"{d:<8}{n:>8}{e:>8}{(n - e) * 100 // max(n, 1):>9}%")
    print(f"{'合计':<8}{tn:>8}{te:>8}{(tn - te) * 100 // max(tn, 1):>9}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

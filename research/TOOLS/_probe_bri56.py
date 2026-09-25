"""codec 语料覆盖缺口盘点：到底有哪些「游戏在显示、语料里没有」的行。

动机（2026-09-25 实机）：少量 briefing 台词漏翻（保持英文）、个别整段空白。

「哪些表项是台词」现在由池的排布规则回答（03 号文档 §10.6，`n_text`），
不再靠启发式；本探针负责盘点这条判据切完之后还剩哪些覆盖缺口 ——
语种误标、空行、以及真台词里夹着非法 UTF-8 导致写不了的那几行。

    python research\\TOOLS\\_probe_bri56.py            # 盘点 + 抽样
    python research\\TOOLS\\_probe_bri56.py --all      # 全量列出被过滤行
"""
import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config                      # noqa: E402
from pwsf.po_export import _codec_wrong_lang  # noqa: E402

# 一句话像不像真台词：全是可见 ASCII、有空格、够长
_WORD = re.compile(r"[A-Za-z]")


def looks_real(text: str) -> bool:
    """像不像真台词：忽略夹带的乱码字符，只看 ASCII 部分像不像英文句子。"""
    ascii_part = "".join(ch for ch in text if ch.isascii() and ch.isprintable())
    body = ascii_part.replace("\\n", " ").strip()
    return len(body) >= 12 and len(_WORD.findall(body)) >= 8 and " " in body


def show(text: str) -> str:
    """一律转义打印 —— Windows 控制台（GBK）打不出 U+FFFD 之类。"""
    return text.encode("unicode_escape").decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="列出全部被过滤行")
    ap.add_argument("--sample", type=int, default=40)
    args = ap.parse_args()

    rows = config.BRIEFING_TSV.read_text(encoding="utf-8").splitlines()
    head = rows[0].split("\t")
    col = {n: i for i, n in enumerate(head)}
    skip_rec = _codec_wrong_lang(rows[1:], col)

    stat = Counter()
    kept = 0
    by_reason = defaultdict(list)
    rec_with_blanked = set()
    rec_total = set()

    for r in rows[1:]:
        c = r.split("\t")
        if len(c) <= col["text"] or c[col["lang"]] != "en":
            continue
        key = (c[col["group"]], c[col["off"]])
        rec_total.add(key)
        text = c[col["text"]]
        ref = (f"codec/{c[col['group']]}/{c[col['sector']]}/"
               f"{c[col['off']]}/{c[col['line']]}")
        if key in skip_rec:
            stat["drop:wrong-lang"] += 1
            by_reason["wrong-lang"].append((ref, text))
            continue
        if not text.strip():
            stat["drop:empty"] += 1
            by_reason["empty"].append((ref, text))
            continue
        if int(c[col["line"]]) >= int(c[col["n_text"]]):
            stat["drop:non-text"] += 1      # 表项指进池后的二进制块
            by_reason["non-text"].append((ref, text))
            rec_with_blanked.add(key)   # 写回时 display_lines 会清空它们
            continue
        if "\ufffd" in text:
            stat["drop:ufffd"] += 1    # 真台词但夹非法字节，写回无法无损
            by_reason["ufffd"].append((ref, text))
            continue
        kept += 1

    print(f"en 行总数        : {kept + sum(stat.values())}")
    print(f"进语料           : {kept}")
    for k in sorted(stat):
        print(f"{k:<16} : {stat[k]}")
    print(f"en 记录数        : {len(rec_total)}")
    print(f"含非台词表项(写回会被清空)的记录  : {len(rec_with_blanked)}")

    print("\n== 抽样（各原因前若干条原样）==")
    for reason, items in sorted(by_reason.items()):
        print(f"-- {reason} ({len(items)})")
        for ref, text in (items if args.all else items[:8]):
            print(f"  {ref}\n    {show(text)}")

    print("\n== 各原因里「像真台词」的行数（误杀嫌疑）==")
    for reason, items in sorted(by_reason.items()):
        suspicious = [x for x in items if looks_real(x[1])]
        print(f"{reason:<12}: {len(suspicious)} / {len(items)}")
        if not suspicious:
            continue
        shown = suspicious if args.all else suspicious[:args.sample]
        for ref, text in shown:
            print(f"  {ref}\n    {show(text)}")
        if not args.all and len(suspicious) > args.sample:
            print(f"  ... 其余 {len(suspicious) - args.sample} 条加 --all")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

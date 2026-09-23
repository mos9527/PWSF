"""证据：SLOT.DAT 每个资源池里有没有【可读英文】。

`_probe_resclass.py` 报出 16 个类别，其中只有 `0x5d`(RBX) 和 `0x1c`(GTT)
被现有管线当语料。本脚本不预设格式：对每个池的字节做 ASCII 长串扫描，
按类别统计「像句子的串」（>=24 个可打印字符且含 >=3 个空格），并把去重后
的串与已提取语料比对 —— 出现在池里、但不在任何 `_*.tsv` 里的，就是漏网文本。

用法（仓库根）：
    python research\\TOOLS\\_probe_pooltext.py                 # 全量
    python research\\TOOLS\\_probe_pooltext.py --class 0x5e     # 只看 FEL
    python research\\TOOLS\\_probe_pooltext.py --dump-all       # 把串落盘
"""
from __future__ import annotations

import argparse
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pwsf import slotdat as S          # noqa: E402

RUN = re.compile(rb"[ -~]{24,}")


def looks_like_sentence(s: bytes) -> bool:
    if s.count(b" ") < 3:
        return False
    letters = sum(1 for c in s if 65 <= c <= 90 or 97 <= c <= 122)
    return letters >= len(s) * 0.7


def corpus_texts() -> set:
    """所有已提取 TSV 里的文本（用于判断「漏网」）。"""
    out = set()
    for name in ("_dump_olang.tsv", "_slot_olang_lines.tsv", "_cutscene_lines.tsv",
                 "_gtt_lines.tsv", "_briefing_lines.tsv", "_stage_olang_lines.tsv",
                 "subtitle_ingame.tsv"):
        p = ROOT / "research" / "ANALYSIS" / name
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                out.add(line.rstrip("\n").split("\t")[-1].strip())
    return out


def scan(cls_want: int | None = None, dump_all: bool = False,
         verbose: bool = True):
    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    per_class = defaultdict(Counter)        # cls -> Counter(text)
    where = {}                              # text -> (cls, pool id, record)
    t0 = time.time()
    for n, rec in enumerate(recs):
        try:
            pools = S.pools(rec, ks)
        except Exception:                   # noqa: BLE001
            continue
        for eid, _off, blob in pools:
            cls = (eid & 0x7F000000) >> 24
            if cls_want is not None and cls != cls_want:
                continue
            for m in RUN.finditer(blob):
                s = m.group()
                if not looks_like_sentence(s):
                    continue
                txt = s.decode("ascii")
                per_class[cls][txt] += 1
                where.setdefault(txt, (cls, eid, rec.index))
        if verbose and n and n % 400 == 0:
            print(f"  ... {n}/{len(recs)}", flush=True)

    known = corpus_texts()
    print(f"scanned {len(recs)} records in {time.time() - t0:.1f}s")
    print(f"{'class':>6} {'strings':>8} {'distinct':>9} {'new?':>7}  sample")
    total_new = Counter()
    for cls, cnt in sorted(per_class.items()):
        new = [t for t in cnt if t not in known]
        total_new[cls] = len(new)
        sample = (new or list(cnt))[:1]
        print(f"{cls:#04x} {sum(cnt.values()):8d} {len(cnt):9d} "
              f"{len(new):7d}  {(sample[0][:70] if sample else '')}")

    out = ROOT / "research" / "BUILD" / "_pooltext_new.tsv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        fh.write("class\tpool\trecord\ttext\n")
        for cls, cnt in sorted(per_class.items()):
            pool = Counter()
            for t in cnt:
                if t in known and not dump_all:
                    continue
                c, eid, rec = where[t]
                pool[t] = cnt[t]
                fh.write(f"{c:#04x}\t{eid:#010x}\t{rec}\t{t}\n")
    print(f"\nwrote {sum(total_new.values())} new (or all, with --dump-all) "
          f"strings -> {out}")
    if dump_all:
        for cls, cnt in sorted(per_class.items()):
            print(f"  {cls:#04x}: {len(cnt)} distinct")
    return per_class


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--class", dest="cls", default=None)
    ap.add_argument("--dump-all", action="store_true")
    args = ap.parse_args()
    want = int(args.cls, 0) if args.cls else None
    scan(want, args.dump_all)


if __name__ == "__main__":
    main()

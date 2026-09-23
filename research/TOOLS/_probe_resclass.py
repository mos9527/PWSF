"""证据：SLOT.DAT 资源池【全类别】普查。

已提取的语料只认两类：
  * `0x20??????` = RBX 文本表（`slotdat_find_res_entry` 的过滤器，也是
    `slotdat.embedded_olang` 唯一处理的）
  * `0x1c??????` = GTT 池（ANALYSIS/11）
`11_gtt_text.md` §2 还提到第三类 `0x5e??????`（FEL），从来没普查过。

本脚本不预设类别：把每条记录的每个 live 资源条目按 `(id & 0x7F000000)`
归类，报出每类的 id 数 / 记录数，并对每个 id 记下前 16 字节（用于识别
魔数）。任何不是 0x20 / 0x1c 的类 = 可能漏掉的语料。

用法（仓库根）：
    python research\\TOOLS\\_probe_resclass.py
    python research\\TOOLS\\_probe_resclass.py --limit 200
    python research\\TOOLS\\_probe_resclass.py --class 0x5e   # 只看某一类
"""
from __future__ import annotations

import argparse
import struct
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pwsf import slotdat as S          # noqa: E402


def printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def census(limit: int = 0, want: int | None = None, verbose: bool = True):
    recs = S.load_index()
    if limit:
        recs = recs[:limit]
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)

    by_class = Counter()                  # cls -> pool entries
    ids = defaultdict(set)                # cls -> {pool id}
    recs_of = defaultdict(set)            # cls -> {record index}
    head = {}                             # pool id -> (record, first bytes)
    failed = []
    t0 = time.time()
    for n, rec in enumerate(recs):
        try:
            pools = S.pools(rec, ks)
        except Exception as exc:          # noqa: BLE001
            failed.append((rec.index, str(exc)))
            continue
        for eid, _off, blob in pools:
            cls = (eid & 0x7F000000) >> 24
            by_class[cls] += 1
            ids[cls].add(eid)
            recs_of[cls].add(rec.index)
            if eid not in head:
                head[eid] = (rec.index, blob[:16])
        if verbose and n and n % 200 == 0:
            print(f"  ... {n}/{len(recs)} records", flush=True)
    dt = time.time() - t0

    print(f"{len(recs)} records scanned in {dt:.1f}s, {len(failed)} failed")
    print(f"{'class':>8} {'entries':>8} {'ids':>6} {'records':>8}  sample head")
    for cls, n in sorted(by_class.items()):
        if want is not None and cls != want:
            continue
        sample = sorted(ids[cls])[0]
        rec_i, h = head[sample]
        print(f"{cls:#04x}({cls:#x}) {n:8d} {len(ids[cls]):6d} "
              f"{len(recs_of[cls]):8d}  id {sample:#010x} rec {rec_i} "
              f"{h.hex()}  |{printable(h)}|")
    if want is not None:
        print(f"\n-- detail: class {want:#x}, {len(ids[want])} ids --")
        for eid in sorted(ids[want])[:200]:
            rec_i, h = head[eid]
            print(f"  {eid:#010x} rec {rec_i:5d} {h.hex()} |{printable(h)}|")
    return by_class


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--class", dest="cls", default=None,
                    help="e.g. 0x5e -- only dump this class in detail")
    args = ap.parse_args()
    want = int(args.cls, 0) if args.cls else None
    census(args.limit, want)


if __name__ == "__main__":
    main()

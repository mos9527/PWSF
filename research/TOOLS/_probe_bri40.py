"""_probe_bri40.py —— 记录块的自然断层检验（语言归属）

判据：若文件按语言分块存放，则
  * 同一块内相邻记录首尾相接（间隙小）；
  * 块与块之间有大的填充间隙；
  * 各块的记录数应接近相等（每种语言一份）。

用法： python _probe_bri40.py
"""
import collections
import re
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")


def main():
    br = load(DAT)
    recs = br.records
    print(f"记录 {len(recs)}  扇区 {len(br.data)//SECTOR}")

    # --- 1. 相邻记录的字节跨度（记录起点 -> 下一条记录起点） ---
    print("\n[1] 相邻记录跨度分布（跨度 = 下一条记录起点 - 本记录起点）")
    spans = []
    for a, b in zip(recs, recs[1:]):
        spans.append((b.off - a.off, a.off, b.off))
    spans.sort(reverse=True)
    print("  最大 20 个跨度：")
    for sp, o1, o2 in spans[:20]:
        print(f"    {sp:#8x}  {o1:#x} -> {o2:#x}   "
              f"sec {o1//SECTOR} -> {o2//SECTOR}")

    # --- 2. 用大跨度切块 ---
    print("\n[2] 以跨度 > 0x10000 为界切块")
    cuts = [i + 1 for i, (sp, _, _) in enumerate(
        (x, 0, 0) for x in [])]  # placeholder
    cuts = [i + 1 for i in range(len(recs) - 1)
            if recs[i + 1].off - recs[i].off > 0x10000]
    bounds = [0] + cuts + [len(recs)]
    blocks = []
    for i in range(len(bounds) - 1):
        lo, hi = bounds[i], bounds[i + 1]
        grp = recs[lo:hi]
        sc = collections.Counter(r.script_class() for r in grp)
        blocks.append((grp[0].off, grp[-1].off, hi - lo, dict(sc)))
    for k, (o1, o2, n, sc) in enumerate(blocks):
        print(f"  块{k:2d}  sec{o1//SECTOR:4d}-{o2//SECTOR:4d}  "
              f"off {o1:#7x}-{o2:#7x}  记录 {n:4d}  {sc}")

    # --- 3. 每个扇区的记录数（找空扇区 / 稀疏带）---
    print("\n[3] 每扇区记录数（只列 0 或 <3 的稀疏扇区，用于定位块边界填充）")
    per = collections.Counter(r.sector for r in recs)
    sparse = [s for s in range(len(br.data) // SECTOR) if per.get(s, 0) < 3]
    runs, start, prev = [], None, None
    for s in sparse:
        if start is None:
            start = prev = s
        elif s == prev + 1:
            prev = s
        else:
            runs.append((start, prev))
            start = prev = s
    if start is not None:
        runs.append((start, prev))
    for a, b in runs:
        if b - a >= 0:
            print(f"    sec {a:4d}-{b:4d}  ({b-a+1} 个扇区，每扇区 <3 条记录)")

    # --- 4. 共享语音 ID 的跨块文本对照（决定性判据）---
    print("\n[4] 共享语音 ID 的跨块文本对照")
    vid2rec = collections.defaultdict(list)
    for i, r in enumerate(recs):
        for v in set(r.voice_ids(br.data)):
            vid2rec[v].append(i)
    multi = {v: idxs for v, idxs in vid2rec.items() if len(idxs) > 1}
    print(f"  共 {len(vid2rec)} 个语音 ID，其中 {len(multi)} 个出现在多条记录")
    shown = 0
    for v, idxs in sorted(multi.items()):
        # 只看跨越"大跨度切点"的
        blks = {next(i for i in range(len(bounds) - 1)
                     if bounds[i] <= x < bounds[i + 1]) for x in idxs}
        if len(blks) < 2:
            continue
        print(f"\n  == {v}   记录 {idxs}   块 {sorted(blks)}")
        for i in idxs:
            r = recs[i]
            print(f"    [{i}] sec{r.sector} cls={r.script_class()} "
                  f"n={r.n_lines}")
            for t in r.lines[:3]:
                print(f"        {t[:70]}")
        shown += 1
        if shown >= 6:
            break
    if not shown:
        print("  （没有语音 ID 同时出现在两个块中）")

    # --- 5. 台词文本完全重复的记录（同文多语言？不，同文即同语言）---
    print("\n[5] 首行文本重复情况")
    first = collections.Counter(r.lines[0] for r in recs if r.lines)
    dup = [(t, c) for t, c in first.items() if c > 1]
    print(f"  首行唯一 {len(first)} / 记录 {len(recs)}；重复的 {len(dup)} 组")
    for t, c in sorted(dup, key=lambda x: -x[1])[:5]:
        print(f"    x{c}  {t[:70]}")


if __name__ == "__main__":
    sys.exit(main())

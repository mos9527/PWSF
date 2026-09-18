"""Probe: 用「语音 ID 是语言无关锚点」实证语言分段，取代启发式猜测。

可证伪的判据
------------
若 0076531d.DAT 把同一段 CODEC 按语言各存一份，则：
  1. 同一个 voice ID 应出现在多个「扇区段」的记录里；
  2. 这些记录的台词条数、脚本长度应当一致（同源副本）；
  3. 各段内 voice ID 的集合应高度重叠（近乎相同），而不是互不相交。
反之若 voice ID 各段互不相交 -> 分段不是语言，另有含义。
"""
import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_briefing as B

br = B.load(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
            r"\MLG\disc0_rel\0076531d.DAT")
D = br.data

# 观测到的扇区段边界（来自台词内容观感，本脚本负责证伪/证实）
SEG = [("ja", 0, 147), ("en", 148, 287), ("fr", 288, 439), ("de", 440, 590),
       ("it", 591, 735), ("es", 736, 894), ("x2", 895, 1011)]


def seg_of(sec):
    for name, a, b in SEG:
        if a <= sec <= b:
            return name
    return "?"


for r in br.records:
    seg = D[r.script_off:min(len(D), r.script_off + 16384)]
    r.vids = sorted({m.decode("ascii", "replace")
                     for m in re.findall(rb"[a-z]_[a-z]{3}_[A-Za-z0-9_]{6,}", seg)})
    r.seg = seg_of(r.sector)

print(f"记录 {len(br.records)}；有语音 ID 的记录 "
      f"{sum(1 for r in br.records if r.vids)}")

# 1) 每个段的 voice ID 集合
byseg = collections.defaultdict(set)
for r in br.records:
    byseg[r.seg].update(r.vids)
print("\n=== 各段 voice ID 集合 ===")
for name, _, _ in SEG:
    s = byseg[name]
    print(f"  {name}: {len(s)} 个")

# 2) 段间重叠（Jaccard）
names = [n for n, _, _ in SEG]
print("\n=== 段间 voice ID 集合 |交集| / Jaccard ===")
print("        " + "".join(f"{n:>12}" for n in names))
for a in names:
    row = f"  {a:>5} "
    for b in names:
        i = len(byseg[a] & byseg[b])
        u = len(byseg[a] | byseg[b]) or 1
        row += f"{i:>6}/{i / u:5.2f}"
    print(row)

# 3) 同一 voice ID 出现在几个段里
cnt = collections.Counter()
for v in set().union(*byseg.values()):
    cnt[sum(1 for n in names if v in byseg[n])] += 1
print("\n=== voice ID 出现在多少个段里 ===")
for k in sorted(cnt):
    print(f"  出现在 {k} 个段: {cnt[k]} 个 ID")

# 4) 具体对齐示例：ja 段前 5 条记录的 voice ID，去其它段找同名
print("\n=== 对齐示例：ja 段前 6 条记录在其它段的同名副本 ===")
ja = [r for r in br.records if r.seg == "ja"][:6]
for r in ja:
    print(f"\n ja rec off={r.off:#x} sec={r.sector} n={r.n_lines} "
          f"vids={r.vids[:2]}")
    for v in r.vids[:2]:
        hits = [(x.seg, x.sector, x.off, x.n_lines)
                for x in br.records if v in x.vids]
        for s, sec, off, n in hits:
            if s != "ja":
                print(f"     vid={v:<26} -> {s} sec={sec:<5} off={off:#x} n={n}")

# 5) 同源副本的一致性：台词条数是否相同
print("\n=== 同源副本台词条数一致性（抽样 200 个跨段共享的 voice ID）===")
shared = [v for v in set().union(*byseg.values())
          if sum(1 for n in names if v in byseg[n]) >= 3][:200]
ok = bad = 0
for v in shared:
    ns = {x.n_lines for x in br.records if v in x.vids}
    if len(ns) == 1:
        ok += 1
    else:
        bad += 1
print(f"  跨段共享 voice ID {len(shared)} 个：条数完全一致 {ok}，不一致 {bad}")

# 6) 段内开头记录的头部逐字节对比（找语言字段）
print("\n=== 各段第一条记录头 32 字节 ===")
seen = {}
for r in br.records:
    if r.seg not in seen and r.vids:
        seen[r.seg] = r
for name, _, _ in SEG:
    r = seen.get(name)
    if not r:
        continue
    h = D[r.off:r.off + 32]
    print(f"  {name} sec={r.sector:<5} off={r.off:#08x}: "
          + " ".join(f"{b:02x}" for b in h))

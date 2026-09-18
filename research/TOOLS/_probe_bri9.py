"""Probe: 记录元数据（id24 / flags）与语言、分组的关系。"""
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_briefing as B

br = B.load(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
            r"\MLG\disc0_rel\0076531d.DAT")
print(f"记录 {len(br.records)}  台词 {sum(r.n_lines for r in br.records)}")
bad = [r for r in br.records if r.problems]
print("异常记录：", len(bad))
for r in bad[:10]:
    print(f"   {r.off:#x} {r.problems}")

print("\n前 30 条：")
print(f"{'off':>8} {'sec':>5} {'idx':>6} {'id24':>8} {'flg':>4} {'n':>3}  lang  first")
for r in br.records[:30]:
    print(f"{r.off:8x} {r.sector:5} {r.idx:6} {r.id24:8x} {r.flags:4} "
          f"{r.n_lines:3}  {r.script_class():4}  {r.lines[0][:44]!r}")

print("\nflags 取值分布：", dict(collections.Counter(r.flags for r in br.records)))
print("id24 唯一值：", len({r.id24 for r in br.records}), "/", len(br.records))

# id24 是否按扇区递增？
inc = sum(1 for a, b in zip(br.records, br.records[1:]) if b.id24 > a.id24)
print(f"id24 相邻递增：{inc}/{len(br.records) - 1}")

# 语言 × flags 交叉表
print("\nflags × lang：")
ct = collections.Counter((r.flags, r.script_class()) for r in br.records)
for flg in sorted({k[0] for k in ct}):
    row = {lg: n for (f, lg), n in ct.items() if f == flg}
    print(f"  flags={flg:<4} {dict(sorted(row.items(), key=lambda x: -x[1]))}")

# 同一扇区内记录的 id24 是否连续
print("\n扇区 0 / 1 / 500 / 1010 内的记录：")
for sec in (0, 1, 500, 1010):
    rs = [r for r in br.records if r.sector == sec]
    print(f"  扇区 {sec}: " + ", ".join(f"{r.id24:x}/{r.flags}" for r in rs))

# 语音 ID
import re
pat = re.compile(rb"[a-z]_[a-z]{3}_[a-z0-9_]{4,}")
hits = collections.Counter()
for r in br.records:
    lo, hi = r.script_off, min(len(br.data), r.script_off + 8192)
    for m in pat.finditer(br.data[lo:hi]):
        hits[m.group().decode()] += 1
print(f"\n脚本区语音 ID（前 20，共 {len(hits)} 种）：")
for k, v in list(hits.most_common(20)):
    print(f"   {k:<28} {v}")

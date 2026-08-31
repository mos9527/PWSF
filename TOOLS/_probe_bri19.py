"""_probe_bri19 —— 检验「语言 = 连续扇区段」假说。

判据（全部为客观事实，不做猜测）：
  1. 逐扇区的记录数 / kana 记录数 / latin 记录数
  2. 按 script_class 的连续同构区间切段
  3. 各段的：记录数、台词总数、语音 ID 集合大小
  4. 段间语音 ID 的 Jaccard（u32 化后比较，避免 str 开销）
"""
import collections

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records
print(f"记录 {len(recs)}  扇区 {len(br.data)//SECTOR}  台词 {sum(r.n_lines for r in recs)}")

# ---- 1. 逐扇区统计 ----
per = collections.defaultdict(collections.Counter)
for r in recs:
    per[r.sector][r.script_class()] += 1
sectors = sorted(per)
print(f"有记录的扇区 {len(sectors)}  范围 {sectors[0]}..{sectors[-1]}")


def sig(c):
    k, l = c["kana"], c["latin"]
    if k and not l:
        return "kana"
    if l and not k:
        return "latin"
    if k and l:
        return "MIX"
    return "-"


# ---- 2. 连续同构区间 ----
segs, cur = [], [sectors[0]]
for s in sectors[1:]:
    if sig(per[s]) != sig(per[cur[-1]]) and s == cur[-1] + 1:
        segs.append(cur)
        cur = [s]
    else:
        cur.append(s)
segs.append(cur)

print("\n=== 同构扇区区间 ===")
for i, g in enumerate(segs):
    c = collections.Counter()
    n = 0
    for s in g:
        c.update(per[s])
        n += sum(per[s].values())
    print(f"[{i}] 扇区 {g[0]:4d}..{g[-1]:4d} ({len(g):4d} 个)  "
          f"记录 {n:5d}  kana {c['kana']:4d} latin {c['latin']:4d} "
          f"- {c['-']:3d}  -> {sig(c)}")

# ---- 3/4. 按「合并相邻同类区间」后的段做统计 ----
merged = []
for g in segs:
    s = sig(per[g[0]])
    if merged and merged[-1][0] == s and g[0] == merged[-1][2] + 1:
        merged[-1][2] = g[-1]
        merged[-1][1].extend(g)
    else:
        merged.append([s, list(g), g[-1]])

print("\n=== 合并后的大段 ===")
vids = {}
for i, (s, g, _) in enumerate(merged):
    rs = [r for r in recs if r.sector in set(g)]
    vs = set()
    for r in rs:
        vs.update(r.voice_ids(br.data))
    vids[i] = vs
    print(f"[{i}] 扇区 {g[0]:4d}..{g[-1]:4d}  记录 {len(rs):5d}  "
          f"台词 {sum(r.n_lines for r in rs):6d}  语音ID {len(vs):4d}  {s}")

print("\n=== 段间语音 ID Jaccard ===")
ks = sorted(vids)
print("      " + "".join(f"{j:>8d}" for j in ks))
for i in ks:
    row = []
    for j in ks:
        a, b = vids[i], vids[j]
        row.append(len(a & b) / len(a | b) if (a | b) else 0.0)
    print(f"[{i:>2d}]  " + "".join(f"{v:8.3f}" for v in row))

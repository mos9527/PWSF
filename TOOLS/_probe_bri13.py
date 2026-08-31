"""诊断：为什么部分记录的台词解出乱码？以 0x15dfb0 为例。"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_briefing as B

br = B.load(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
            r"\MLG\disc0_rel\0076531d.DAT")
D = br.data
u32 = lambda o: struct.unpack_from("<I", D, o)[0]


def dump(a1, note=""):
    print(f"\n{'=' * 78}\n记录 a1={a1:#x}  sector={a1 // 4096}  "
          f"扇区内偏移={a1 % 4096:#x}  {note}")
    print("头 32 字节: " + " ".join(f"{b:02x}" for b in D[a1:a1 + 32]))
    v5 = 0
    v10 = a1 + 12 + 8 * v5
    o0, o1, o2, o3 = (u32(v10), u32(v10 + 4), u32(v10 + 8), u32(v10 + 12))
    v11 = v10 + o0
    p1, p2, p3 = v10 + o1, v10 + o2, v10 + o3
    print(f"  v10={v10:#x}  off=({o0}, {o1}, {o2}, {o3})")
    print(f"  v11(脚本)={v11:#x}  v3[1](偏移表)={p1:#x}  "
          f"v3[2](文本池)={p2:#x}  v3[3]={p3:#x}")
    cnt = (p2 - p1) // 4
    print(f"  按 (v3[2]-v3[1])/4 推出的串数 n = {cnt}")
    print(f"  位置参照：本扇区末={(a1 // 4096 + 1) * 4096:#x}  "
          f"下扇区起点={(a1 // 4096 + 1) * 4096:#x}")
    print(f"\n  偏移表（{p1:#x} .. {p2:#x}）:")
    for i in range(cnt):
        v = u32(p1 + 4 * i)
        q = p2 + v
        raw = D[q:q + 40]
        try:
            s = raw.split(b"\x00")[0].decode("utf-8")
            ok = "OK "
            show = s[:46]
        except UnicodeDecodeError as e:
            ok = f"BAD@{e.start}"
            show = repr(raw[:24])
        print(f"    [{i:3}] off={v:<7} -> {q:#x}  {ok:8} {show}")
    # 文本池结尾在哪？看 p3 / v11 / 下一个魔数
    nxt = D.find(B.REC_MAGIC, p2)
    print(f"\n  文本池起点 p2={p2:#x}")
    print(f"  v3[3]={p3:#x}   v11={v11:#x}   "
          f"下一个记录魔数位置={nxt if nxt < 0 else hex(nxt)}")


dump(0x15DFB0, "<<< 用户报告的问题记录")

# 统计：全文件有多少记录的台词不可解码
bad_recs = []
for r in br.records:
    nbad = 0
    for t in r.lines:
        # 还原原始字节再判断（lines 已用 replace 解码，改用 replacement char 判定）
        if "\ufffd" in t:
            nbad += 1
    if nbad:
        bad_recs.append((r, nbad))
print(f"\n\n{'=' * 78}\n含不可解码台词的记录：{len(bad_recs)} / {len(br.records)}")
tot_bad = sum(n for _, n in bad_recs)
print(f"不可解码台词行：{tot_bad} / {sum(r.n_lines for r in br.records)}")
for r, n in bad_recs[:15]:
    print(f"  {r.off:#x} sec={r.sector:<5} 扇区内={r.off % 4096:#6x} "
          f"n={r.n_lines:<4} 坏={n:<4} 首行={r.lines[0][:40]!r}")

# 坏行是否集中在"尾部"？
print("\n坏行在记录中的位置分布（行号 / 该记录总行数）：")
import collections
pos = collections.Counter()
for r, _ in bad_recs:
    for i, t in enumerate(r.lines):
        if "\ufffd" in t:
            pos["尾部" if i >= r.n_lines - 2 else "中前部"] += 1
print("  ", dict(pos))

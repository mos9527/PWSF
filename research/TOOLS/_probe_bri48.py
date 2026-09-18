"""_probe_bri48.py —— 脚本字节码 0x6d 指令的参数结构 + 语音 ID ↔ 台词逐行对应

已知（IDA 取证）
--------------
* ``sub_1400A4770``（操作数解码）：``op & 0xF`` 为 0..12 时即长度，
  13/14/15 分别表示后随 u8 / u16 / u24 长度。
* ``sub_1400A35C0``（解释器）按 ``op & 0xF0`` 分派：
  - ``0x30``：``v22 = sub_1400A4770(a1,&len); acc = sub_14013CD90(v22)``
    （sub_14013CD90 实证为 **RPN 表达式求值器**，见其 decompile）
  - ``0x60``：``v17 = sub_1400A4770(a1,&len)``；``id = u24@v17``；
    在 ``qword_141103DF0`` 处理器表里按 id 查函数；
    实参由 ``sub_1400A53D0(v17+3, &arglen)`` 构造 -> 调用
  - ``0x70``：调子程序
* 因此 ``0x6d`` = op 0x60 + u8 长度；payload 布局：
  ``[u24 id][args...]``，args 起点 = payload+3。

本轮要回答
----------
1. 一条记录的脚本里有多少条 ``0x6d``，其数量是否等于台词条数 n_lines？
2. ``0x6d`` 的 args 里哪个字节随行号递增（0 起）？
3. args 里其余字段是什么（时间轴？说话人？镜头？）—— 通过「同一记录内
   逐条比对 + 跨记录统计」找变化/恒定字段。
"""
import collections
import struct
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")


def decode_operand(buf, i):
    """sub_1400A4770：返回 (长度, 操作数体起点)"""
    lo = buf[i] & 0x0F
    if lo == 13:
        return buf[i + 1], i + 2
    if lo == 14:
        return struct.unpack_from("<H", buf, i + 1)[0], i + 3
    if lo == 15:
        return (buf[i + 1] | buf[i + 2] << 8 | buf[i + 3] << 16), i + 4
    return lo, i + 1


def walk(data, start, end):
    """从 start 起按 sub_1400A4770 逐条走字节码，返回指令列表。"""
    out = []
    i = start
    while i < end:
        op = data[i]
        hi = op & 0xF0
        if hi == 0:
            break
        ln, body = decode_operand(data, i)
        if ln == 0 or body + ln > end:
            break
        payload = data[body:body + ln]
        out.append((i, op, ln, payload))
        i = body + ln
    return out


def main():
    br = load(DAT)
    recs = br.records

    # --- 1. 各 opcode 出现次数 ---
    ops = collections.Counter()
    for r in recs:
        for i, op, ln, p in walk(br.data, r.script_off, r.script_end(br.data)):
            ops[op] += 1
    print("[1] 脚本区 opcode 频次（top 20）")
    for op, c in ops.most_common(20):
        print(f"    {op:#04x}  hi={op & 0xF0:#04x} lo={op & 0x0F:2d}  {c:6d}")

    # --- 2. 0x6d 指令条数 vs 台词条数 ---
    print("\n[2] 0x6d 条数 vs 台词条数（前 12 条记录）")
    print(f"    {'rec':>5s} {'sec':>5s} {'n_lines':>7s} {'0x6d':>5s}  "
          f"{'ids':>10s}  {'len分布':>16s}")
    stats = []
    for ri, r in enumerate(recs):
        ins = walk(br.data, r.script_off, r.script_end(br.data))
        sixd = [x for x in ins if x[1] == 0x6D]
        if not sixd:
            continue
        ids = {p[0] | p[1] << 8 | p[2] << 16 for _, _, _, p in sixd if len(p) >= 3}
        lens = collections.Counter(x[2] for x in sixd)
        stats.append((ri, r, sixd, ids, lens))
    for ri, r, sixd, ids, lens in stats[:12]:
        print(f"    {ri:5d} {r.sector:5d} {r.n_lines:7d} {len(sixd):5d}  "
              f"{len(ids):10d}  {dict(lens.most_common(3))}")
    eq = sum(1 for ri, r, sixd, _, _ in stats if len(sixd) == r.n_lines)
    print(f"\n    0x6d 条数 == 台词条数：{eq} / {len(stats)}")

    # --- 3. 0x6d 的 args 字段扫描 ---
    print("\n[3] 0x6d 的 payload 逐字节扫描（args = payload[3:]）")
    for ri, r, sixd, ids, lens in stats[:3]:
        print(f"\n    记录 {ri}  sec{r.sector}  台词 {r.n_lines}  "
              f"0x6d {len(sixd)}  id(s) {[hex(x) for x in list(ids)[:3]]}")
        for k, (off, op, ln, p) in enumerate(sixd[:6]):
            args = p[3:]
            print(f"      [{k}] off={off:#x} len={ln} id={p[0]|p[1]<<8|p[2]<<16:#08x} "
                  f"args({len(args)})={args.hex(' ')}")

    # 找随行号递增的字节位置
    print("\n[4] args 中『等于行号 k』的字节位置统计")
    pos = collections.defaultdict(collections.Counter)
    nrec = 0
    for ri, r, sixd, ids, lens in stats:
        if len(sixd) != r.n_lines or r.n_lines < 3:
            continue
        nrec += 1
        for k, (off, op, ln, p) in enumerate(sixd):
            args = p[3:]
            for j, b in enumerate(args):
                pos[j][b == k] += 1
    print(f"    参与统计的记录 {nrec} 条")
    rank = sorted(pos.items(),
                  key=lambda kv: -(kv[1][True] / max(1, sum(kv[1].values()))))
    for j, c in rank[:8]:
        tot = sum(c.values())
        print(f"      args[{j:2d}]  命中 {c[True]:5d}/{tot:5d} "
              f"= {c[True]*100//tot:3d}%")

    # --- 5. 恒定字段 ---
    print("\n[5] args 中『跨记录恒定』的字节位置（用于判时间轴/标志）")
    const = collections.defaultdict(collections.Counter)
    for ri, r, sixd, ids, lens in stats:
        for off, op, ln, p in sixd:
            args = p[3:]
            for j, b in enumerate(args):
                const[j][b] += 1
    for j in sorted(const):
        c = const[j]
        top, n = c.most_common(1)[0]
        print(f"      args[{j:2d}]  众数 {top:#04x} 占 {n*100//sum(c.values()):3d}%  "
              f"取值数 {len(c)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""_probe_bri50.py —— briefing_insn_decode 的 case 0x10/0x20 长度规则（取证）

背景
----
``pwsf/briefing.py`` 的 ``_decode`` 把 ``op & 0xF0 == 0x10/0x20`` 当成 **1 字节**
保守处理，PLANS/03 §2 因此记着"CODEC 回写卡在 case 0x10/0x20"。本探针从
IDA 取回真实规则并做全文件实证。

IDA 证据（`briefing_insn_decode` @ 0x1400A4B40，反编译 + 汇编核对）
------------------------------------------------------------------
跳转表 ``jpt_1400A4D7C``（switch on ``op & 0xF0``）：

    1400a4d7e  cases 16,32      -> sub_1400A3AB0(v3, a2, &v21)
    1400a4eee  case 48  (0x30)  -> RPN 表达式
    1400a4da6  case 64  (0x40)  -> 局部槽读取
    1400a4f6d  case 80  (0x50)  -> 带长度载荷
    1400a4e87  case 128 (0x80)  -> 包裹（0x8d/0x8e）
    1400a4e4d  case 144 (0x90)  -> 全局槽读取
    def_1400A4BC4  default      -> 含 **0x60 / 0x70**，rax = rbx = a1（不前进）

``sub_1400A3AB0`` @ 0x1400A3AB0（case 0x10/0x20 的长度来源）：

    v4 = u32 LE @ a1                     <- 4 字节定长头
    *a2 = (v4 >> 24) & 0xF               <- 操作数类型
    v8  = a1 + 4
    if ((v4 >> 24) & 0xF0) == 0x20:      <- 即 a1[3] & 0xF0 == 0x20
        v8 = insn_decode(insn_decode(a1+4))    两个嵌套操作数
    sub_1400A4210(handler, v4, v12, a3)
    return v8

故 **0x1x / 0x2x = 4 字节定长头；当 a1[3] & 0xF0 == 0x20 时后面再跟两条
``briefing_insn_decode`` 能解的操作数**。v5（u16 @ a1+2）只用于查处理函数表
（0x800000 -> off_140EA4860，0x100000 -> unk_14117A530，否则 off_140EA4880），
与长度无关。

另一个决定性事实（本次一并取得）
--------------------------------
``briefing_script_run`` @ 0x1400A35C0 的**主循环只用**
``briefing_insn_operand`` @ 0x1400A4770 推进，且只处理
``op & 0xF0 ∈ {0, 0x30, 0x60, 0x70}``：

    v2 = *a1 & 0xF0
    if (!v2) return 0;                 // hi==0 终止
    if (v2 == 0x30) { ...; a1 = &v22[v24]; }
    if (v2 == 0x60) { ...; a1 = &v17[v24]; }
    if (v2 == 0x70) { ...; a1 = &v3[v24]; }
    // 其余（0x10/0x20/0x40/0x50/0x80/0x90）落到 LABEL_25，a1 不变 -> 死循环

即 **解释器顶层流里根本不存在 0x1x/0x2x/0x8x**；``briefing_insn_decode`` 是给
**表达式区 / 实参区**（0x30 的 RPN、0x70 的实参、0x6e 的 args）用的，那里
反过来**不存在 0x6x/0x7x**（它们走 default 会不前进）。

本探针要回答的两件事
--------------------
[1] 现有 walker 走出来的流里，0x1x/0x2x 到底出现了多少次？（0 次 = 这个卡点
    对提取/回写实际没有影响）
[2] 换成 IDA 真实规则后，遍历结果是否变化？
"""
import collections
import struct
import sys

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

WRAP = {0x8D, 0x8E, 0x6E, 0x6F, 0x7A, 0x87}


# ---------------------------------------------------------------- 解码器 A：现状
def decode_old(data, i, end):
    """pwsf/briefing.py::_decode（0x10/0x20 按 1 字节保守处理）。"""
    op = data[i]
    if op & 0xC0 == 0xC0:
        return i + 1, i + 1, 0
    hi = op & 0xF0
    if hi:
        if hi in (0x30, 0x50, 0x60, 0x70, 0x80):
            lo = op & 0x0F
            if lo == 13 and i + 1 < end:
                n, p = data[i + 1], i + 2
            elif lo == 14 and i + 2 < end:
                n, p = struct.unpack_from("<H", data, i + 1)[0], i + 3
            elif lo == 15 and i + 3 < end:
                n = data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16
                p = i + 4
            else:
                n, p = lo, i + 1
            return p, p + n, n
        if hi == 0x40:
            return i + 1, i + 2 if (op & 0x0F) == 0x0F else i + 1, 0
        return i + 1, i + 1, 0          # 0x10 / 0x20 / 0x90 / 其它
    if op == 0:
        return i + 1, i, 0
    if op in (1, 14):
        return i + 1, i + 3, 0
    if op in (2, 3, 4):
        return i + 1, i + 2, 0
    if op in (6, 8):
        return i + 1, i + 4, 0
    if op == 7:
        n = data[i + 1] if i + 1 < end else 0
        return i + 2, i + 2 + n, n
    if op in (9, 10, 13):
        return i + 1, i + 5, 0
    if op == 15:
        return i + 1, i + 9, 0
    return i + 1, i + 1, 0


# ------------------------------------------------- 解码器 B：IDA 真实规则（含 0x10/0x20）
def decode_ida(data, i, end, depth=0):
    """逐字照抄 0x1400A4B40 + 0x1400A3AB0。

    返回 (载荷起点, 下一条, 载荷长度)。``下一条 == i`` 表示该 opcode 会让
    ``briefing_insn_decode`` **不前进**（0x60/0x70 等 default 分支）。
    """
    op = data[i]
    if op & 0xC0 == 0xC0:
        return i + 1, i + 1, 0
    hi = op & 0xF0
    if hi:
        if hi in (0x10, 0x20):                     # sub_1400A3AB0
            if i + 4 > end:
                return i + 1, i + 1, 0
            nxt = i + 4
            if (data[i + 3] & 0xF0) == 0x20 and depth < 4:
                _, j, _ = decode_ida(data, nxt, end, depth + 1)
                _, j, _ = decode_ida(data, j, end, depth + 1)
                nxt = j
            return i + 4, nxt, 0
        if hi in (0x30, 0x50, 0x80):
            lo = op & 0x0F
            if lo == 13 and i + 1 < end:
                n, p = data[i + 1], i + 2
            elif lo == 14 and i + 2 < end:
                n, p = struct.unpack_from("<H", data, i + 1)[0], i + 3
            elif lo == 15 and i + 3 < end:
                n = data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16
                p = i + 4
            else:
                n, p = lo, i + 1
            return p, p + n, n
        if hi == 0x40:
            return i + 1, i + 2 if (op & 0x0F) == 0x0F else i + 1, 0
        if hi == 0x90:
            return i + 1, i + 1, 0
        return i + 1, i, 0                         # 0x60 / 0x70 / 其它：不前进
    if op == 0:
        return i + 1, i, 0
    if op in (1, 14):
        return i + 1, i + 3, 0
    if op in (2, 3, 4):
        return i + 1, i + 2, 0
    if op in (6, 8):
        return i + 1, i + 4, 0
    if op == 7:
        n = data[i + 1] if i + 1 < end else 0
        return i + 2, i + 2 + n, n
    if op in (9, 10, 13):
        return i + 1, i + 5, 0
    if op == 15:
        return i + 1, i + 9, 0
    return i + 1, i + 1, 0


def walk(data, start, end, dec, maxdepth=8):
    out, stall = [], 0
    stack = [(start, end, 0)]
    while stack:
        a, b, d = stack.pop()
        i = a
        while i < b:
            body, nxt, ln = dec(data, i, b)
            if nxt <= i:
                stall += 1
                break
            if body > b:
                break
            if body + ln > b:
                ln = b - body
            nxt = min(nxt, b)
            out.append((i, data[i], ln, body, d))
            if data[i] in WRAP and d < maxdepth and ln > 0:
                stack.append((body, body + ln, d + 1))
            i = nxt
    return out, stall


def main():
    br = load(DAT)
    data, recs = br.data, br.records
    print(f"记录 {len(recs)} 条")

    ops_old = collections.Counter()
    ops_ida = collections.Counter()
    n_old = n_ida = 0
    stall_recs = 0
    end_hits_old = end_hits_ida = 0
    sixd_old = sixd_ida = 0
    diff_recs = []

    for r in recs:
        a = r.entry_off if r.entry_off > 0 else r.script_off
        b = r.script_end(data)
        if not (0 <= a < b <= len(data)):
            continue
        o, _ = walk(data, a, b, decode_old)
        n_, st = walk(data, a, b, decode_ida)
        for i, op, ln, body, d in o:
            ops_old[op] += 1
        for i, op, ln, body, d in n_:
            ops_ida[op] += 1
        n_old += len(o)
        n_ida += len(n_)
        if st:
            stall_recs += 1
        sixd_old += sum(1 for x in o if x[1] == 0x6D)
        sixd_ida += sum(1 for x in n_ if x[1] == 0x6D)
        if o and o[-1][0] + 1 >= b:
            end_hits_old += 1
        if n_ and n_[-1][0] + 1 >= b:
            end_hits_ida += 1
        if {x[0] for x in o} != {x[0] for x in n_}:
            diff_recs.append(r.off)

    print("\n[1] 现有规则走出的 opcode 频次（top 20）")
    for op, c in ops_old.most_common(20):
        print(f"    {op:#04x}  {c:8d}")
    hit = {op: c for op, c in ops_old.items() if op & 0xF0 in (0x10, 0x20)}
    print(f"\n[2] 现有规则遇到的 0x1x/0x2x：{len(hit)} 种 / {sum(hit.values())} 次")
    for op, c in sorted(hit.items())[:20]:
        print(f"    {op:#04x}  {c}")

    print(f"\n[3] 指令总数  现有 {n_old}   IDA 规则 {n_ida}")
    print(f"    0x6d 数    现有 {sixd_old}   IDA 规则 {sixd_ida}")
    print(f"    走到流末尾  现有 {end_hits_old}   IDA 规则 {end_hits_ida}")
    print(f"    IDA 规则下「不前进」的记录（撞上 0x60/0x70 等 default）："
          f"{stall_recs} / {len(recs)}")
    print(f"    两条规则产生不同指令集合的记录：{len(diff_recs)}")
    for off in diff_recs[:10]:
        print(f"        {off:#x}")

    print("\n[4] IDA 规则走出的 opcode 频次（top 20）")
    for op, c in ops_ida.most_common(20):
        print(f"    {op:#04x}  {c:8d}")

    # ---------------------------------------------------------------- 回写可行性
    print("\n[5] 回写可行性：记录内部布局与碎片")
    slack = []
    for i, r in enumerate(recs):
        nxt = recs[i + 1].off if i + 1 < len(recs) else len(data)
        pool_end = r.v10 + r.off2 + (
            max(r.table) + len(r.lines[-1].encode()) + 1 if r.lines else 0)
        slack.append(nxt - pool_end)
    neg = [s for s in slack if s < 0]
    print(f"    记录结束 -> 下一条记录起点 的空隙：min {min(slack)} "
          f"max {max(slack)}  总 {sum(slack)}")
    print(f"    负值（布局估计越界）的记录：{len(neg)}")
    sizes = [len(r.lines) for r in recs]
    print(f"    台词条数：{sum(sizes)}   pool 占用见下")

    tot_text = sum(len(t.encode()) + 1 for r in recs for t in r.lines)
    print(f"    文本池字节总量：{tot_text}")
    print(f"    文件总大小：{len(data)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

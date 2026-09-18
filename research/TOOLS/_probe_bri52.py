"""_probe_bri52.py —— 分层解码模型：块用解释器规则，实参区用 insn_decode 规则

动机
----
_probe_bri50 证明**单独任何一套解码器都走不通**整段字节码：

* ``briefing_insn_decode``（0x1400A4B40）的 hi 跳转表没有 0x60/0x70 的 case，
  它们落 default 直接返回入参指针。纯用它：2049/2049 条记录不前进。
* ``briefing_script_run``（0x1400A35C0）主循环只用 ``briefing_insn_operand``
  （0x1400A4770）推进，只分发 ``op & 0xF0 ∈ {0x00(终止), 0x30, 0x60, 0x70}``，
  遇到 0x8d/0x8e 会原地打转。

把两边的事实合起来，字节码其实是**两层语法**：

    块（block）  0x8d/0x8e <u8|u16|u24 len> <body>
        body 交给 briefing_script_run：
        briefing_insn_operand 取长度，只处理 0x30 / 0x60 / 0x70，hi==0 结束。

    实参区（args）  0x6x/0x7x <len> [u24 handler id][argc][args...]
        args 由**处理函数**用 briefing_insn_decode 逐条解：
        0x07 字符串字面量、0x1x/0x2x 四字节定长头、0x8x 嵌套块…，
        op==0 结束。

``briefing_script_run`` 的 0x70 分支正好印证了这个分层——它自己就用
``briefing_insn_decode`` 循环解实参：

    for (i = briefing_insn_decode(v3 + 3, &v25, &v27); v25;
         i = briefing_insn_decode(i, &v25, &v27)) { ... v31[v4++] = v27; }

而 0x8e 块头的语义可以从同一函数的 0x70 分支反推：子程序体在 pool 里的
存法是 ``0x8e <u16 len> <body>``，``briefing_insn_operand(pool+off)`` 一下
就跳过 3 字节头，然后把 **body** 交给 briefing_script_run。

本探针实现这个分层模型，并与「现状混合规则」对比。
"""
import collections
import re
import struct
import sys

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

ID_CUE = 0x3B91EB


# ------------------------------------------------- 规则 1：解释器（块 / body）
def operand(data, i, end):
    """briefing_insn_operand @ 0x1400A4770 -> (长度, 载荷起点)。"""
    lo = data[i] & 0x0F
    if lo == 13:
        return data[i + 1], i + 2
    if lo == 14:
        return struct.unpack_from("<H", data, i + 1)[0], i + 3
    if lo == 15:
        return (data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16), i + 4
    return lo, i + 1


def walk_block(data, start, end, out, depth):
    """块体：只认 hi ∈ {0x30, 0x60, 0x70}，hi==0 结束。"""
    i = start
    while i < end:
        hi = data[i] & 0xF0
        if hi == 0:
            return i                                   # 正常终止
        if hi not in (0x30, 0x60, 0x70):
            return -i - 1                              # 负号 = 卡死
        n, body = operand(data, i, end)
        if body > end or body + n > end:
            return -i - 1
        out.append((i, data[i], n, body, depth, "blk"))
        # 实参区起点：0x60 先经过 briefing_call_args_build(0x1400A53D0) 取
        # 一个长度字节（>=0x80 表示「长度在下一字节」），0x70 没有这一字节。
        if hi == 0x60 and n > 4:
            c = data[body + 3]
            if c & 0x80:
                L, p = data[body + 4], body + 5
            else:
                L, p = c, body + 4
            if 0 < L and p + L <= min(body + n, end) and depth < 8:
                walk_args(data, p, p + L, out, depth + 1)
        elif hi == 0x70 and n > 3 and depth < 8:
            walk_args(data, body + 3, body + n, out, depth + 1)
        i = body + n
    return i


# --------------------------------------- 规则 2：insn_decode（实参区 / args）
def walk_args(data, start, end, out, depth):
    """实参区：briefing_insn_decode 的完整规则；0x8x 载荷是嵌套块。"""
    i = start
    while i < end:
        op = data[i]
        if op & 0xC0 == 0xC0:
            i += 1
            continue
        hi = op & 0xF0
        if hi:
            if hi in (0x10, 0x20):
                if i + 4 > end:
                    return -i - 1
                out.append((i, op, 4, i, depth, "arg"))
                nxt = i + 4
                if (data[i + 3] & 0xF0) == 0x20:
                    for _ in range(2):
                        j = _skip(data, nxt, end)
                        if j < 0:
                            return -i - 1
                        nxt = j
                i = nxt
                continue
            if hi in (0x30, 0x50, 0x80):
                lo = op & 0x0F
                if lo == 13:
                    n, p = data[i + 1], i + 2
                elif lo == 14:
                    n, p = struct.unpack_from("<H", data, i + 1)[0], i + 3
                elif lo == 15:
                    n = data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16
                    p = i + 4
                else:
                    n, p = lo, i + 1
                if p > end or p + n > end:
                    return -i - 1
                out.append((i, op, n, p, depth, "arg"))
                if hi == 0x80 and n > 0 and depth < 8:
                    walk_block(data, p, p + n, out, depth + 1)
                i = p + n
                continue
            if hi == 0x40:
                i += 2 if (op & 0x0F) == 0x0F else 1
                continue
            if hi == 0x90:
                i += 1
                continue
            return -i - 1                              # 0x60/0x70：不前进
        # hi == 0：低操作码表
        if op == 0:
            return i                                   # 终止
        if op in (1, 14):
            i += 3
        elif op in (2, 3, 4):
            i += 2
        elif op in (6, 8):
            i += 4
        elif op == 7:
            n = data[i + 1] if i + 1 < end else 0
            out.append((i, op, n, i + 2, depth, "arg"))
            i += 2 + n
        elif op in (9, 10, 13):
            i += 5
        elif op == 15:
            i += 9
        else:
            i += 1
        if i > end:
            return -i - 1
    return i


def _skip(data, i, end):
    """解一条 insn_decode 指令并返回下一条（供 0x10/0x20 的嵌套操作数用）。"""
    op = data[i]
    if op & 0xC0 == 0xC0:
        return i + 1
    hi = op & 0xF0
    if hi:
        if hi in (0x30, 0x50, 0x80):
            lo = op & 0x0F
            if lo == 13:
                n, p = data[i + 1], i + 2
            elif lo == 14:
                n, p = struct.unpack_from("<H", data, i + 1)[0], i + 3
            elif lo == 15:
                n = data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16
                p = i + 4
            else:
                n, p = lo, i + 1
            return p + n
        if hi == 0x40:
            return i + 2 if (op & 0x0F) == 0x0F else i + 1
        return -1 if hi in (0x60, 0x70) else i + 1
    if op == 0:
        return i
    if op in (1, 14):
        return i + 3
    if op in (2, 3, 4):
        return i + 2
    if op in (6, 8):
        return i + 4
    if op == 7:
        return i + 2 + (data[i + 1] if i + 1 < end else 0)
    if op in (9, 10, 13):
        return i + 5
    if op == 15:
        return i + 9
    return i + 1


# ------------------------------------------------------------ 现状（对比组）
WRAP = {0x8D, 0x8E, 0x6E, 0x6F, 0x7A, 0x87}


def walk_hybrid(data, start, end, out, depth):
    from pwsf.briefing import _decode
    stack = [(start, end, 0)]
    while stack:
        a, b, d = stack.pop()
        i = a
        while i < b:
            body, nxt, ln = _decode(data, i, b)
            if nxt <= i or body > b:
                break
            if body + ln > b:
                ln = b - body
            nxt = min(nxt, b)
            out.append((i, data[i], ln, body, d, "hyb"))
            if data[i] in WRAP and d < 8 and ln > 0:
                stack.append((body, body + ln, d + 1))
            i = nxt


def cues(data, ins):
    out = []
    for off, op, ln, body, d, k in ins:
        if op != 0x6D or ln < 23 or body + ln > len(data):
            continue
        p = data[body:body + ln]
        if (p[0] | p[1] << 8 | p[2] << 16) != ID_CUE:
            continue
        a = p[3:]
        if len(a) < 20:
            continue
        out.append((a[6], a[2] | a[3] << 8 | a[4] << 16 | a[5] << 24,
                    a[14] | a[15] << 8, a[17] | a[18] << 8))
    out.sort(key=lambda x: x[0])
    return out


def main():
    br = load(DAT)
    data, recs = br.data, br.records
    print(f"记录 {len(recs)}")

    res = {}
    for tag, fn in (("分层模型", "layer"), ("现状混合", "hybrid")):
        nrec = 0
        nrows = 0
        clean = 0            # 行号 0..n-1 且时间轴单调
        stalls = 0
        lits = 0
        noise = 0
        chain = 0
        for r in recs:
            a = r.entry_off if r.entry_off > 0 else r.script_off
            b = r.script_end(data)
            if not (0 <= a < b <= len(data)):
                continue
            out = []
            if fn == "layer":
                # 入口是块头 0x8d/0x8e：跳过去，body 交给解释器规则
                hi = data[a] & 0xF0
                if hi == 0x80:
                    n, body = operand(data, a, b)
                    st = walk_block(data, body, min(body + n, b), out, 0)
                else:
                    st = walk_block(data, a, b, out, 0)
                if st < 0:
                    stalls += 1
            else:
                walk_hybrid(data, a, b, out, 0)
            for i, op, ln, body, d, k in out:
                if op == 0x07 and ln:
                    lits += 1
                    s = data[body:body + ln].split(b"\x00")[0]
                    if not re.fullmatch(rb"[a-z]_[a-z]{3}_[A-Za-z0-9_]+", s):
                        noise += 1
            c = cues(data, out)
            if c:
                nrec += 1
                nrows += len(c)
                ln_ = [x[0] for x in c]
                ts = [x[2] for x in c]
                te = [x[3] for x in c]
                if ln_ == list(range(len(ln_))) and all(
                        x <= y for x, y in zip(ts, ts[1:])):
                    clean += 1
                if all(te[i] == ts[i + 1] for i in range(len(ts) - 1)):
                    chain += 1
        res[tag] = (nrec, nrows, clean, chain, stalls, lits, noise)
        print(f"\n[{tag}]")
        print(f"    含 0x6d 的记录：{nrec}   演出信息行数：{nrows}")
        print(f"    行号从 0 连续 + 时间轴单调：{clean}")
        print(f"    时间轴首尾严格相接：{chain}")
        print(f"    卡死的记录：{stalls}")
        print(f"    0x07 字面量 {lits}，其中非语音 ID 形态 {noise}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

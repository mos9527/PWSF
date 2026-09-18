"""_probe_bri51.py —— CODEC 回写可行性：文本到底在哪、记录能否原地改写

前情（_probe_bri50.py）
----------------------
* ``briefing_insn_decode`` 的 case 0x10/0x20 规则已从 IDA 取回（4 字节定长头，
  ``a1[3] & 0xF0 == 0x20`` 时再跟两条嵌套操作数）——**卡点本身已解开**；
* 但纯 IDA 规则在顶层流上 2049/2049 全部不前进，证明它**不是**顶层解码器
  （顶层由 ``briefing_script_run`` 用 ``briefing_insn_operand`` 推进，只认
  hi ∈ {0x00, 0x30, 0x60, 0x70}）。故"按解码结果重新发射字节码"这条路
  缺乏忠实实现，不能作为回写方案。

本探针换一个问法：**回写真的需要重发射字节码吗？**

* 台词在**文本池**（off1 -> u32 偏移表，off2 -> NUL 结尾串），字节码只用
  **行号索引**引用它（0x6d 的 args[6]）；
* 若脚本区内**不存在**任何可译文本，则回写 = 重写文本池 + 重建偏移表，
  其余字节原样保留 —— 与字节码语法完全无关。

回答三件事
----------
[A] 脚本区里有没有非 ASCII / 多字节 UTF-8？（没有 = 文本只在池里）
[B] 记录的**精确**字节边界：off1/off2/off3 与文本池末端的关系
[C] 逐记录：新池大小 vs 该记录到下一记录的空隙（能否原地改写、不用搬家）
"""
import collections
import re
import sys

from pwsf_briefing import load
from pwsf import config, po

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

WRAP = {0x8D, 0x8E, 0x6E, 0x6F, 0x7A, 0x87}


def decode(data, i, end):
    """pwsf/briefing.py::_decode（现状），仅用于取 0x07 字面量。"""
    op = data[i]
    if op & 0xC0 == 0xC0:
        return i + 1, i + 1, 0
    hi = op & 0xF0
    if hi:
        if hi in (0x30, 0x50, 0x60, 0x70, 0x80):
            lo = op & 0x0F
            if lo == 13:
                n, p = data[i + 1], i + 2
            elif lo == 14:
                n, p = int.from_bytes(data[i + 1:i + 3], "little"), i + 3
            elif lo == 15:
                n = data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16
                p = i + 4
            else:
                n, p = lo, i + 1
            return p, p + n, n
        if hi == 0x40:
            return i + 1, i + 2 if (op & 0x0F) == 0x0F else i + 1, 0
        return i + 1, i + 1, 0
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


def walk(data, start, end):
    out = []
    stack = [(start, end, 0)]
    while stack:
        a, b, d = stack.pop()
        i = a
        while i < b:
            body, nxt, ln = decode(data, i, b)
            if nxt <= i or body > b:
                break
            if body + ln > b:
                ln = b - body
            nxt = min(nxt, b)
            out.append((i, data[i], ln, body, d))
            if data[i] in WRAP and d < 8 and ln > 0:
                stack.append((body, body + ln, d + 1))
            i = nxt
    return out


def main():
    br = load(DAT)
    data, recs = br.data, br.records
    print(f"记录 {len(recs)}   文件 {len(data)} 字节")

    # ------------------------------------------------------------------ [A]
    print("\n[A] 字节码里有没有可译文本？")
    lits = collections.Counter()
    nonvoice = []
    u8text = []
    emb = 0
    for r in recs:
        a, b = r.script_off, r.script_end(data)
        if not (0 <= a < b <= len(data)):
            continue
        seg = data[a:b]
        # 该记录自己的台词会不会以裸字节形式出现在脚本区里？
        for t in r.lines:
            e = t.encode()
            if len(e) >= 8 and e in seg:
                emb += 1
                break
        for i, op, ln, body, d in walk(data, r.entry_off
                                       if r.entry_off > 0 else a, b):
            if op == 0x07 and ln:
                s = data[body:body + ln].split(b"\x00")[0]
                lits[s] += 1
                if not re.fullmatch(rb"[a-z]_[a-z]{3}_[A-Za-z0-9_]+", s):
                    nonvoice.append((r.off, s))
                    try:
                        d_ = s.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    if any(ord(c) > 0x7F for c in d_):
                        u8text.append((r.off, d_))
    print(f"    0x07 字符串字面量：{len(lits)} 种 / {sum(lits.values())} 次")
    print(f"    非语音 ID 形态（多半是遍历失步产生的噪声）：{len(nonvoice)}")
    print(f"    其中能严格 UTF-8 解码且含非 ASCII 的：{len(u8text)}")
    for off, s in u8text[:10]:
        print(f"        {off:#x}  {s!r}")
    print(f"    本记录台词以裸字节出现在脚本区里的记录：{emb} / {len(recs)}")

    # ------------------------------------------------------------------ [B]
    print("\n[B] 记录内部布局（v10 = off + 12）")
    same = diff = 0
    d3 = collections.Counter()
    tail = collections.Counter()
    for i, r in enumerate(recs):
        p2 = r.v10 + r.off2
        nxt = recs[i + 1].off if i + 1 < len(recs) else len(data)
        # 真正的池末端 = 每一串都用「自己的偏移 + 自己的长度」算，取最大
        pool_end = max((p2 + v + len(t.encode("utf-8")) + 1
                        for v, t in zip(r.table, r.lines)), default=p2)
        off3_abs = r.v10 + r.off3
        if off3_abs == pool_end:
            same += 1
        else:
            diff += 1
            d3[off3_abs - pool_end] += 1
        tail[nxt - max(off3_abs, pool_end)] += 1
        r._pool_end = pool_end
    print(f"    v10+off3 == 文本池末端：{same} / {len(recs)}")
    print(f"    不等的偏移差分布（top5）：{d3.most_common(5)}")
    print(f"    记录末端 -> 下一记录 的空隙分布（top8）：{tail.most_common(8)}")

    print("\n    空隙内容抽样（记录末端后 32 字节；记录末端 = v10+off3）")
    shown = 0
    for i, r in enumerate(recs):
        if r.lang != "en" or shown >= 4:
            continue
        nxt = recs[i + 1].off if i + 1 < len(recs) else len(data)
        g = data[r.v10 + r.off3:nxt][:32]
        if not g:
            continue
        print(f"        {r.off:#x}  gap={nxt - (r.v10 + r.off3):4d}  "
              f"{' '.join(f'{b:02x}' for b in g)}")
        shown += 1

    # ------------------------------------------------------------------ [C]
    print("\n[C] 原地改写：每条记录有多少增长预算？")
    tr = {}
    for p in po.po_files(config.PO_DIR / "codec"):
        tr.update(po.translated(p))
    print(f"    src/codec/*.po 现有译文：{len(tr)} 条（0 = 还没翻，用模拟测算）")

    zero = nonzero = 0
    pools, slacks, ratios = [], [], []
    for i, r in enumerate(recs):
        if r.lang != "en":
            continue
        nxt = recs[i + 1].off if i + 1 < len(recs) else len(data)
        gap = data[r._pool_end:nxt]
        if gap and not any(gap):
            zero += 1
        else:
            nonzero += 1
        pool = r._pool_end - (r.v10 + r.off2)
        slack = nxt - r._pool_end
        pools.append(pool)
        slacks.append(slack)
        ratios.append(1.0 + slack / pool if pool else 99.0)
    print(f"    en 块记录：{len(pools)}")
    print(f"    空隙全 0 的：{zero}   非全 0 的：{nonzero}")
    print(f"    文本池字节：min {min(pools)} 中位 "
          f"{sorted(pools)[len(pools)//2]}  max {max(pools)}  "
          f"合计 {sum(pools)}")
    print(f"    可用空隙：min {min(slacks)} 中位 "
          f"{sorted(slacks)[len(slacks)//2]}  max {max(slacks)}  "
          f"合计 {sum(slacks)}")
    ratios.sort()
    print(f"    逐记录「池可放大到几倍」的上界：min {ratios[0]:.2f}  "
          f"5% {ratios[len(ratios)//20]:.2f}  中位 {ratios[len(ratios)//2]:.2f}")
    for k in (1.0, 1.5, 2.0):
        over = sum(1 for x in ratios if x < k)
        print(f"    放大 {k:.1f}x 时放不下的记录：{over} / {len(ratios)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

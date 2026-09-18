"""_probe_bri38 —— 字节码反汇编器（依据 sub_1400A4B40 / sub_1400A4770）。

sub_1400A4B40(a1, &op, &val) 的指令编码（已反编译取证）：
  (b & 0xC0) == 0xC0 : 1 字节；op=9  ；val = (b & 0x3F) - 1      小整数
  (b & 0xF0) == 0x30 : op=0x30；长度取自低 4 位（13/14/15 -> u8/u16/u24）
                       payload 是表达式（sub_14013CD90）
  (b & 0xF0) == 0x50 : op = 0x50 | (payload[0] << 16)；val = payload+4
                       u24 id = payload[1..3]（sub_1400A49A0 取证）
  (b & 0xF0) == 0x60 : op=0x60；长度同 0x30；payload[0..2] = u24 处理器 id
                       payload[3..] = 参数（sub_1400A53D0）
  (b & 0xF0) == 0x70 : op=0x70；长度同 0x30；payload[0..2] = 子程序 id
  (b & 0xF0) == 0x80 : 字符串；val = payload 起始（0x8d/0x8e/0x8f = u8/u16/u24 长度）
  (b & 0xF0) == 0x90 : op=15；1 字节
  (b & 0xF0) == 0    : op = b 本身
        0 -> 结束   1 -> u16    2/3/4 -> u8    6/8 -> u24
        7 -> 内联字符串（u8 长度前缀，val = 串首）
        9/10/13 -> u32           14 -> sub_1400A31F0(u16)   15 -> u64

本脚本从 record.entry_off 起走一遍，打印指令流；并对 0x6d 指令
（id 0x3B91EB）单独标注参数。
"""
import sys

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

br = load(DAT)
recs = br.records
data = br.data


def u16(b, p):
    return b[p] | (b[p + 1] << 8)


def u24(b, p):
    return b[p] | (b[p + 1] << 8) | (b[p + 2] << 16)


def u32(b, p):
    return int.from_bytes(b[p:p + 4], "little")


def length_of(b, p):
    """返回 (payload 起点, 长度, 长度字段字节数)"""
    lo = b[p] & 0x0F
    if lo == 13:
        return p + 2, b[p + 1], 1
    if lo == 14:
        return p + 3, u16(b, p + 1), 2
    if lo == 15:
        return p + 4, u24(b, p + 1), 3
    return p + 1, lo, 0


def disasm(b, start, end, limit=200, depth=0, out=None):
    """返回 [(off, text)]。depth>0 时对 CALL/SUB 的 payload 递归展开。"""
    if out is None:
        out = []
    pad = "  " * depth
    p = start
    n = 0
    while p < end and n < limit:
        op = b[p]
        if (op & 0xC0) == 0xC0:
            out.append((p, f"{op:02x}              int {(op & 0x3F) - 1}"))
            p += 1
        elif (op & 0xF0) == 0x30:
            q, ln, _ = length_of(b, p)
            out.append((p, f"{op:02x} EXPR  len={ln:<4} payload={bytes(b[q:q+min(ln,24)]).hex(' ')}"))
            p = q + ln
        elif (op & 0xF0) == 0x50:
            q, ln, _ = length_of(b, p)
            i = u24(b, q + 1)
            out.append((p, f"{op:02x} CMD   len={ln:<4} id24={i:#08x} "
                           f"arg={bytes(b[q+4:q+4+min(ln-4,24)]).hex(' ')}"))
            p = q + ln
        elif (op & 0xF0) == 0x60:
            q, ln, _ = length_of(b, p)
            i = u24(b, q)
            out.append((p, pad + f"{op:02x} CALL  len={ln:<4} id24={i:#08x} "
                                f"arg={bytes(b[q+3:q+3+min(ln-3,24)]).hex(' ')}"))
            if depth < 3:
                disasm(b, q + 3, q + ln, limit, depth + 1, out)
            p = q + ln
        elif (op & 0xF0) == 0x70:
            q, ln, _ = length_of(b, p)
            i = u24(b, q)
            out.append((p, pad + f"{op:02x} SUB   len={ln:<4} id24={i:#08x} "
                                f"arg={bytes(b[q+3:q+3+min(ln-3,24)]).hex(' ')}"))
            if depth < 3:
                disasm(b, q + 3, q + ln, limit, depth + 1, out)
            p = q + ln
        elif (op & 0xF0) == 0x80:
            q, ln, _ = length_of(b, p)
            s = bytes(b[q:q + ln])
            out.append((p, pad + f"{op:02x} STR   len={ln:<4} {s[:40]!r}"))
            if depth < 6 and (op & 0x0F) in (13, 14, 15) and ln > 8:
                disasm(b, q, q + ln, limit, depth + 1, out)
            p = q + ln
        elif (op & 0xF0) == 0x90:
            out.append((p, f"{op:02x}              reg[{op & 0xF}]"))
            p += 1
        else:
            k = op
            if k == 0:
                out.append((p, "00  END"))
                p += 1
            elif k == 1:
                out.append((p, f"01  u16 {u16(b, p+1)}"))
                p += 3
            elif k in (2, 3, 4):
                out.append((p, f"{k:02x}  u8  {b[p+1]}"))
                p += 2
            elif k in (6, 8):
                out.append((p, f"{k:02x}  u24 {u24(b, p+1)}"))
                p += 4
            elif k == 7:
                ln = b[p + 1]
                s = bytes(b[p + 2:p + 2 + ln])
                out.append((p, f"07  STR8 len={ln:<3} {s.decode('latin1')!r}"))
                p += 2 + ln
            elif k in (9, 10, 13):
                out.append((p, f"{k:02x}  u32 {u32(b, p+1)}"))
                p += 5
            elif k == 14:
                out.append((p, f"0e  FIX  {u16(b, p+1)}"))
                p += 3
            elif k == 15:
                out.append((p, f"0f  u64  {int.from_bytes(b[p+1:p+9],'little')}"))
                p += 9
            else:
                out.append((p, f"{k:02x}  ???"))
                break
        n += 1
    return out


# ---- 入口 opcode 统计 ----
import collections
cnt = collections.Counter(data[r.entry_off] for r in recs)
print("全部记录 entry 处首字节分布：",
      dict(sorted(cnt.items(), key=lambda kv: -kv[1])[:16]))

# ---- 逐条反汇编几条记录 ----
idx = [int(x) for x in sys.argv[1:]] or [0, 1]
for i in idx:
    r = recs[i]
    e = r.script_end(data)
    print(f"\n===== 记录 {i}  扇区 {r.sector}  off={r.off:#x}  "
          f"行数={r.n_lines}  entry={r.entry_off:#x} ({r.entry_off - r.off:#x})  "
          f"end={e:#x} =====")
    for t in r.lines:
        print("   台词:", t.replace("\n", "\\n")[:70])
    # sub_1400A3040: v1 = sub_1400A4770(A->entry, &len) —— 先解掉入口那条
    # 0x8d/0x8e 包裹指令，再把**操作数区**（真正的脚本体）交给解释器。
    b0 = data[r.entry_off]
    body = r.entry_off + (2 if b0 == 0x8D else 3)
    ln = data[r.entry_off + 1] if b0 == 0x8D else u16(data, r.entry_off + 1)
    print(f"  [入口包裹] op={b0:#04x} 脚本体长度={ln}  体起点={body:#x}")
    for off, txt in disasm(data, body, min(e, body + ln)):
        print(f"  {off - r.off:6x}  {txt}")

"""Probe: 反汇编 BRIEFING 记录里的脚本字节码（按 sub_1400A4770 + sub_1400A35C0）。

sub_1400A4770(_BYTE *a1, int *a2)：
    switch (*a1 & 0xF) {
      case 13: *a2 = u8@(a1+1);  return a1 + 2;
      case 14: *a2 = u16@(a1+1); return a1 + 3;
      case 15: *a2 = u24@(a1+1); return a1 + 4;
      default: *a2 = *a1 & 0xF;  return a1 + 1;
    }
sub_1400A35C0 按 op & 0xF0 分派：0x30 / 0x60 / 0x70，其余跳过；0x00 结束。
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


def operand(pc):
    op = D[pc]
    lo = op & 0x0F
    if lo == 13:
        return D[pc + 1], pc + 2
    if lo == 14:
        return int.from_bytes(D[pc + 1:pc + 3], "little"), pc + 3
    if lo == 15:
        return int.from_bytes(D[pc + 1:pc + 4], "little"), pc + 4
    return lo, pc + 1


def disasm(rec, limit=200):
    out = []
    pc = rec.entry_off
    for _ in range(limit):
        if pc >= len(D):
            break
        op = D[pc]
        hi = op & 0xF0
        if hi == 0:
            out.append((pc, op, None, b""))
            break
        ln, p = operand(pc)
        payload = D[p:p + ln]
        out.append((pc, op, ln, payload))
        pc = p + ln
        if pc >= len(D):
            break
    return out


def fmt(op, ln, pl):
    lo = op & 0x0F
    if len(pl) and all(0x20 <= c < 0x7F for c in pl):
        s = pl.split(b"\x00")[0].decode("ascii", "replace")
        if len(s) >= 3:
            return f"str {s!r}"
    if len(pl) in (1, 2, 4):
        return f"u{len(pl) * 8}={int.from_bytes(pl, 'little')}"
    return pl.hex()


print("=== 前 6 条记录的字节码 ===")
for rec in br.records[:6]:
    print(f"\n[rec off={rec.off:#x} idx={rec.idx} n_lines={rec.n_lines} "
          f"entry={rec.entry_off:#x} pool={rec.script_off:#x}]")
    for pc, op, ln, pl in disasm(rec, limit=60):
        if ln is None:
            print(f"   {pc:#07x}  {op:#04x}  END")
            break
        print(f"   {pc:#07x}  {op:#04x}  len={ln:<4} {fmt(op, ln, pl)}")

print("\n\n=== 全文件 opcode 分布 (op & 0xF0) ===")
hi_cnt = collections.Counter()
full = collections.Counter()
for rec in br.records:
    for pc, op, ln, pl in disasm(rec, limit=4000):
        hi_cnt[op & 0xF0] += 1
        full[op] += 1
        if op & 0xF0 == 0:
            break
print("高 4 位：", {hex(k): v for k, v in hi_cnt.most_common()})
print("完整字节（前 40）：", {hex(k): v for k, v in full.most_common(40)})

print("\n\n=== 0x3x / 0x6x / 0x7x 的 payload 形态 ===")
for fam in (0x30, 0x60, 0x70):
    c = collections.Counter()
    samples = []
    for rec in br.records:
        for pc, op, ln, pl in disasm(rec, limit=4000):
            if op & 0xF0 == 0:
                break
            if op & 0xF0 == fam:
                key = (ln, "str" if (len(pl) > 3 and all(0x20 <= x < 0x7F for x in pl))
                       else "bin")
                c[key] += 1
                if len(samples) < 8 and key[1] == "str":
                    samples.append((rec.off, pc, op, pl))
    print(f"\n 0x{fam:02x}: {dict(c.most_common(12))}")
    for off, pc, op, pl in samples[:8]:
        print(f"     rec={off:#x} pc={pc:#x} op={op:#04x} {pl[:48]!r}")

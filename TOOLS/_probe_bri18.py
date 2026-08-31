"""真假记录判别：用「脚本区入口是否为合法字节码」作为独立判据。

sub_1400A3040 从 A->entry 起先执行一条 sub_1400A4770 包裹指令，
其 opcode 必须是 0x8d/0x8e（case 13/14，后随 u8/u16 长度）。
若入口字节不是这类值，或长度超出记录范围 -> 该记录可疑（魔数碰撞）。
"""
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_briefing as B

br = B.load(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
            r"\MLG\disc0_rel\0076531d.DAT")
D = br.data


def entry_ok(r) -> tuple:
    e = r.entry_off
    if not (0 <= e < len(D)):
        return False, "entry 越界"
    op = D[e]
    if op & 0xF0 == 0:
        return False, f"入口 opcode {op:#04x} 高4位为0"
    lo = op & 0x0F
    if lo == 13:
        n, body = D[e + 1], e + 2
    elif lo == 14:
        n = int.from_bytes(D[e + 1:e + 3], "little")
        body = e + 3
    elif lo == 15:
        n = int.from_bytes(D[e + 1:e + 4], "little")
        body = e + 4
    else:
        n, body = lo, e + 1
    end = body + n
    if end > len(D):
        return False, f"脚本体越界 end={end:#x}"
    if op not in (0x8D, 0x8E):
        return False, f"入口 opcode {op:#04x} 非 0x8d/0x8e"
    return True, f"len={n}"


good = bad = 0
reasons = collections.Counter()
bad_with_clean_text = 0
for r in br.records:
    ok, why = entry_ok(r)
    if ok:
        good += 1
    else:
        bad += 1
        reasons[why.split(" ", 1)[-1][:28]] += 1
        if not any("\ufffd" in t for t in r.lines):
            bad_with_clean_text += 1

print(f"记录总数 {len(br.records)}")
print(f"  脚本区入口合法   {good}")
print(f"  脚本区入口不合法 {bad}   （其中台词全部可解码的有 {bad_with_clean_text}）")
print("\n不合法原因分布：")
for k, v in reasons.most_common(12):
    print(f"   {k:<30} {v}")

# 交叉统计：入口合法性 vs 台词可解码性
print("\n=== 交叉表 ===")
cross = collections.Counter()
for r in br.records:
    ok, _ = entry_ok(r)
    clean = not any("\ufffd" in t for t in r.lines)
    cross[(ok, clean)] += 1
for (ok, clean), n in sorted(cross.items(), key=lambda x: -x[1]):
    print(f"  入口{'合法' if ok else '非法'} / 台词{'全可解码' if clean else '含乱码'}: {n}")

print("\n=== 用户报告的那条记录 ===")
for r in br.records:
    if r.off == 0x15DFB0:
        ok, why = entry_ok(r)
        print(f"  off={r.off:#x}  入口{r.entry_off:#x}  opcode={D[r.entry_off]:#04x}"
              f"  判定={'合法' if ok else '非法'}  {why}")
        print(f"  v11={r.off + 12 + r.off0:#x}  脚本池={r.script_off:#x}  "
              f"end={r.end:#x}")
        print(f"  扇区内偏移 {r.off % 4096:#x}（距扇区末仅 {4096 - r.off % 4096} 字节）")
        for i, t in enumerate(r.lines):
            print(f"    [{i}] {t[:60]!r}")

print("\n=== 所有「记录头紧邻扇区末尾」的记录（剩余空间 < 64B）的可疑度 ===")
tight = [r for r in br.records if 4096 - (r.off % 4096) < 64]
print(f"  共 {len(tight)} 条")
bad_tight = sum(1 for r in tight if not entry_ok(r)[0])
print(f"  其中入口不合法 {bad_tight}")
tot_tight_bad = sum(1 for r in tight if any("\ufffd" in t for t in r.lines))
print(f"  其中台词含乱码 {tot_tight_bad}")

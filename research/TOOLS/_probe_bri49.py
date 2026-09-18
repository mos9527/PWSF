"""_probe_bri49.py —— 递归解码脚本字节码：0x6d 参数结构 + 语音 ID↔台词逐行对应

关键修正（相对 _probe_bri48 的失败）
----------------------------------
``0x6d`` 指令**不在顶层**。顶层是一条 ``0x6e``（op 0x60 + u16 长度），其载荷里
先是一段 C 串（语音资源 ID），随后是 ``0x8d/0x8e`` 包裹的一串 ``0x6d``。
故必须**递归**下钻：遇到 op 0x8d/0x8e（``sub_1400A4B40`` 的 case 0x80）
或 op 0x6e 时，继续解码其载荷。

顶层结构（实测，记录 111 / sec42）：
    6e 69 00  <u24 id>  "…kaz0100_000_0\0"  8d 7e 00
        └─ 载荷(0x69=105 B) ────────────────┘   └─ 0x7e=126 B ─┐
           6d 17 eb 91 3b 07 06 59 d9 55 0e 00 00 5a 69 26 b2
              01 01 bd 01 01 b1 06 00                        <- 行 0
           6d 17 eb 91 3b 07 06 e6 dc 28 0e 01 00 5a 69 26 b2
              01 01 e9 06 01 0c 0b 00                        <- 行 1
           …

本轮产出：0x6d 各字段的统计画像 + 语音 ID/行号/时间轴三元组。
"""
import collections
import struct
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

# 需要递归下钻其载荷的 opcode（含长度的包裹指令）
WRAP = {0x8D, 0x8E, 0x6E, 0x6F, 0x7A, 0x87}
ID_6D = 0x3B91EB


def oper(data, i):
    """sub_1400A4770 的操作数解码 -> (长度, 载荷起点)"""
    lo = data[i] & 0x0F
    if lo == 13:
        return data[i + 1], i + 2
    if lo == 14:
        return struct.unpack_from("<H", data, i + 1)[0], i + 3
    if lo == 15:
        return (data[i + 1] | data[i + 2] << 8 | data[i + 3] << 16), i + 4
    return lo, i + 1


def walk(data, start, end, depth=0, out=None, maxdepth=4):
    out = [] if out is None else out
    i = start
    while i < end:
        op = data[i]
        if op & 0xF0 == 0:
            break
        ln, body = oper(data, i)
        if ln <= 0 or body + ln > end:
            break
        out.append((i, op, ln, body, depth))
        if op in WRAP and depth < maxdepth:
            walk(data, body, body + ln, depth + 1, out, maxdepth)
        i = body + ln
    return out


def main():
    br = load(DAT)
    recs = br.records

    # --- 1. 递归后 opcode 频次 ---
    ops = collections.Counter()
    per6d = []
    for ri, r in enumerate(recs):
        a, b = r.script_off, r.script_end(br.data)
        ins = walk(br.data, a, b)
        for i, op, ln, body, d in ins:
            ops[(op, d)] += 1
        sixd = [(i, ln, body) for i, op, ln, body, d in ins if op == 0x6D]
        if sixd:
            per6d.append((ri, r, sixd))
    print("[1] 递归后 opcode 频次（top 16，含深度）")
    for (op, d), c in ops.most_common(16):
        print(f"    {op:#04x} depth={d}  {c:7d}")

    print(f"\n[2] 含 0x6d 的记录：{len(per6d)} / {len(recs)}")
    eq = sum(1 for ri, r, s in per6d if len(s) == r.n_lines)
    print(f"    0x6d 条数 == 台词条数：{eq} / {len(per6d)}")
    diff = collections.Counter(len(s) - r.n_lines for ri, r, s in per6d)
    print(f"    (0x6d 数 - 台词数) 分布：{dict(sorted(diff.items()))}")

    # --- 3. 0x6d 参数画像 ---
    print("\n[3] 0x6d 参数画像（payload[0..2]=u24 id，args=payload[3:]）")
    idcnt = collections.Counter()
    lens = collections.Counter()
    arglens = collections.Counter()
    for ri, r, sixd in per6d:
        for i, ln, body in sixd:
            p = br.data[body:body + ln]
            idcnt[p[0] | p[1] << 8 | p[2] << 16] += 1
            lens[ln] += 1
            arglens[ln - 3] += 1
    print(f"    id 分布：{ {hex(k): v for k, v in idcnt.most_common(4)} }")
    print(f"    长度分布：{dict(lens.most_common(4))}")
    print(f"    args 长度分布：{dict(arglens.most_common(4))}")

    # 逐字节：是否单调/恒定
    print("\n[4] args 逐字节画像（只在 0x6d 数 == 台词数 的记录上统计）")
    seq = []
    for ri, r, sixd in per6d:
        if len(sixd) != r.n_lines or r.n_lines < 3:
            continue
        rows = [br.data[body:body + ln][3:] for i, ln, body in sixd]
        seq.append((ri, r, rows))
    print(f"    参与统计的记录：{len(seq)}")
    if not seq:
        return 0
    n = min(len(rows[0]) for _, _, rows in seq)
    print(f"    args 最短长度 {n}")
    lin = collections.defaultdict(collections.Counter)
    for ri, r, rows in seq:
        for k, a in enumerate(rows):
            for j in range(min(len(a), n)):
                lin[j][(a[j] == k, a[j])] += 1
    print(f"    {'pos':>5s} {'=行号':>7s} {'众数':>6s} {'众数占比':>8s} {'取值数':>6s}")
    for j in range(n):
        c = lin[j]
        hit = sum(v for (eqk, b), v in c.items() if eqk)
        tot = sum(c.values())
        mode = max(c.items(), key=lambda kv: kv[1])
        print(f"    {j:5d} {hit*100//tot:6d}% {mode[0][1]:#6x} "
              f"{mode[1]*100//tot:7d}% {len({b for _, b in c}):6d}")

    # --- 5. 时间轴字段的单调性检验 ---
    print("\n[5] 时间轴候选字段（u16 LE）单调性检验")
    for cand in ((14, 15), (17, 18)):
        a0, a1 = cand
        ok = tot = 0
        for ri, r, rows in seq:
            vals = []
            good = True
            for a in rows:
                if len(a) <= a1:
                    good = False
                    break
                vals.append((a[a0] | a[a1 - 1] << 8) if a1 < a0 else
                            (a[a0] | a[a1] << 8))
            if good and len(vals) > 1:
                tot += 1
                if all(v <= w for v, w in zip(vals, vals[1:])):
                    ok += 1
        print(f"    args[{a0}] | args[{a1}]<<8 : 单调不减 {ok}/{tot}")

    # --- 6. 语音 ID ↔ 台词逐行对应（终检） ---
    print("\n[6] 语音 ID ↔ 台词逐行对应抽样")
    import re
    shown = 0
    for ri, r, sixd in per6d:
        if len(sixd) != r.n_lines or r.n_lines < 2:
            continue
        seg = br.data[r.script_off:r.script_end(br.data)]
        m = re.findall(rb"[a-z]_[a-z]{3}_[A-Za-z0-9_]{6,}", seg)
        if not m:
            continue
        print(f"\n  记录 {ri}  sec{r.sector}  语音 {m[0].decode()}")
        for k, (i, ln, body) in enumerate(sixd[:4]):
            p = br.data[body:body + ln]
            a = p[3:]
            t0 = a[14] | a[15] << 8 if len(a) > 15 else -1
            t1 = a[17] | a[18] << 8 if len(a) > 18 else -1
            print(f"    行{k}  id4={p[2]:#04x}{p[3]:02x}{p[4]:02x}{p[5]:02x} "
                  f"args[6]={a[6]:3d}  t={t0}..{t1}  {r.lines[k][:44]}")
        shown += 1
        if shown >= 3:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())

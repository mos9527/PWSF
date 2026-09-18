"""_probe_bri39 —— 建立「语音 ID ↔ 台词行」的**逐行**对应并验证。

脚本结构（_probe_bri38.py 反汇编取证）：
  入口 0x8d/0x8e 包裹
    └─ 6e CALL id=0x57C8D1          一段对话
         └─ 6e CALL id=0x9930CC     一个说话人组（其首个参数是语音 ID 串）
              └─ 6d CALL id=0x3B91EB × N   每行一条；参数 arg[6..7] = u16 行号

本脚本遍历全部记录，抽出 (语音ID, [行号...])，并检验：
  语音 ID 的「行号字段」(倒数第 2 段，形如 010/020) 是否 == 10 * 该组首行号
  组内行号是否连续
"""
import collections
import re

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")
br = load(DAT)
data = br.data
recs = br.records

GROUP_CALL = 0x9930CC
LINE_CALL = 0x3B91EB


def u16(b, p):
    return b[p] | (b[p + 1] << 8)


def u24(b, p):
    return b[p] | (b[p + 1] << 8) | (b[p + 2] << 16)


def length_of(b, p):
    lo = b[p] & 0x0F
    if lo == 13:
        return p + 2, b[p + 1]
    if lo == 14:
        return p + 3, u16(b, p + 1)
    if lo == 15:
        return p + 4, u24(b, p + 1)
    return p + 1, lo


def find_calls(b, start, end, wanted):
    """在 [start,end) 内**线性扫描**所有 opcode==0x6e/0x6d 且 id 匹配的指令。

    不做树形解析（STR 包裹层难以可靠展开），直接按 2 字节对齐扫描：
    命中条件是 id 匹配且长度字段自洽（不越界、尾部是 00 或下一指令合法）。
    """
    for p in range(start, end - 6):
        op = b[p]
        if (op & 0xF0) != 0x60:
            continue
        q, ln = length_of(b, p)
        if ln < 3 or q + ln > end:
            continue
        if u24(b, q) == wanted:
            yield p, q + 3, q + ln      # (指令位置, 参数起点, 参数终点)


VID = re.compile(rb"[a-z]_[a-z]{3}_[A-Za-z0-9]+_(\d{3})_(\d+)")

stat = collections.Counter()
samples = []
nrec_with_groups = 0
for ri, r in enumerate(recs):
    e = r.script_end(data)
    b0 = data[r.entry_off]
    body = r.entry_off + (2 if b0 == 0x8D else 3)
    ln = data[r.entry_off + 1] if b0 == 0x8D else u16(data, r.entry_off + 1)
    end = min(e, body + ln)
    groups = list(find_calls(data, body, end, GROUP_CALL))
    if not groups:
        stat["无说话人组的记录"] += 1
        continue
    nrec_with_groups += 1
    for gi, (gp, garg, gend) in enumerate(groups):
        seg = data[garg:gend]
        m = VID.search(seg)
        if not m:
            stat["组内无语音ID"] += 1
            continue
        vid_line = int(m.group(1))
        lines = []
        for lp, larg, lend in find_calls(data, garg, gend, LINE_CALL):
            a = data[larg:lend]
            if len(a) >= 8:
                lines.append((lp, u16(a, 6)))
        if not lines:
            stat["组内无行"] += 1
            continue
        idxs = [i for _, i in lines]
        first = idxs[0]
        stat["组总数"] += 1
        if vid_line == 10 * first:
            stat["语音ID行字段 == 10*首行号"] += 1
        else:
            stat["不一致"] += 1
            if len(samples) < 12:
                samples.append((ri, gp, m.group(0).decode(), vid_line, idxs[:8]))
        if idxs == list(range(first, first + len(idxs))):
            stat["行号连续"] += 1
        else:
            stat["行号不连续"] += 1
        stat["行数合计"] += len(idxs)

print("有说话人组的记录:", nrec_with_groups, "/", len(recs))
for k, v in stat.most_common():
    print(f"  {k}: {v}")

print("\n=== 不一致样例（记录序, 指令偏移, 语音ID, ID行字段, 行号列表）===")
for s in samples:
    print("  ", s)

# 抽样：打印若干记录的完整 (语音ID, 行号) 表
print("\n=== 抽样：前 6 条记录的 (语音ID -> 行号) ===")
for ri in range(6):
    r = recs[ri]
    e = r.script_end(data)
    b0 = data[r.entry_off]
    body = r.entry_off + (2 if b0 == 0x8D else 3)
    ln = data[r.entry_off + 1] if b0 == 0x8D else u16(data, r.entry_off + 1)
    end = min(e, body + ln)
    print(f"记录 {ri}  行数={r.n_lines}  扇区 {r.sector}")
    for gp, garg, gend in find_calls(data, body, end, GROUP_CALL):
        m = VID.search(data[garg:gend])
        idxs = [u16(data[larg:lend], 6)
                for _, larg, lend in find_calls(data, garg, gend, LINE_CALL)]
        print(f"    {m.group(0).decode() if m else '?':28s} 行号 {idxs}")

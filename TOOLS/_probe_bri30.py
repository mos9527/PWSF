"""_probe_bri30 —— 逐扇区判定正确 keystream 偏移 k：**最长可读文本游程**判据。

扇区内容 = 记录头 + 文本池（可读）+ 脚本字节码（二进制）。
因此「替换字符总数」不是好判据（二进制区贡献大量替换字符），
而「最长连续可读游程」能直接抓出文本池是否被正确解出。

对每扇区每个 k，计算：
  * 最长连续可解码字节数
  * 该游程的起始偏移
  * 前 2048 / 后 2048 字节各自的替换字符数（观察扇区内是否存在 k 切换）
"""
import sys

import numpy as np

from pwsf_crypto import MT19937, name_hash, XOR_CONST
from pwsf_briefing import SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

raw = np.frombuffer(open(DAT, "rb").read(), dtype=np.uint8)
nsec = len(raw) // SECTOR
raw = raw[:nsec * SECTOR].reshape(nsec, SECTOR)
key = name_hash("0076531d")

mt = MT19937(key)
mt.advance(20)
KMAX = 6
ks = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range(KMAX * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8).reshape(KMAX, SECTOR)


def longest_run(d: bytes):
    """返回 (最长连续可解码字节数, 起点偏移)。逐字节走 UTF-8 状态机。"""
    i = best = bstart = start = 0
    n = len(d)
    while i < n:
        c = d[i]
        if c < 0x80:
            ln = 1
        elif 0xC2 <= c <= 0xDF and i + 1 < n and 0x80 <= d[i+1] <= 0xBF:
            ln = 2
        elif 0xE0 <= c <= 0xEF and i + 2 < n and \
                0x80 <= d[i+1] <= 0xBF and 0x80 <= d[i+2] <= 0xBF:
            ln = 3
        elif 0xF0 <= c <= 0xF4 and i + 3 < n and \
                all(0x80 <= d[i+j] <= 0xBF for j in (1, 2, 3)):
            ln = 4
        else:
            if i - start > best:
                best, bstart = i - start, start
            start = i + 1
            i += 1
            continue
        i += ln
    if i - start > best:
        best, bstart = i - start, start
    return best, bstart


def repl(d: bytes) -> int:
    return d.decode("utf-8", "replace").count("�")


a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 12
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 18
print(f"扇区 {a0}..{a1}")
print("  s  k | 最长可读游程  起点 | 前半repl 后半repl | 游程开头 30 字")
for s in range(a0, min(a1 + 1, nsec)):
    for k in range(KMAX):
        d = bytes(raw[s] ^ ks[k])
        L, st = longest_run(d)
        r1, r2 = repl(d[:2048]), repl(d[2048:])
        head = d[st:st + 30].decode("utf-8", "replace").replace("\x00", ".")
        print(f"{s:5d} {k} | {L:6d} @ {st:5d} | {r1:6d} {r2:6d} | {head!r}")
    print()

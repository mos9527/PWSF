"""_probe_bri29 —— 用**严格 UTF-8 解码**给逐扇区 × k 打分（取代不靠谱的结构判据）。

_probe_bri28 的结构判据会把「二进制字节码扇区」误判为高文本性，
本脚本改用 Python codecs 严格解码：统计每个 4096 字节扇区解码后的
替换字符（U+FFFD）数量，0 个 = 完全可解码。

同时给出「可打印/文本标记」计数，用于区分「纯文本」与「含二进制的
记录体」。
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
KMAX = 8
ks = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range(KMAX * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8).reshape(KMAX, SECTOR)


def repl(d: bytes) -> int:
    return d.decode("utf-8", "replace").count("�")


a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 0
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 48
print(f"扇区 {a0}..{a1}：k=0..{KMAX-1} 下的替换字符数（* = 最少）")
print("  s   " + "".join(f"  k={k}  " for k in range(KMAX)) + "   最少值")
best = {}
for s in range(a0, min(a1 + 1, nsec)):
    vals = [repl(bytes(raw[s] ^ ks[k])) for k in range(KMAX)]
    k = min(range(KMAX), key=lambda i: vals[i])
    best[s] = (k, vals[k])
    cells = "".join(("*" if i == k else " ") + f"{v:5d}" for i, v in enumerate(vals))
    print(f"{s:5d} {cells}   {vals[k]}")

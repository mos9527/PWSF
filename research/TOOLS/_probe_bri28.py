"""_probe_bri28 —— 打印逐扇区在 k=0..5 下的文本性分数，看清「chunk」结构。

若加密单元是「连续若干扇区、块内 keystream 连续、块首重播种」，
则会看到形如 k=0,1,2,3,0,1,2,3... 的游程。
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


def score(a: np.ndarray) -> np.ndarray:
    cont = (a >= 0x80) & (a <= 0xBF)
    l2 = (a >= 0xC2) & (a <= 0xDF)
    l3 = (a >= 0xE0) & (a <= 0xEF)
    l4 = (a >= 0xF0) & (a <= 0xF4)
    n = (a < 0x80).sum(axis=1)
    n = n + 2 * (l2[:, :-1] & cont[:, 1:]).sum(axis=1)
    n = n + 3 * (l3[:, :-2] & cont[:, 1:-1] & cont[:, 2:]).sum(axis=1)
    n = n + 4 * (l4[:, :-3] & cont[:, 1:-2] & cont[:, 2:-1] & cont[:, 3:]).sum(axis=1)
    return n / a.shape[1]


a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 0
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 48
print(f"扇区 {a0}..{a1} 在 k=0..{KMAX-1} 下的分数（* 标记该扇区最优 k）")
print("  s   " + "".join(f"  k={k}  " for k in range(KMAX)))
for s in range(a0, min(a1 + 1, nsec)):
    a = raw[s] ^ ks                     # (KMAX, SECTOR)
    sc = score(a)
    k = int(sc.argmax())
    cells = "".join(("*" if i == k else " ") + f"{v:5.3f}" for i, v in enumerate(sc))
    print(f"{s:5d} {cells}")

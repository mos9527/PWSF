"""_probe_bri34 —— 精确求每个扇区**首字节**在 keystream 中的绝对偏移 d。

方法（不依赖任何分块假设）：
  取扇区开头 24 字节密文 c。要求明文是合法 UTF-8。对日语文本而言，
  绝大多数字符是 3 字节序列（lead E0-EF + 2 个续字节 80-BF），或对
  拉丁文本而言是 ASCII(<80)。
  逐字节用 numpy 全库筛选候选 d：
      (ks[d+i] ^ c[i]) 落在允许集合内
  先筛前 6 字节（两个 3 字节字符），再逐字节验证到 24 字节。

输出每个扇区的候选 d 列表 → 直接给出「块起点 P = 扇区偏移 - d」。
"""
import sys

import numpy as np

from pwsf_crypto import MT19937, name_hash, XOR_CONST
from pwsf_briefing import SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")
raw = np.frombuffer(open(DAT, "rb").read(), dtype=np.uint8)
nsec = len(raw) // SECTOR
key = name_hash("0076531d")

mt = MT19937(key)
mt.advance(20)
KS = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range((nsec + 16) * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8)
N = len(KS) - 64

# 三字节序列形态：L=lead(E0-EF) C=cont(80-BF)
def mask_lead(a):
    return (a >= 0xE0) & (a <= 0xEF)


def mask_cont(a):
    return (a >= 0x80) & (a <= 0xBF)


def mask_ascii(a):
    return a < 0x80


def candidates(c: np.ndarray, nbytes: int = 6) -> np.ndarray:
    """c: 密文前若干字节；返回满足「前两个三字节字符合法」的 d（或 ASCII 混合）。

    简化：要求 0..2 与 3..5 各自构成 (lead,cont,cont) 或全 ASCII。
    """
    ok = np.ones(N, dtype=bool)
    for grp in range(0, nbytes, 3):
        if grp + 2 >= nbytes:
            break
        x = KS[grp:N + grp] ^ c[grp]
        y = KS[grp + 1:N + grp + 1] ^ c[grp + 1]
        z = KS[grp + 2:N + grp + 2] ^ c[grp + 2]
        three = mask_lead(x) & mask_cont(y) & mask_cont(z)
        one = mask_ascii(x) & mask_ascii(y) & mask_ascii(z)
        ok &= (three | one)
    return np.flatnonzero(ok)


def verify(d: int, c: bytes, n: int = 48) -> int:
    """返回 c[:n] 在偏移 d 下能严格 UTF-8 解码的字节数（贪心）。"""
    p = bytes(KS[d:d + n])[0:len(c[:n])] if False else None
    dec = bytes(np.frombuffer(c[:n], dtype=np.uint8) ^ KS[d:d + n])
    i = 0
    L = len(dec)
    while i < L:
        b0 = dec[i]
        if b0 < 0x80:
            i += 1
        elif 0xE0 <= b0 <= 0xEF and i + 2 < L and \
                mask_cont(np.uint8(dec[i+1])) and mask_cont(np.uint8(dec[i+2])):
            i += 3
        elif 0xC2 <= b0 <= 0xDF and i + 1 < L and mask_cont(np.uint8(dec[i+1])):
            i += 2
        elif 0xF0 <= b0 <= 0xF4 and i + 3 < L and \
                all(mask_cont(np.uint8(dec[i+k])) for k in (1, 2, 3)):
            i += 4
        else:
            break
    return i


a0 = int(sys.argv[1]) if len(sys.argv) > 1 else 13
a1 = int(sys.argv[2]) if len(sys.argv) > 2 else 18
print(f"扇区 {a0}..{a1} 首字节的 keystream 绝对偏移 d")
for s in range(a0, min(a1 + 1, nsec)):
    c = raw[s * SECTOR:s * SECTOR + 48]
    cand = candidates(c)
    good = []
    for d in cand:
        n = verify(int(d), c)
        if n >= 24:
            good.append((int(d), n))
    good.sort(key=lambda t: -t[1])
    print(f"s{s:5d} 候选 {len(cand):4d} -> 通过 {len(good):3d}", end="")
    if good:
        best = good[0]
        print(f"   最优 d={best[0]:9d} (解码 {best[1]} 字节)  "
              f"P={(s * SECTOR - best[0]) / SECTOR:10.3f} 扇区", end="")
        if len(good) > 1:
            print(f"   次选 {[g[0] for g in good[1:4]]}", end="")
    print()

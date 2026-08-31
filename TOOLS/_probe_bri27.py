"""_probe_bri27 —— 为「常规 k=0 未解出的扇区」穷举 keystream 扇区偏移 k。

背景：_probe_bri26 用严格 UTF-8 可解码字节比给每扇区打分，随机数据基线
≈0.57，文本 ≥0.70。有 133 个扇区在 k=0 下仍是 0.57 左右（未解出）。
本脚本对这 133 个扇区枚举 k=0..N-1，检验「加密重播种粒度不是每扇区
而是更大的块、块内共用连续 keystream」的假说。

打分用向量化的结构判据（等价于 UTF-8 覆盖字节比）：
  s1 = ASCII;  s2 = C2..DF + 1 续;  s3 = E0..EF + 2 续;  s4 = F0..F4 + 3 续
  score = (s1 + 2*s2 + 3*s3 + 4*s4) / 扇区长度
"""
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
ks = np.frombuffer(
    np.array([(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
              for _ in range(nsec * SECTOR // 4)], dtype=np.uint32).tobytes(),
    dtype=np.uint8).reshape(nsec, SECTOR)


def score(a: np.ndarray) -> np.ndarray:
    """a: (m, SECTOR) uint8 -> 每行 UTF-8 覆盖字节比"""
    cont = (a >= 0x80) & (a <= 0xBF)
    l2 = (a >= 0xC2) & (a <= 0xDF)
    l3 = (a >= 0xE0) & (a <= 0xEF)
    l4 = (a >= 0xF0) & (a <= 0xF4)
    n = (a < 0x80).sum(axis=1)
    n = n + 2 * (l2[:, :-1] & cont[:, 1:]).sum(axis=1)
    n = n + 3 * (l3[:, :-2] & cont[:, 1:-1] & cont[:, 2:]).sum(axis=1)
    n = n + 4 * (l4[:, :-3] & cont[:, 1:-2] & cont[:, 2:-1] & cont[:, 3:]).sum(axis=1)
    return n / a.shape[1]


s0 = score(raw ^ ks[0])
bad = np.where(s0 < 0.70)[0]
print(f"k=0 未解出扇区 {len(bad)} / {nsec}")
print(f"k=0 已解出的分数区间 {s0[s0>=0.70].min():.3f} .. {s0.max():.3f}")
print(f"未解出的分数区间 {s0[bad].min():.3f} .. {s0[bad].max():.3f}")

print("\n=== 逐个未解出扇区的最优 k ===")
rows = []
for s in bad:
    sc = score(raw[s] ^ ks)
    k = int(sc.argmax())
    rows.append((s, k, float(sc[k]), float(sc[0]), s % 4))
    print(f"  s{s:5d}  best k={k:4d} score={sc[k]:.3f}   "
          f"k=0:{sc[0]:.3f}  s%4={s % 4}  s//4={s // 4}  s%8={s % 8}")

import collections
c = collections.Counter(r[1] for r in rows)
print("\n最优 k 的分布（前 15）:", c.most_common(15))
good = [r for r in rows if r[2] > 0.70]
print(f"\n其中最优 score>0.70 的：{len(good)} 个")
for r in good[:30]:
    print("  ", r)

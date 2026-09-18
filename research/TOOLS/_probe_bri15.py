"""恢复 0076531d.DAT 的解密块结构。

模型（待验证）：磁盘按「块」加密，块 = 连续若干扇区，起点 S 任意；
块内第 k 个扇区用 keystream 偏移 k*4096（来自 buffer_xor_decrypt 对整个
请求缓冲区的连续解密）。
请求参数：起始扇区 = (req>>8)&0xFFFF，扇区数 = (HIBYTE(req)+1)<<2（>=4）。

锚点：记录头魔数 6f 45 62 4e 出现在 16 字节对齐处（4 字节特定序列，
随机碰撞概率极低），可作为判据。
"""
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import MT19937, name_hash, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
raw = F.read_bytes()
N, PAGE = len(raw), 4096
NSEC = N // PAGE
key = name_hash(F.stem)
MAGIC = b"\x6f\x45\x62\x4e"

mt = MT19937(key)
mt.advance(20)
KMAX = 8
KS = struct.pack("<%dI" % (KMAX * PAGE // 4),
                 *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                   for _ in range(KMAX * PAGE // 4)])
KSI = int.from_bytes(KS, "little")


def dec(p: int, k: int) -> bytes:
    blk = raw[p * PAGE:(p + 1) * PAGE]
    ks = KSI >> (k * PAGE * 8) & ((1 << (PAGE * 8)) - 1)
    return ((int.from_bytes(blk, "little") ^ ks)).to_bytes(PAGE, "little")


def magic_hits(d: bytes) -> int:
    return sum(1 for o in range(0, PAGE, 16) if d[o:o + 4] == MAGIC)


# 1) 每个扇区在每个 k 下的魔数命中数
prof = []
for p in range(NSEC):
    row = [magic_hits(dec(p, k)) for k in range(KMAX)]
    prof.append(row)

print("=== 各扇区魔数命中数（列 = k=0..7），前 40 个扇区 ===")
print("      " + "".join(f"k{k} " for k in range(KMAX)))
for p in range(40):
    print(f"  {p:4} " + " ".join(f"{c:2}" for c in prof[p]))

# 2) 每个扇区魔数最多的 k
argk = [max(range(KMAX), key=lambda k: (prof[p][k], -k)) for p in range(NSEC)]
confident = [p for p in range(NSEC) if prof[p][argk[p]] > 0]
print(f"\n有魔数命中的扇区：{len(confident)}/{NSEC}")
print("其 k 分布：", dict(collections.Counter(argk[p] for p in confident)))

print("\n=== 有把握的扇区的 k（前 80 个，'?' = 无魔数）===")
s = ""
for p in range(min(NSEC, 120)):
    s += str(argk[p]) if prof[p][argk[p]] > 0 else "?"
    if (p + 1) % 40 == 0:
        s += "\n"
print(s)

# 3) 检查扇区 348-352
print("\n=== 扇区 345..356 的魔数剖面 ===")
for p in range(345, 357):
    print(f"  {p:4}  " + " ".join(f"{c:2}" for c in prof[p])
          + f"   -> k={argk[p]}  魔数={prof[p][argk[p]]}")

# 4) k 序列是否呈「块内递增」？统计相邻扇区 k 的差
seq = [(p, argk[p]) for p in confident]
diffs = collections.Counter()
for (p1, k1), (p2, k2) in zip(seq, seq[1:]):
    if p2 == p1 + 1:
        diffs[k2 - k1] += 1
print("\n相邻（连续）有把握扇区的 k 差值分布：", dict(diffs))

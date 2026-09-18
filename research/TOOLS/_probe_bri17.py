"""了断：k=0 与 k=1 到底哪个是 0076531d.DAT 的正确解密？

对每个扇区、每个 k 计算两个独立指标：
  (1) 文本性：逐字节走 UTF-8 状态机，统计「构成合法 UTF-8 序列」的字节占比
  (2) 魔数：16 字节对齐处出现 6f 45 62 4e 的次数
正确的 k 应在这两个指标上都显著胜出。
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
PAGE, NSEC = 4096, len(raw) // 4096
key = name_hash(F.stem)
MAGIC = b"\x6f\x45\x62\x4e"

mt = MT19937(key)
mt.advance(20)
KMAX = 4
KS = struct.pack("<%dI" % (KMAX * PAGE // 4),
                 *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                   for _ in range(KMAX * PAGE // 4)])


def dec(p, k):
    blk = raw[p * PAGE:(p + 1) * PAGE]
    return bytes(a ^ b for a, b in zip(blk, KS[k * PAGE:(k + 1) * PAGE]))


def utf8_ratio(d: bytes) -> float:
    """逐字节走 UTF-8 状态机，返回合法序列覆盖的字节占比。"""
    i = n = ok = 0
    L = len(d)
    while i < L:
        b = d[i]
        if b == 0x00:                 # NUL 是串分隔符，计入合法但不推进
            n += 1
            ok += 1
            i += 1
            continue
        if b < 0x80:
            ln = 1
        elif 0xC2 <= b <= 0xDF:
            ln = 2
        elif 0xE0 <= b <= 0xEF:
            ln = 3
        elif 0xF0 <= b <= 0xF4:
            ln = 4
        else:
            n += 1
            i += 1
            continue                  # 非法首字节
        if i + ln > L:
            n += L - i
            break
        try:
            bytes(d[i:i + ln]).decode("utf-8")
            ok += ln
        except UnicodeDecodeError:
            pass
        n += ln
        i += ln
    return ok / n if n else 0.0


def magic(d):
    return sum(1 for o in range(0, PAGE, 16) if d[o:o + 4] == MAGIC)


rows = []
for p in range(NSEC):
    r = []
    for k in range(KMAX):
        d = dec(p, k)
        r.append((utf8_ratio(d), magic(d)))
    rows.append(r)

print("=== 全文件各 k 的指标总和 ===")
for k in range(KMAX):
    tr = sum(r[k][0] for r in rows) / NSEC
    mg = sum(r[k][1] for r in rows)
    print(f"  k={k}  平均文本性={tr:.4f}   魔数总数={mg}")

print("\n=== 每个扇区「文本性」最优的 k 分布 ===")
bt = [max(range(KMAX), key=lambda k: rows[p][k][0]) for p in range(NSEC)]
print("  ", dict(collections.Counter(bt)))

print("\n=== 每个扇区「魔数」最多的 k 分布（只统计有魔数的扇区）===")
bm = [max(range(KMAX), key=lambda k: (rows[p][k][1], -k)) for p in range(NSEC)]
conf = [p for p in range(NSEC) if rows[p][bm[p]][1] > 0]
print(f"  有魔数的扇区 {len(conf)}/{NSEC}")
print("  ", dict(collections.Counter(bm[p] for p in conf)))

print("\n=== 扇区 349 / 350 / 351 的三项指标 ===")
print(f"{'sec':>5} {'k':>2} {'文本性':>8} {'魔数':>5}")
for p in (348, 349, 350, 351, 352):
    for k in range(KMAX):
        print(f"{p:5} {k:2} {rows[p][k][0]:8.4f} {rows[p][k][1]:5}")

print("\n=== 抽样：文本性最优 k != 0 的扇区，看其相邻扇区 ===")
cnt = 0
for p in range(NSEC):
    if bt[p] != 0 and cnt < 25:
        neigh = " ".join(f"{q}:{bt[q]}" for q in range(max(0, p - 2), min(NSEC, p + 3)))
        print(f"  扇区 {p}: 文本性k={bt[p]} 魔数k={bm[p]}({rows[p][bm[p]][1]})  "
              f"邻域[{neigh}]")
        cnt += 1

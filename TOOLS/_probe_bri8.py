"""Probe: 决定性 A/B 测试 —— 0076531d.DAT 的解密粒度是 4096 还是 16384 字节？

在 file+0x1700 处（扇区 1 内）比较两种解密结果。
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import MT19937, name_hash, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
raw = F.read_bytes()
key = name_hash(F.stem)


def ks(nbytes):
    mt = MT19937(key)
    mt.advance(20)
    return bytes(struct.pack("<%dI" % (nbytes // 4),
                             *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                               for _ in range(nbytes // 4)]))


K16 = ks(16384)
TARGET = 0x1700

# A: 逐扇区 —— file[0x1000:0x2000] 用 K16[0:4096]
a = bytes(x ^ y for x, y in zip(raw[0x1000:0x2000], K16[0:4096]))
# B: 4 扇区连续 —— file[0:16384] 用 K16，取 0x1700 处
blk = bytes(x ^ y for x, y in zip(raw[0:16384], K16))
b = blk[TARGET:TARGET + 4096]

print(f"目标：file+{TARGET:#x}（扇区 1 内偏移 {TARGET - 0x1000:#x}）\n")
for tag, d in (("A 逐扇区(4096)", a), ("B 连续(16384)", b)):
    off = TARGET - 0x1000
    c = d[off:off + 64]
    print(f"--- {tag} ---")
    print("  " + " ".join(f"{x:02x}" for x in c[:48]))
    print("  " + repr(d[off:off + 80]))
    try:
        print("  utf8:", d[off:off + 80].decode("utf-8").split("\x00")[0][:60])
    except UnicodeDecodeError as e:
        print(f"  utf8: 解码失败 @{e.start}")
    print()

# 全文件两种假设下的「完全由可打印/UTF-8 组成的 512 字节窗口」数量
def score(dec):
    n = 0
    for o in range(0, len(dec) - 512, 512):
        w = dec[o:o + 512]
        try:
            w.decode("utf-8")
            n += 1
        except UnicodeDecodeError:
            pass
    return n


decA = bytearray(raw)
for p in range(len(raw) // 4096):
    decA[p * 4096:(p + 1) * 4096] = bytes(
        x ^ y for x, y in zip(raw[p * 4096:(p + 1) * 4096], K16[:4096]))
decB = bytearray(raw)
for q in range(len(raw) // 16384):
    decB[q * 16384:(q + 1) * 16384] = bytes(
        x ^ y for x, y in zip(raw[q * 16384:(q + 1) * 16384], K16))
print(f"512 字节窗口 UTF-8 可解码计数： A(逐扇区)={score(decA)}  B(4扇区连续)={score(decB)}")

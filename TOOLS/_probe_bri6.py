"""Probe: 按「分段独立解密」假设，在 0076531d.DAT 全盘枚举 BRIEFING 记录。

依据
----
briefing_dat_load @ 0x1400A5570:
    buffer_xor_decrypt(buf, sectors << 12, name_hash("0076531d"))
每次请求都重新用 key 播种 MT（buffer_xor_decrypt 内部 mt_seed + advance(20)），
故密钥流只与「块内偏移」有关，与文件绝对偏移无关。块起点 = 请求的起始扇区，
块长 = 4*(HIBYTE(req)+1) 个扇区（briefing_dat_request_pages @ 0x140804220）。

做法：把每个扇区 p 都当作可能的块起点，用「块内偏移 0 起」的密钥流解密其后
16 KiB，再在头 4096 字节内找记录头（sub_1400A3230 语义）。
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import MT19937, buffer_xor_decrypt, name_hash, XOR_CONST

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
raw = F.read_bytes()
N = len(raw)
key = name_hash(F.stem)
PAGE = 4096
WIN = 16384

# 块内密钥流（对所有候选起点相同）
mt = MT19937(key)
mt.advance(20)
ks = struct.pack("<%dI" % (WIN // 4), *[(mt.next() ^ XOR_CONST) & 0xFFFFFFFF
                                        for _ in range(WIN // 4)])
KS = int.from_bytes(ks, "little")

print(f"{F.name}  size={N:#x} ({N})  sectors={N // PAGE}  key={key:#010x}")


def dec_at(p: int) -> bytes:
    """把扇区 p 当作块起点，解密其后 WIN 字节"""
    b = raw[p * PAGE:p * PAGE + WIN]
    if len(b) < WIN:
        b = b + b"\x00" * (WIN - len(b))
    v = int.from_bytes(b, "little") ^ KS
    return v.to_bytes(WIN, "little")


def scan(dec: bytes, base_off: int, limit: int = 4096):
    """在 dec[0:limit] 内找记录头，返回 [(a1_abs, v5, v10, offs..., p1, p2, cnt)]"""
    nd = len(dec) // 4
    dw = list(struct.unpack("<%dI" % nd, dec[:nd * 4]))
    out = []
    for i in range(0, limit // 4 - 4):
        o0, o1, o2, o3 = dw[i], dw[i + 1], dw[i + 2], dw[i + 3]
        if o1 >= o2 or not (4 <= o2 - o1 <= 0x20000) or ((o2 - o1) & 3):
            continue
        v10 = 4 * i
        p1, p2 = v10 + o1, v10 + o2
        if p2 >= nd:
            continue
        cnt = (p2 - p1) // 4
        if cnt < 1 or cnt > 4096:
            continue
        j0 = p1 // 4
        if dw[j0] != 0:
            continue
        prev, ok = 0, True
        for k in range(1, cnt):
            v = dw[j0 + k]
            if v <= prev:
                ok = False
                break
            prev = v
        if not ok:
            continue
        e = dec.find(b"\x00", p2, min(len(dec), p2 + 4096))
        if e < 0:
            continue
        s = dec[p2:e]
        if not (2 <= len(s) <= 2000):
            continue
        try:
            s.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # 反推 a1：v10 = a1 + 12 + 8*v5，且 u32@(a1+4+4*v5) 是首个 -1
        for v5 in range(0, 513):
            a1 = v10 - 12 - 8 * v5
            if a1 < 0 or (a1 & 3):
                continue
            if dw[(a1 + 4 + 4 * v5) // 4] != 0xFFFFFFFF:
                continue
            if any(dw[(a1 + 4 + 4 * k) // 4] == 0xFFFFFFFF for k in range(v5)):
                continue
            out.append((base_off + a1, v5, base_off + v10, o0, o1, o2, o3,
                        base_off + p1, base_off + p2, cnt, s))
            break
    return out


alls = []
for p in range(N // PAGE):
    r = scan(dec_at(p), p * PAGE)
    if r:
        alls.append((p, r))

print(f"\n块起点（扇区）命中 {len(alls)} 个")
tot = 0
for p, r in alls:
    print(f"\n=== 扇区 {p} (file {p * PAGE:#x}) ===  记录 {len(r)} 条")
    tot += len(r)
    for a1, v5, v10, o0, o1, o2, o3, p1, p2, cnt, s in r:
        print(f"  a1={a1:#08x} (idx={a1 / 16:.2f}) v5={v5} n={cnt:<4} "
              f"{s.decode('utf-8')[:64]}")
print(f"\n记录总数 {tot}")

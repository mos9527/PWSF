"""Debug: 为什么 a1=0 未被 _probe_bri3 命中"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
F = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
dec = bytes(buffer_xor_decrypt(bytearray(F.read_bytes()), name_hash(F.stem)))
N = len(dec)
u32 = lambda o: struct.unpack_from("<I", dec, o)[0]

print("N =", hex(N))
for a1 in (0, 0x4A0, 0xA80):
    p = a1 + 4
    v5 = 0
    while p + 4 <= N and u32(p) != 0xFFFFFFFF:
        v5 += 1
        p += 4
        if v5 > 256:
            break
    v10 = a1 + 12 + 8 * v5
    print(f"\na1={a1:#x}  v5={v5}  v10={v10:#x}")
    if v10 + 16 > N:
        print("   v10 out of range")
        continue
    o0, o1, o2, o3 = (u32(v10), u32(v10 + 4), u32(v10 + 8), u32(v10 + 12))
    print(f"   off = {o0} {o1} {o2} {o3}")
    p1, p2 = v10 + o1, v10 + o2
    print(f"   p1={p1:#x} p2={p2:#x}  diff={p2 - p1}  mod4={(p2 - p1) % 4}")
    if not (0 <= p1 < p2 < N):
        print("   -> 范围检查失败")
        continue
    if (p2 - p1) % 4 or not (4 <= p2 - p1 <= 0x20000):
        print("   -> 长度检查失败")
        continue
    cnt = (p2 - p1) // 4
    vals = [u32(p1 + 4 * i) for i in range(cnt)]
    print(f"   cnt={cnt}  vals[:16]={vals[:16]}")
    print(f"   vals[0]={vals[0]}")
    inc = all(vals[i] < vals[i + 1] for i in range(cnt - 1))
    print(f"   递增={inc}")
    s = dec[p2:p2 + 64].split(b"\x00")[0]
    print(f"   首段({len(s)}B) = {s[:60]!r}")
    try:
        s.decode("utf-8")
        print("   utf8 OK ->", s.decode("utf-8")[:60])
    except UnicodeDecodeError as e:
        print(f"   utf8 FAIL @{e.start}: {s[:60]!r}")

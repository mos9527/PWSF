"""Probe: 0076531d.DAT == BRIEFING (CODEC) data?"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
f = GAME / "MLG" / "disc0_rel" / "0076531d.DAT"
raw = bytearray(f.read_bytes())
key = name_hash(f.stem)                      # name_hash("0076531d")
print(f"{f.name} size={len(raw):#x} key={key:#010x}  sectors={len(raw)>>12}")

dec = bytes(buffer_xor_decrypt(bytearray(raw), key))


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7F or x in (9, 10, 13)) / len(b)


print(f"printable as-is = {printable_ratio(raw[:4096]):.3f}")
print(f"printable dec   = {printable_ratio(dec[:4096]):.3f}")
print("DEC head:")
for off in range(0, 160, 16):
    c = dec[off:off + 16]
    print(f"    {off:04x}  {' '.join(f'{b:02x}' for b in c):<47}  "
          + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))

# 扫描可读 ASCII 串
import re
hits = [m for m in re.finditer(rb"[\x20-\x7e]{8,}", dec)]
print(f"\nASCII runs >=8: {len(hits)}")
for m in hits[:30]:
    print(f"    @{m.start():#x}  {m.group()[:90]!r}")

# UTF-8 日文检测
u8 = dec.decode("utf-8", "ignore")
jp = re.findall(r"[぀-ヿ一-鿿]{4,}", u8)
print(f"\nJP-ish runs >=4: {len(jp)}")
for s in jp[:15]:
    print(f"    {s[:70]!r}")

"""Probe: is .xsx (subtitle) encrypted the same way as .olang?"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pwsf_crypto import name_hash, buffer_xor_decrypt

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")

FILES = [
    "MLG/data/Mov/00348273.xsx",
    "MLG/data/Mov/004bc514.xsx",
    "EXLANG/data/Mov/0019f5e1.xsx",
    "MLG/data/hqMov/008f5eec.xsx",
]


def hd(buf: bytes, n: int = 64) -> str:
    out = []
    for off in range(0, min(n, len(buf)), 16):
        c = buf[off:off + 16]
        out.append(f"    {off:04x}  {' '.join(f'{b:02x}' for b in c):<47}  "
                   + "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c))
    return "\n".join(out)


for rel in FILES:
    f = GAME / rel.replace("/", "\\")
    raw = bytearray(f.read_bytes())
    name = f.stem
    for cand in (name, f.name, "./" + rel):
        k = name_hash(cand)
        d = bytes(buffer_xor_decrypt(bytearray(raw), k))
        print(f"\n=== {rel} len={len(raw)}  key({cand!r})={k:#010x}")
        print(hd(d))
        if d[:4].isalpha():
            print("    >>> looks like ASCII magic")
        break
    print("  RAW:")
    print(hd(bytes(raw)))

"""SLOT.DAT / SLOT.KEY: first look.

The mount table at 0x140e9d6e0 (208 bytes per slot, base pointer
off_140EA4220 @ 0x140EA4220) pairs every hashed disc0 filename with the plain
host0: debug name of the same slot:

    slot  0   009645fa.PDT   STAGEDAT.PDT
    slot  1   002aba34.DAT   SLOT.DAT
    slot  3   0001112d.PDT   BGM.PDT
    slot  4   00b2b2a8.PDT   VOICEBF.PDT
    slot  5   00b2b4b6.PDT   VOICERT.PDT
    slot  6   00b2b475.PDT   VOICEPS.PDT
    slot 13   002aba34.KEY   SLOT.KEY
    slot 14   0076531d.DAT   BRIEFING.DAT

bigdat_load_and_verify @ 0x1400A6290 confirms the stride: it calls
name_hash(off_140EA4220 + 208), i.e. slot 1 = "002aba34.DAT".

BRIEFING.DAT is encrypted per 4096-byte sector, each sector independently
seeded with name_hash(stem) (03_codec.md section 1.1).  This probe tries the
same two models on SLOT.KEY and on the head of SLOT.DAT and reports which
produces structure.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096


def printable_frac(b: bytes) -> float:
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / max(1, len(b))


def hexdump(blob: bytes, n: int = 256, base: int = 0) -> str:
    out = []
    for off in range(0, min(n, len(blob)), 16):
        row = blob[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"    {base + off:06x}  {hx:<47}  {asc}")
    return "\n".join(out)


def per_sector(raw: bytes, key: int) -> bytes:
    out = bytearray()
    for off in range(0, len(raw), SECTOR):
        chunk = bytearray(raw[off:off + SECTOR])
        buffer_xor_decrypt(chunk, key)
        out += chunk
    return bytes(out)


def continuous(raw: bytes, key: int) -> bytes:
    buf = bytearray(raw)
    buffer_xor_decrypt(buf, key)
    return bytes(buf)


def report(tag: str, blob: bytes) -> None:
    print(f"  [{tag}] printable={printable_frac(blob[:0x2000]):.3f} "
          f"zeros={blob[:0x2000].count(0)}")
    print(hexdump(blob))


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    for name, cap in (("002aba34.KEY", None), ("002aba34.DAT", 3 * SECTOR)):
        path = C.pristine(root / name)
        try:
            with open(path, "rb") as fh:
                raw = fh.read() if cap is None else fh.read(cap)
        except OSError as exc:
            print(f"== {name}: open failed ({exc}); close the game and retry")
            continue
        key = name_hash(path.stem)
        print(f"== {name}  size={len(raw)}  key={key:#010x}")
        report("raw", raw)
        report("per-4096", per_sector(raw, key))
        report("continuous", continuous(raw, key))


if __name__ == "__main__":
    main()

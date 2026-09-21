"""Probe: is there a second BRIEFING corpus?  (EXLANG/disc0_rel/0076531d.DAT)

`ANALYSIS/03_codec.md` and `pwsf.briefing` both read `MLG/disc0_rel/0076531d.DAT`
(4,142,432 B).  There is a SECOND copy under `EXLANG/disc0_rel/`, and it is
24,416 bytes LARGER, so it is not a byte-for-byte duplicate.  EXLANG is the
extra-language (pt/sp) pack, so its copy may hold extra records -- and the
still-missing in-mission radio line

    "There's no one around - why not try some shooting practice?"  (Miller)

has never been looked for there.

Decryption is the one proven for this file (03 §1.1): per 4096-byte sector,
`buffer_xor_decrypt(sector, name_hash("0076531d"))`.

Usage:  python _probe_briefing_exlang.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf.crypto import buffer_xor_decrypt, name_hash    # noqa: E402

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
KEY = name_hash("0076531d")
SECTOR = 4096
NEEDLES = [b"shooting practice", b"no one around", b"there's no one",
           b"Investigate the Supply"]


def decrypt(path: Path) -> bytes:
    raw = path.read_bytes()
    out = bytearray()
    for off in range(0, len(raw), SECTOR):
        blk = bytearray(raw[off:off + SECTOR])
        buffer_xor_decrypt(blk, KEY)
        out += blk
    return bytes(out)


def report(path: Path) -> None:
    plain = decrypt(path)
    print(f"\n{path.parent.parent.name}/{path.name}: "
          f"{path.stat().st_size} bytes")
    low = plain.lower()
    for nd in NEEDLES:
        i = low.find(nd.lower())
        print(f"  {nd!r:<28} {'@ %#x' % i if i >= 0 else 'not found'}")
        if i >= 0:
            print("     ", plain[max(0, i - 80):i + len(nd) + 80])
    nz = [c for c in plain if c]
    good = sum(1 for c in nz if 32 <= c < 127) / max(len(nz), 1)
    print(f"  printable (non-zero) {good:.2f}")


def main() -> None:
    for rel in ("MLG/disc0_rel/0076531d.DAT",
                "EXLANG/disc0_rel/0076531d.DAT"):
        p = GAME / rel.replace("/", "\\")
        if p.is_file():
            report(p)
        else:
            print(f"{rel}: missing")


if __name__ == "__main__":
    main()

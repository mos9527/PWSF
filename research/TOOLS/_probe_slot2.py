"""SLOT.KEY index -> SLOT.DAT entries, and a grep for the cutscene line.

_probe_slot1 showed 002aba34.KEY (= SLOT.KEY, mount slot 13) decrypts with the
ordinary buffer_xor_decrypt using key = name_hash("002aba34"), and that the
plaintext is a flat table:

    +0x00   12 B  header
    +0x0c   20 B  per record, (42752 - 12) / 20 = 2137 records exactly

Record fields, read off the running sector numbers in the dump:

    +0x00  u16  start sector   (== previous record's end)
    +0x02  u16  ?
    +0x04  u16  end sector
    +0x06  u16  ?
    +0x08  u32  hash
    +0x0c  u32  ?
    +0x10  u32  sector count   (== end - start, verified below)

This probe checks those invariants, then decrypts entries out of SLOT.DAT and
greps for the comic-cutscene line from the 2026-09-18 screenshot.
"""

import re
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import config as C
from pwsf.crypto import buffer_xor_decrypt, name_hash

SECTOR = 4096
REC = 20
HDR = 12
NEEDLES = (b"offshore", b"OFFSHORE", b"SOME ROOTS", b"some roots")
PRINTABLE = re.compile(rb"[ -~]{6,}")


def load_key(path: Path):
    raw = path.read_bytes()
    buf = bytearray(raw)
    buffer_xor_decrypt(buf, name_hash(path.stem))
    n, rem = divmod(len(buf) - HDR, REC)
    recs = [struct.unpack_from("<HHHHIII", buf, HDR + REC * i) for i in range(n)]
    return bytes(buf[:HDR]), recs, rem


def check(recs) -> None:
    contiguous = sum(1 for a, b in zip(recs, recs[1:]) if a[2] == b[0])
    counted = sum(1 for r in recs if r[6] == r[2] - r[0])
    print(f"  records={len(recs)}  start==prev_end: {contiguous}/{len(recs) - 1}"
          f"  count==end-start: {counted}/{len(recs)}")
    print(f"  sector range: {min(r[0] for r in recs)}..{max(r[2] for r in recs)}")
    for tag, col in (("f1", 1), ("f3", 3), ("f5", 5)):
        print(f"  {tag} top: {Counter(r[col] for r in recs).most_common(8)}")


def main() -> None:
    root = C.require_game() / "MLG" / "disc0_rel"
    hdr, recs, rem = load_key(C.pristine(root / "002aba34.KEY"))
    print(f"== SLOT.KEY  header={hdr.hex(' ')}  leftover={rem}")
    check(recs)
    for r in recs[:6]:
        print(f"    {r}")

    dat = C.pristine(root / "002aba34.DAT")
    try:
        fh = open(dat, "rb")
    except OSError as exc:
        print(f"== SLOT.DAT open failed ({exc}); close the game and retry")
        return
    size = dat.stat().st_size
    print(f"== SLOT.DAT size={size} ({size // SECTOR} sectors)  "
          f"key={name_hash(dat.stem):#010x}")
    key = name_hash(dat.stem)
    with fh:
        hits = 0
        magics = Counter()
        for i, r in enumerate(recs):
            start, _, _, _, h, _, nsec = r
            fh.seek(start * SECTOR)
            raw = fh.read(nsec * SECTOR)
            if len(raw) < nsec * SECTOR:
                print(f"  rec {i}: truncated at sector {start}")
                break
            # BRIEFING.DAT is keyed per 4096-byte sector; try that first
            out = bytearray()
            for off in range(0, len(raw), SECTOR):
                chunk = bytearray(raw[off:off + SECTOR])
                buffer_xor_decrypt(chunk, key)
                out += chunk
            blob = bytes(out)
            magics[blob[:4]] += 1
            for needle in NEEDLES:
                at = blob.find(needle)
                if at >= 0:
                    hits += 1
                    print(f"  HIT rec={i} sector={start} n={nsec} hash={h:#010x} "
                          f"at={at:#x}")
                    print("      " + repr(blob[max(0, at - 150):at + 250]))
                    break
            if i < 3:
                print(f"  rec {i} head: {blob[:64].hex(' ')}")
                print(f"       strings: {PRINTABLE.findall(blob[:0x1000])[:8]}")
        print(f"  magics: {magics.most_common(10)}")
        print(f"  hits: {hits}")


if __name__ == "__main__":
    main()

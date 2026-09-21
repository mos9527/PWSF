"""Probe: what IS `STW000000ac1d01` (325,968 B) and where is the mission title?

Step 2 of the save-file investigation.  The file is not plaintext (printable
0.33) and `buffer_xor_decrypt(name_hash(basename))` does not reveal the title,
so before guessing keys this probe just describes the bytes:

  - byte histogram (a single-byte XOR shows up as one dominant value)
  - period detection: autocorrelation of the first 4096 bytes against shifts
  - per-4096-sector printable ratio (the BRIEFING file is sector-keyed, so a
    sector that is NOT keyed with the others would stand out)
  - magic scan for embedded images (the save slot shows a portrait thumbnail,
    so a JPEG/BMP/PNG header inside is a strong plaintext oracle)
  - zlib / known-magic scan at every 16-byte aligned offset

Usage:  python _probe_savedata2.py [--file PATH]
"""
import argparse
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_crypto as C

SAVE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW"
            r"\mgspw_savedata_win\76561199148085959\ww\STW000000ac1d01")

MAGICS = [b"\xff\xd8\xff", b"BM", b"\x89PNG", b"RIFF", b"GIF8",
          b"\x78\xda", b"\x78\x9c", b"PK\x03\x04", b"RBX\x00"]

NEEDLES = [b"Investigate the Supply", b"shooting practice",
           b"no one around", b"Opening"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(SAVE))
    args = ap.parse_args()
    data = Path(args.file).read_bytes()
    print(f"{Path(args.file).name}: {len(data)} bytes")

    n = len(data)
    print("\ntop bytes:", Counter(data).most_common(8))

    # autocorrelation: is there a repeating keystream period?
    head = data[:4096]
    best = []
    for shift in range(1, 2049):
        same = sum(1 for i in range(2048) if head[i] == head[i + shift])
        best.append((same / 2048, shift))
    best.sort(reverse=True)
    print("autocorr top:", [(f"{r:.3f}", s) for r, s in best[:5]])

    # per-sector printable ratio
    sect = [data[i:i + 4096] for i in range(0, n, 4096)]
    ratios = [sum(1 for c in s if 32 <= c < 127) / len(s) for s in sect]
    print(f"\nsectors: {len(sect)}  printable min={min(ratios):.2f} "
          f"max={max(ratios):.2f} mean={sum(ratios) / len(ratios):.2f}")
    print("  first 12:", [f"{r:.2f}" for r in ratios[:12]])

    print("\nmagic scan:")
    for m in MAGICS:
        start, cnt = 0, 0
        while True:
            i = data.find(m, start)
            if i < 0:
                break
            cnt += 1
            start = i + 1
            if cnt <= 3:
                print(f"  {m.hex():12} @ {i:#x}  {data[i:i + 24].hex()}")
        print(f"  {m.hex():12} total {cnt}")

    print("\nzlib attempt on every 4-byte offset of the first 64 KiB:")
    ok = 0
    for off in range(0, min(len(data), 1 << 16), 4):
        try:
            body = zlib.decompressobj().decompress(data[off:])
        except zlib.error:
            continue
        if len(body) > 256:
            print(f"  @{off:#x} -> {len(body)} B  {body[:32]!r}")
            ok += 1
            if ok > 6:
                break

    print("\nneedle scan (raw):",
          {nd.decode(): data.lower().find(nd) for nd in NEEDLES})

    print("\nname_hash candidates:")
    for cand in ["STW000000ac1d01", "STW000000", "ww", "usersv",
                 "EU_SYSTEM.DAT", "STW000000ac1d01.dat", "STW"]:
        k = C.name_hash(cand)
        buf = bytes(C.buffer_xor_decrypt(bytearray(data[:65536]), k))
        good = sum(1 for c in buf if 32 <= c < 127) / len(buf)
        print(f"  {cand:22} key={k:#010x} printable={good:.2f} "
              f"{buf[:24].hex()}")


if __name__ == "__main__":
    main()

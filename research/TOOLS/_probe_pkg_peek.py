"""Probe: peek at one container's payloads -- are they STAGEDAT-shaped?

Checks, per entry: mode 0x100 / 0x40 unmask, then whether the plaintext is a
zlib stream, an "SP" container, or plain.  Also reports whether a zlib stream
inflates into the same inner file archive we proved for STAGEDAT (u32 count +
NUL-terminated names, 4-pad, u32 size, data at the next 16-byte boundary).

This is the cheap reconnaissance step before sweeping the multi-GB mission
packages (ADEMO / ADEMOHQ), which is where the still-missing codec hint
"There's no one around - why not try some shooting practice?" should live.
"""
import argparse
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_crypto as C

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
MASK32 = 0xFFFFFFFF


def unmask(arc, blob: bytes) -> bytes:
    """MT layer, then the second stage: mode 0x100 byte xor / mode 0x40 LCG.

    The mode 0x40 seeding is the one cracked by _probe_stagedat.py: the LCG
    restarts from the DERIVED (state, inc) for every entry -- CRC-32 of the
    payload is 6/6 under it and 0/6 under "continues across entries".
    """
    buf = C.buffer_xor_decrypt(bytearray(blob), arc.key)
    if arc.mode == 0x100:
        return bytes(buf.translate(bytes(i ^ (arc.lo & 0xFF)
                                         for i in range(256))))
    if arc.mode == 0x40:
        s = (arc.hi ^ arc.lo) & MASK32
        state = (s | ((s ^ 0x6576) << 16)) & MASK32
        inc = (arc.m * s) & MASK32
        dwords = len(buf) & ~3
        if dwords:
            A._unmask_lcg(memoryview(buf)[:dwords], state, inc)
        return bytes(buf)
    return bytes(buf)


def inflate(plain: bytes) -> tuple:
    if plain[4:6] == b"\x78\xda":
        raw, off = plain[4:], 4
    elif plain[:2] == b"\x78\xda":
        raw, off = plain[2:], 2
    else:
        return None, "raw"
    try:
        return zlib.decompressobj().decompress(raw), f"zlib@{off}"
    except zlib.error:
        return None, "zlib_fail"


def describe(plain: bytes) -> str:
    if plain[4:6] == b"\x78\xda":
        raw, off = plain[4:], 4
    elif plain[:2] == b"\x78\xda":
        raw, off = plain[2:], 2
    else:
        return f"plain magic={plain[:4].hex()} {plain[:4]!r}"
    try:
        body = zlib.decompressobj().decompress(raw)
    except zlib.error as ex:
        return f"zlib@{off} FAIL {ex}"
    kind = ""
    if len(body) >= 4:
        count, = struct.unpack_from("<I", body, 0)
        end = body.find(b"\x00", 4)
        if 0 < count <= 4096 and 0 < end - 4 <= 256:
            kind = (f" inner-archive count={count} "
                    f"first={body[4:end].decode('latin-1')!r}")
    return f"zlib@{off} {len(plain)}->{len(body)}{kind}"


def sentences(body: bytes) -> list:
    """Sentence-looking ASCII runs: has a space, mostly letters, >= 16 chars."""
    import re as _re
    out = []
    for m in _re.finditer(rb"[ -~]{16,}", body):
        s = m.group().strip()
        if b" " not in s:
            continue
        letters = sum(1 for c in s if 65 <= c <= 90 or 97 <= c <= 122)
        if letters / len(s) > 0.75:
            out.append(s.decode("latin-1"))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("rel", help="path relative to the game dir")
    ap.add_argument("--entries", type=int, default=8)
    ap.add_argument("--zlib", type=int, default=0,
                    help="peek this many payloads that inflate but are NOT the "
                         "STAGEDAT inner archive (head bytes + ASCII runs)")
    ap.add_argument("--zlib-text", action="store_true",
                    help="for EVERY inflated payload, report sentence-like "
                         "ASCII runs (finds text archives with another layout)")
    args = ap.parse_args()
    p = GAME / args.rel
    size = p.stat().st_size
    with p.open("rb") as f:
        arc = A.parse(f.read(8 << 20), p.stem, str(p), max_entries=200000)
    probs = A.verify(arc, size)
    print(f"{args.rel}: mode={arc.mode:#x} count={arc.count} "
          f"{'ok' if not probs else probs[:1]}")
    if args.zlib_text:
        with p.open("rb") as f:
            for i in range(arc.count):
                e = arc.entries[i]
                f.seek(e.c)
                plain = unmask(arc, f.read(e.a))
                body, note = inflate(plain)
                if body is None:
                    continue
                s = sentences(body)
                if len(s) >= 3:
                    print(f"  entry {i:4d} {len(plain):>#10x}->{len(body):<9d} "
                          f"{len(s):4d} sentences")
                    for x in s[:4]:
                        print(f"        {x[:100]}")
        return

    with p.open("rb") as f:
        shown = 0
        for i in range(arc.count):
            if shown >= args.entries and not args.zlib:
                break
            e = arc.entries[i]
            f.seek(e.c)
            plain = unmask(arc, f.read(e.a))
            ok = A.entry_crc(plain) == e.b
            desc = describe(plain)
            want = (not args.zlib) or ("inner-archive" not in desc
                                       and desc.startswith("zlib@"))
            if not want:
                continue
            shown += 1
            print(f"  entry {i:3d} size={e.a:#x} crc={'ok' if ok else 'BAD'} "
                  f"{desc}")
            if args.zlib:
                raw = plain[4:] if plain[4:6] == b"\x78\xda" else plain[2:]
                body = zlib.decompressobj().decompress(raw)
                print(f"       head={body[:48]!r}")
                import re as _re
                runs = [m.group().decode("latin-1")
                        for m in _re.finditer(rb"[ -~]{8,}", body)][:6]
                print(f"       ascii={runs}")
                shown += 0
            if shown >= (args.zlib or args.entries):
                break


if __name__ == "__main__":
    main()

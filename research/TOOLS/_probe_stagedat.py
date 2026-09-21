"""Probe: crack the mode 0x40 payload unmask (STAGEDAT = 009645fa.PDT).

Why: the codec hint "There's no one around - why not try some shooting
practice?" is in none of the extracted corpora, and 009645fa.PDT
(487 MB, 557 entries, the only mode 0x40 container) is the last unreadable
text-bearing candidate.  04_archive.md §6.2 lists it as unresolved because
the LCG seed lives at pkg+196 (state) / pkg+200 (inc), written outside
archive_index_load.

Evidence used here (IDA, imagebase 0x140000000):
  entry_payload_transform 0x140123E90  mode 0x40:
      for each whole dword: *p ^= state; state = inc + 48828125 * state;
      and it WRITES state back to pkg+196 -> the stream continues across
      entries read from the same package.
  sub_140123DB0 (key derive, used for header/index/names):
      s = hi ^ lo; state = s | ((s ^ 0x6576) << 16); inc = m * s

Oracle: entry.b == crc32(payload[:size & ~3])  (04_archive.md §4), so any
candidate seeding can be confirmed without knowing the plaintext.

Candidates tested:
  A fresh      each entry restarts from the derived (state, inc)
  B continued  entry 0 starts where the header/index/names stream ended and
               the stream runs on across entries (matches the write-back)
  C none       MT layer only (no LCG at all)
"""
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
STAGE = GAME / "MLG" / "disc0_rel" / "009645fa.PDT"
MASK32 = 0xFFFFFFFF
HEAD_CAP = 8 << 20


def lcg_xor(buf: bytearray, state: int, inc: int) -> int:
    """In-place dword LCG xor (replicates 0x140123E90 mode 0x40)."""
    return A._unmask_lcg(buf, state, inc)


def mt_layer(blob: bytes, key: int) -> bytearray:
    """Step 1 of the pipeline: buffer_xor_decrypt with a fresh MT state."""
    return A.buffer_xor_decrypt(bytearray(blob), key) \
        if hasattr(A, "buffer_xor_decrypt") else None


def main() -> None:
    import pwsf_crypto as C
    size = STAGE.stat().st_size
    with STAGE.open("rb") as f:
        head = f.read(HEAD_CAP)
    arc = A.parse(head, STAGE.stem, str(STAGE), max_entries=200000)
    print(f"{STAGE.name}: mode={arc.mode:#x} lo={arc.lo:#x} hi={arc.hi:#x} "
          f"m={arc.m:#x} count={arc.count} size={size:#x}")
    probs = A.verify(arc, size)
    print(f"  self-check: {probs or 'ok'}")

    s = (arc.hi ^ arc.lo) & MASK32
    state0 = (s | ((s ^ 0x6576) << 16)) & MASK32
    inc = (arc.m * s) & MASK32
    print(f"  derived: state0={state0:#x} inc={inc:#x}")

    # where the header/index/names stream ended (28 + 12n + 24n bytes)
    n = arc.count
    after_tables = state0
    for _ in range((28 + 12 * n + 24 * n) >> 2):
        after_tables = (inc + 48828125 * after_tables) & MASK32
    print(f"  state after header+index+names: {after_tables:#x}")

    # pick a few small entries as the oracle (cheap, and CRC covers them fully)
    order = sorted(range(arc.count), key=lambda i: arc.entries[i].a)[:6]
    print(f"  oracle entries (smallest): {order}")

    with STAGE.open("rb") as f:
        blobs = {}
        for i in order:
            e = arc.entries[i]
            f.seek(e.c)
            blobs[i] = f.read(e.a)

    def check(name, state_of):
        """state_of(entry_index) -> (state, inc) to start that entry with."""
        ok = 0
        for i in order:
            blob = blobs[i]
            st, ic = state_of(i)
            buf = C.buffer_xor_decrypt(bytearray(blob), arc.key)
            dwords = len(blob) & ~3
            if dwords:
                st = lcg_xor(memoryview(buf)[:dwords], st, ic)
            plain = bytes(buf)
            if A.entry_crc(plain) == arc.entries[i].b:
                ok += 1
                if ok == 1:
                    print(f"    first plaintext of entry {i}: "
                          f"{plain[:48]!r}")
        print(f"  {name}: CRC ok {ok}/{len(order)}")
        return ok == len(order)

    # A: fresh per entry
    check("A fresh (state0, inc)", lambda i: (state0, inc))

    # C: no LCG at all
    def none_state(i):
        return None, None
    ok = 0
    for i in order:
        blob = blobs[i]
        plain = bytes(C.buffer_xor_decrypt(bytearray(blob), arc.key))
        if A.entry_crc(plain) == arc.entries[i].b:
            ok += 1
    print(f"  C MT-only: CRC ok {ok}/{len(order)}")

    # B: continuous stream, entries in file order (offset order)
    file_order = sorted(range(arc.count), key=lambda i: arc.entries[i].c)
    state_by_entry = {}
    st = after_tables
    for i in file_order:
        state_by_entry[i] = st
        dwords = len(blobs[i]) if i in blobs else arc.entries[i].a
        st = (inc + 48828125 * st) & MASK32  # placeholder, refined below
    # recompute properly: advance by the dword count of each entry
    st = after_tables
    for i in file_order:
        state_by_entry[i] = st
        nd = (arc.entries[i].a & ~3) >> 2
        for _ in range(nd):
            st = (inc + 48828125 * st) & MASK32
    check("B continued (stream across entries)",
          lambda i: (state_by_entry[i], inc))

    # --- A confirmed: sweep every entry, zlib-inflate, look for the line -----
    import re
    import zlib
    NEEDLES = [b"shooting practice", b"no one around"]
    RUN_RE = re.compile(rb"[ -~]{12,}")
    TSV = Path(__file__).resolve().parent.parent / "ANALYSIS" / \
        "_stagedat_preview.tsv"
    rows, hits = [], []
    t0 = time.time()
    with STAGE.open("rb") as f:
        for i in range(arc.count):
            e = arc.entries[i]
            f.seek(e.c)
            blob = f.read(e.a)
            buf = C.buffer_xor_decrypt(bytearray(blob), arc.key)
            dwords = len(buf) & ~3
            if dwords:
                lcg_xor(memoryview(buf)[:dwords], state0, inc)
            plain = bytes(buf)
            note = ""
            body = plain
            if plain[4:6] == b"\x78\xda" or plain[:2] == b"\x78\xda":
                raw = plain[4:] if plain[4:6] == b"\x78\xda" else plain[2:]
                try:
                    body = zlib.decompressobj().decompress(raw)
                    note = f"zlib {len(plain)}->{len(body)}"
                except zlib.error as ex:
                    note = f"zlib_fail {ex}"
                    body = plain
            low = body.lower()
            for nd in NEEDLES:
                if nd in low:
                    hits.append((i, e.c, nd, low.find(nd)))
            strs = [m.group().strip() for m in RUN_RE.finditer(body)]
            rows.append((i, f"{e.c:#x}", e.a, len(body), note,
                         " | ".join(s.decode("latin-1")[:80]
                                    for s in strs[:3])))
            if i % 50 == 0:
                print(f"  [{i}/{arc.count}] {time.time() - t0:.0f}s")
    print(f"  swept {arc.count} entries in {time.time() - t0:.0f}s")

    with TSV.open("w", encoding="utf-8") as f:
        f.write("entry\toff\tsize\tinflated\tnote\tsamples\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    print(f"  preview -> {TSV.name} ({len(rows)} rows)")
    print("NEEDLE HITS:", hits or "none")
    rows.sort(key=lambda r: -int(r[5].count(" | ")))
    for r in rows[:20]:
        print(f"  e{r[0]:<4} {r[3]:>9} B {r[4]:<22} {r[5][:110]}")


if __name__ == "__main__":
    main()

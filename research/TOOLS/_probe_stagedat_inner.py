"""Probe: the inner file archive inside STAGEDAT payloads, and its .olang tables.

Chain (each step independently verified):
  009645fa.PDT entry payload
    -> buffer_xor_decrypt(name_hash(stem))        04_archive.md §4 step 1
    -> LCG unmask, FRESH per entry:
         s = hi ^ lo; state = s | ((s ^ 0x6576) << 16); inc = m * s
         (0x140123E90 mode 0x40; confirmed by _probe_stagedat.py: CRC 6/6,
          whereas MT-only and "stream continues across entries" both fail)
    -> u32 header + zlib stream (0x78 0xda)
    -> inner file archive:  u32 name_len; name[name_len]; pad to 4;
         u32 size; u32 u1; u32 u2; data[size]      (u1/u2 == 0 so far)
    -> inner *.olang are plain RBX tables          01_olang_text.md

Why this matters: the 17 on-disk .olang files are NOT the whole corpus.
STAGEDAT ships per-mission inner archives with lang_*.olang tables whose text
was never extracted.  The codec hint
    "There's no one around - why not try some shooting practice?"
is the test case.

Outputs: ANALYSIS/_stagedat_files.tsv   every inner file
         ANALYSIS/_stagedat_olang.tsv   every string of every inner olang
"""
import struct
import sys
import time
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_crypto as C
import pwsf_olang as O

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
STAGE = GAME / "MLG" / "disc0_rel" / "009645fa.PDT"
ROOT = Path(__file__).resolve().parent.parent
FILES_TSV = ROOT / "ANALYSIS" / "_stagedat_files.tsv"
OLANG_TSV = ROOT / "ANALYSIS" / "_stagedat_olang.tsv"
MASK32 = 0xFFFFFFFF
NEEDLES = [b"shooting practice", b"no one around"]


def payload(arc, blob, state0, inc) -> bytes:
    buf = C.buffer_xor_decrypt(bytearray(blob), arc.key)
    dwords = len(buf) & ~3
    if dwords:
        A._unmask_lcg(memoryview(buf)[:dwords], state0, inc)
    return bytes(buf)


def inflate(plain: bytes) -> tuple:
    """u32 + zlib stream -> (body, note)."""
    if plain[4:6] == b"\x78\xda":
        raw, off = plain[4:], 4
    elif plain[:2] == b"\x78\xda":
        raw, off = plain[2:], 2
    else:
        return plain, "raw"
    try:
        return zlib.decompressobj().decompress(raw), f"zlib@{off}"
    except zlib.error as ex:
        return plain, f"zlib_fail:{ex}"


def inner_files(body: bytes) -> tuple:
    """Parse the inner file archive.

    Layout -- NOT eyeballed, selected by exhaustive search in
    _probe_inner_layout.py over (name pad, data align, tail) x 3 sample
    entries; only one variant parses `count` files and consumes every byte:

        u32  count
        per file:
            name        NUL-terminated, then padded to 4
            u32 size
            data[size]  starts at the next 16-byte boundary
            1 byte      0x00, not counted in size

    Returns (files, consumed, err); consumed == len(body) means the layout
    accounts for every byte, which is the check that makes this trustworthy.
    """
    if len(body) < 4:
        return [], 0, "shorter than the 4-byte count"
    count, = struct.unpack_from("<I", body, 0)
    if not 0 < count <= 4096:
        return [], 0, f"implausible count {count}"
    files, o = [], 4
    for _ in range(count):
        end = body.find(b"\x00", o)
        if end < 0 or end - o > 256:
            return files, o, f"unterminated/oversized name at {o:#x}"
        name = body[o:end]
        p = end + 1
        p += (-p) % 4
        if p + 4 > len(body):
            return files, o, f"size cut at {p:#x}"
        size, = struct.unpack_from("<I", body, p)
        p += 4
        p += (-p) % 16
        data = body[p:p + size]
        if size == 0 or len(data) < size:
            return files, o, f"data cut at {p:#x} ({size:#x} B)"
        files.append((name.decode("latin-1"), size, p, data))
        o = p + size + 1
    return files, o, ""


def main() -> None:
    global FILES_TSV, OLANG_TSV
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump-dir", default="", help="write inner files here")
    ap.add_argument("--dump-ext", default="",
                    help="comma-separated extensions to dump (e.g. ohd,sep)")
    ap.add_argument("--container", default="MLG/disc0_rel/009645fa.PDT",
                    help="container relative to the game dir "
                         "(e.g. EXLANG/disc0_rel/009645fa.PDT)")
    ap.add_argument("--tag", default="", help="suffix for the report names")
    args = ap.parse_args()
    container = GAME / args.container
    dump_ext = {e.lower() for e in args.dump_ext.split(",") if e}
    dump_dir = Path(args.dump_dir) if args.dump_dir else None
    if dump_dir:
        dump_dir.mkdir(parents=True, exist_ok=True)

    src = container
    if args.tag:
        FILES_TSV = FILES_TSV.with_name(FILES_TSV.stem + args.tag + ".tsv")
        OLANG_TSV = OLANG_TSV.with_name(OLANG_TSV.stem + args.tag + ".tsv")
    print(f"container: {src.relative_to(GAME)}")
    size = src.stat().st_size
    with src.open("rb") as f:
        arc = A.parse(f.read(8 << 20), src.stem, str(src),
                      max_entries=200000)
    s = (arc.hi ^ arc.lo) & MASK32
    state0 = (s | ((s ^ 0x6576) << 16)) & MASK32
    inc = (arc.m * s) & MASK32

    rows, texts, hits = [], [], []
    t0 = time.time()
    arc_ok = arc_bad = 0
    with src.open("rb") as f:
        for i in range(arc.count):
            e = arc.entries[i]
            f.seek(e.c)
            plain = payload(arc, f.read(e.a), state0, inc)
            body, note = inflate(plain)
            files, consumed, err = inner_files(body)
            if err or consumed != len(body):
                arc_bad += 1
                if arc_bad <= 5:
                    print(f"  entry {i}: inner parse {err or 'leftover'} "
                          f"({consumed}/{len(body)})")
            else:
                arc_ok += 1
            for nm, sz, off, data in files:
                rows.append((i, f"{e.c:#x}", nm, sz, f"{off:#x}", note,
                             data[:4].hex()))
                if dump_dir and (
                        not dump_ext
                        or nm.rsplit(".", 1)[-1].lower() in dump_ext):
                    out = dump_dir / f"e{i:04d}_{nm.replace('/', '_')}"
                    out.write_bytes(data)
                low = data.lower()
                for nd in NEEDLES:
                    if nd in low:
                        hits.append((i, nm, nd.decode(), low.find(nd)))
                        print(f"  HIT entry{i} {nm} {nd.decode()} "
                              f"@ {low.find(nd):#x}")
                if data[:4] == b"RBX\x00":
                    try:
                        tbl = O.parse(data, nm)
                        for st in tbl.strings():
                            # strings() yields offsets only; the text comes
                            # from the pool (olang.string_at)
                            txt = O.string_at(tbl, st.offset).decode("latin-1")
                            if txt:
                                texts.append((i, nm, f"{tbl.table_id:#010x}",
                                              f"{st.group:#x}", f"{st.entry:#x}",
                                              f"{st.key:#x}", f"{st.meta:#x}",
                                              txt))
                    except (ValueError, struct.error) as ex:
                        print(f"  entry {i}: {nm} RBX parse failed: {ex}")
            if i % 100 == 0:
                print(f"  [{i}/{arc.count}] {time.time() - t0:.0f}s "
                      f"files={len(rows)} strings={len(texts)}")

    print(f"swept {arc.count} entries in {time.time() - t0:.0f}s | "
          f"inner archives: {arc_ok} sound / {arc_bad} rejected")
    with FILES_TSV.open("w", encoding="utf-8") as f:
        f.write("entry\toff\tname\tsize\tdata_off\tnote\tmagic\n")
        for r in rows:
            f.write("\t".join(str(x) for x in r) + "\n")
    with OLANG_TSV.open("w", encoding="utf-8") as f:
        f.write("entry\tfile\ttable_id\tgroup\tentry\tkey\tmeta\ttext\n")
        for r in texts:
            f.write("\t".join(x.replace("\t", " ") for x in
                              (str(v) for v in r)) + "\n")
    print(f"inner files: {len(rows)} -> {FILES_TSV.name}")
    print(f"olang strings: {len(texts)} -> {OLANG_TSV.name}")
    print("NEEDLE HITS:", hits or "none")

    from collections import Counter
    print("\ninner file name histogram (top 25):")
    for nm, c in Counter(r[2] for r in rows).most_common(25):
        print(f"  {c:5d}  {nm}")


if __name__ == "__main__":
    main()

"""Probe: sweep every PDT/DAT container payload and classify what is inside.

This is the "preview every uncollected corpus" pass.  For each payload it
answers: is it readable text, a zlib stream, the STAGEDAT-style inner file
archive, an SP/Ogg package, a FEL blob, or noise -- and it searches for the
missing codec hint everywhere along the way.

    "There's no one around - why not try some shooting practice?"  (Miller)

Already-dumped sources are EXCLUDED (no point re-reading them):
    MLG/Text + EXLANG/Text *.olang   -> _dump_olang.tsv
    002aba34.DAT / .KEY (SLOT)       -> _slot_olang_lines.tsv
    0076531d.DAT (BRIEFING)          -> _briefing_lines.tsv
    .xmx/.xsx movies                 -> 02_movie_subtitle.md §6.1 has no data

Payload chain (each link proven elsewhere):
    buffer_xor_decrypt(name_hash(stem))            04_archive.md §4
    mode 0x100: xor every byte with lo & 0xFF
    mode 0x40 : LCG, FRESH per entry from s = hi^lo,
                state = s | ((s ^ 0x6576) << 16), inc = m * s
                (cracked in _probe_stagedat.py, CRC-32 oracle 6/6)
    then: u32 + zlib  ->  inner file archive
                          u32 count; per file name (NUL-term, 4-pad),
                          u32 size, data at the next 16-byte boundary, +1 NUL
                          (layout searched exhaustively in _probe_inner_layout.py)

Outputs: ANALYSIS/_pkgscan_kinds.tsv   one row per payload
         ANALYSIS/_pkgscan_files.tsv   every inner file
         ANALYSIS/_pkgscan_olang.tsv   every string of every inner olang
         ANALYSIS/_pkgscan_hits.tsv     needle hits

Usage:  python _probe_pkg_scan.py [--jobs 8] [--skip-exlang] [--budget-mb 512]
"""
import argparse
import logging
import re
import struct
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_crypto as C
import pwsf_olang as O

log = logging.getLogger("pkgscan")

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ROOT = Path(__file__).resolve().parent.parent
ANALYSIS = ROOT / "ANALYSIS"
MASK32 = 0xFFFFFFFF
HEAD_CAP = 8 << 20

NEEDLES = [b"shooting practice", b"no one around"]
EXCLUDE_FILES = {"002aba34.dat", "002aba34.key", "0076531d.dat"}
EXCLUDE_EXTS = {".olang", ".xmx", ".xsx", ".orig", ".exe", ".dll", ".asi",
                ".i64", ".id0", ".id1", ".id2", ".nam", ".til"}


def unmask(arc, blob: bytes) -> bytes:
    buf = C.buffer_xor_decrypt(bytearray(blob), arc.key)
    if arc.mode == 0x100:
        return bytes(buf.translate(
            bytes(i ^ (arc.lo & 0xFF) for i in range(256))))
    if arc.mode == 0x40:
        s = (arc.hi ^ arc.lo) & MASK32
        state = (s | ((s ^ 0x6576) << 16)) & MASK32
        inc = (arc.m * s) & MASK32
        dwords = len(buf) & ~3
        if dwords:
            A._unmask_lcg(memoryview(buf)[:dwords], state, inc)
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
    except zlib.error as ex:
        return None, f"zlib_fail:{ex}"


def inner_files(body: bytes) -> tuple:
    """STAGEDAT inner archive; layout from _probe_inner_layout.py."""
    if len(body) < 4:
        return [], ""
    count, = struct.unpack_from("<I", body, 0)
    if not 0 < count <= 4096:
        return [], ""
    files, o = [], 4
    for _ in range(count):
        end = body.find(b"\x00", o)
        if end < 0 or end - o > 256:
            return [], ""
        name = body[o:end]
        p = end + 1
        p += (-p) % 4
        if p + 4 > len(body):
            return [], ""
        size, = struct.unpack_from("<I", body, p)
        p += 4
        p += (-p) % 16
        data = body[p:p + size]
        if size == 0 or len(data) < size:
            return [], ""
        files.append((name.decode("latin-1"), size, data))
        o = p + size + 1
    return (files, "ok") if o == len(body) else ([], "")


def classify(plain: bytes) -> tuple:
    """-> (kind, detail, searchable_bytes)."""
    body, note = inflate(plain)
    if body is not None:
        files, ok = inner_files(body)
        if ok:
            return "inner_archive", f"{note} files={len(files)}", body
        return "zlib", f"{note} {len(body)}B", body
    return note, plain[:4].hex(), plain


def scan_container(path: Path, budget: int, max_entry: int) -> dict:
    rel = str(path.relative_to(GAME))
    size = path.stat().st_size
    t0 = time.time()
    out = {"kinds": [], "files": [], "texts": [], "hits": [],
           "bytes": 0, "entries": 0, "skipped": 0, "rel": rel}
    with path.open("rb") as f:
        head = f.read(min(size, HEAD_CAP))
    try:
        arc = A.parse(head, path.stem, str(path), max_entries=200000)
        if A.verify(arc, size):
            log.warning("%s: rejected as container", rel)
            return out
    except ValueError as ex:
        log.info("%s: not a container (%s)", rel, ex)
        return out
    spent = 0
    with path.open("rb") as f:
        for i in range(arc.count):
            e = arc.entries[i]
            if e.a > max_entry:
                out["skipped"] += 1
                continue
            if spent + e.a > budget:
                out["skipped"] += arc.count - i
                break
            f.seek(e.c)
            plain = unmask(arc, f.read(e.a))
            spent += len(plain)
            out["entries"] += 1
            crc = "ok" if A.entry_crc(plain) == e.b else "BAD"
            kind, detail, blob = classify(plain)
            out["kinds"].append((rel, i, f"{e.c:#x}", e.a, f"{arc.mode:#x}",
                                 crc, kind, detail))

            low = blob.lower()
            for nd in NEEDLES:
                if nd in low:
                    out["hits"].append((f"{rel}:entry{i}", nd.decode(),
                                        f"{low.find(nd):#x}", kind))
                    log.info("HIT %s %r %s", out["hits"][-1][0], nd, kind)

            if kind == "inner_archive":
                files, _ = inner_files(blob)
                for nm, sz, data in files:
                    out["files"].append((rel, i, nm, sz, data[:4].hex()))
                    if data[:4] == b"RBX\x00":
                        try:
                            tbl = O.parse(data, nm)
                            for st in tbl.strings():
                                txt = O.string_at(tbl, st.offset).decode(
                                    "latin-1")
                                if txt:
                                    out["texts"].append((rel, i, nm, txt))
                        except (ValueError, struct.error) as ex:
                            log.info("%s: %s RBX failed: %s", rel, nm, ex)
    out["bytes"] = spent
    log.info("%-46s %6d MB  entries=%-5d skip=%-4d %s  %5.1fs",
             rel, size >> 20, out["entries"], out["skipped"],
             _kind_summary(out["kinds"]), time.time() - t0)
    return out


def _kind_summary(rows) -> str:
    from collections import Counter
    c = Counter(r[6] for r in rows)
    return " ".join(f"{k}={v}" for k, v in c.most_common(4))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=0)
    ap.add_argument("--budget-mb", type=int, default=512)
    ap.add_argument("--max-entry-mb", type=int, default=256)
    ap.add_argument("--skip-exlang", action="store_true")
    ap.add_argument("--needle", action="append", default=[])
    args = ap.parse_args()
    NEEDLES.extend(n.lower().encode() for n in args.needle)
    logging.basicConfig(format="%(asctime)s %(levelname)-7s %(message)s",
                        level=logging.INFO, datefmt="%H:%M:%S")

    files = sorted(p for p in GAME.rglob("*")
                   if p.is_file() and p.suffix.lower() in (".pdt", ".dat")
                   and p.name.lower() not in EXCLUDE_FILES
                   and p.suffix.lower() not in EXCLUDE_EXTS
                   and not (args.skip_exlang and "exlang" in str(p).lower()))
    log.info("%d containers queued", len(files))

    kinds, inner, texts, hits = [], [], [], []
    total = 0
    t0 = time.time()

    def collect(r):
        nonlocal total
        kinds.extend(r["kinds"])
        inner.extend(r["files"])
        texts.extend(r["texts"])
        hits.extend(r["hits"])
        total += r["bytes"]

    if args.jobs:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futs = [pool.submit(scan_container, p, args.budget_mb << 20,
                                args.max_entry_mb << 20) for p in files]
            for fut in as_completed(futs):
                collect(fut.result())
    else:
        for p in files:
            collect(scan_container(p, args.budget_mb << 20,
                                   args.max_entry_mb << 20))

    log.info("done: %d MB decrypted in %.0fs", total >> 20, time.time() - t0)

    def write(name, header, rows):
        with (ANALYSIS / name).open("w", encoding="utf-8") as f:
            f.write(header)
            for r in rows:
                f.write("\t".join(str(x) for x in r) + "\n")
        log.info("%s -> %d rows", name, len(rows))

    write("_pkgscan_kinds.tsv",
          "container\tentry\toff\tsize\tmode\tcrc\tkind\tdetail\n", kinds)
    write("_pkgscan_files.tsv", "container\tentry\tname\tsize\tmagic\n", inner)
    write("_pkgscan_olang.tsv", "container\tentry\tfile\ttext\n", texts)
    write("_pkgscan_hits.tsv", "location\tneedle\toff\tkind\n", hits)

    from collections import Counter
    print("\npayload kinds:")
    for k, v in Counter(r[6] for r in kinds).most_common():
        print(f"  {v:7d}  {k}")
    print("\nneedle hits:", hits or "none")
    print(f"\ninner files: {len(inner)}   olang strings: {len(texts)}")
    print("\nmost common inner file names:")
    for nm, c in Counter(r[2] for r in inner).most_common(15):
        print(f"  {c:5d}  {nm}")


if __name__ == "__main__":
    main()

"""Probe: audit -- which container payloads on disk were NEVER searched?

Two sweeps exist and both had budgets:

  _probe_pkg_scan.py    --budget-mb 512 --max-entry-mb 256
  _probe_textscan.py    --budget-mb 512 --max-entry-mb 128

so any entry bigger than the cap, and any container that ran out of budget,
was silently skipped.  `_probe_fel_cover.py` proved the effect is real: 12
giant ADEMO/ADEMOHQ entries (3,952 MB, 60% of the mission packages) had never
been decrypted at all -- they are now, and the needle is not in them.

This probe closes the audit for the REST of the game: every .pdt/.dat
container, every entry, compared against `ANALYSIS/_pkgscan_kinds.tsv`
(the rows written by the sweep that classified + needle-searched payloads).
Anything not in there is queued and (with --sweep) decrypted and searched.

Usage:
  python _probe_gap.py                    # audit only
  python _probe_gap.py --sweep --procs 24
"""
import argparse
import csv
import logging
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

ROOT = Path(__file__).resolve().parent
KINDS = ROOT.parent / "ANALYSIS" / "_pkgscan_kinds.tsv"
HEAD = 8 << 20
NEEDLES = [b"shooting practice", b"no one around",
           b"Investigate the Supply Facility"]

# covered by their own dedicated pipelines (ANALYSIS/03, /08, /09)
SKIP = {"002aba34.dat", "002aba34.key", "0076531d.dat", "009645fa.pdt"}


def one(task) -> tuple:
    """Search one payload: raw, and -- if it is a zlib stream -- inflated.

    The raw-only version would miss any payload that ships compressed, which
    is exactly the hole we are trying to close, so `classify`'s two zlib
    positions (offset 2 and 4) are both tried.
    """
    path, off, size, key, mode, lo = task
    import pwsf_crypto as C
    import zlib
    with open(path, "rb") as fh:
        fh.seek(off)
        blob = fh.read(size)
    if len(blob) < size:
        return -1
    buf = C.buffer_xor_decrypt(bytearray(blob), key)
    if mode == 0x100:
        buf = bytearray(bytes(buf).translate(
            bytes(i ^ (lo & 0xFF) for i in range(256))))
    low = bytes(buf).lower()
    for nd in NEEDLES:
        if nd in low:
            return (path, off, nd.decode(), hex(low.find(nd)))
    if buf[4:6] == b"\x78\xda":
        raw = bytes(buf)[4:]
    elif buf[:2] == b"\x78\xda":
        raw = bytes(buf)[2:]
    else:
        return None
    try:
        body = zlib.decompressobj().decompress(raw)
    except zlib.error:
        return None
    low2 = body.lower()
    for nd in NEEDLES:
        if nd in low2:
            return (path, off, nd.decode() + " (zlib)",
                    hex(low2.find(nd)))
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--procs", type=int, default=24)
    args = ap.parse_args()
    logging.basicConfig(format="%(asctime)s %(levelname)-7s %(message)s",
                        level=logging.INFO, datefmt="%H:%M:%S")
    log = logging.getLogger("gap")

    import pwsf_archive as A
    import _probe_pkg_scan as S
    game = S.GAME

    done = {}
    with KINDS.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            done.setdefault(r["container"].replace("\\", "/"),
                            set()).add(int(r["entry"]))

    tasks, miss_bytes, tot_bytes = [], 0, 0
    print(f"{'container':46} {'entries':>7} {'searched':>8} "
          f"{'MB':>7} {'MB gap':>7}")
    for p in sorted(q for q in game.rglob("*")
                    if q.is_file() and q.suffix.lower() in (".pdt", ".dat")
                    and q.name.lower() not in SKIP):
        size = p.stat().st_size
        with p.open("rb") as fh:
            head = fh.read(min(size, HEAD))
        try:
            arc = A.parse(head, p.stem, str(p), max_entries=200000)
            if A.verify(arc, size):
                continue
        except ValueError:
            continue
        rel = str(p.relative_to(game)).replace("\\", "/")
        have = done.get(rel, set())
        sizes = [arc.entries[i].a for i in range(arc.count)]
        tot_bytes += sum(sizes)
        gap = [i for i in range(arc.count) if i not in have]
        gmb = sum(sizes[i] for i in gap)
        miss_bytes += gmb
        if gap:
            print(f"{rel:46} {arc.count:7d} {len(have):8d} "
                  f"{sum(sizes) >> 20:7d} {gmb >> 20:7d}")
        for i in gap:
            tasks.append((str(p), arc.entries[i].c, sizes[i], arc.key,
                          arc.mode, arc.lo))
    print(f"\nall containers: {tot_bytes >> 20} MB payload | "
          f"never searched {miss_bytes >> 20} MB in {len(tasks)} entries")
    if not args.sweep or not tasks:
        return

    hits, n, bad = [], 0, 0
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=args.procs) as pool:
        futs = [pool.submit(one, t) for t in tasks]
        for fut in as_completed(futs):
            r = fut.result()
            n += 1
            if r == -1:
                bad += 1
            elif r:
                hits.append(r)
                log.info("HIT %s", r)
            if n % 100 == 0:
                log.info("%d/%d  %.0fs", n, len(tasks), time.time() - t0)
    print(f"\nswept {n} entries ({bad} unreadable) in {time.time() - t0:.0f}s")
    print("needle hits:", hits or "none")


if __name__ == "__main__":
    main()

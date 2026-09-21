"""Probe: how much of ADEMO / ADEMOHQ was actually searched, and what is in it.

`_probe_pkg_scan.py` ran with `--budget-mb 512 --max-entry-mb 256`, i.e. it
gave up on any container after 512 MB of payloads and skipped every single
entry bigger than 256 MB.  ADEMO + ADEMOHQ are 6.6 GB, and
`ANALYSIS/_pkgscan_kinds.tsv` only holds 2,683 MB worth of ADEMO rows, so the
"the codec hint is not in the mission packages" claim in ANALYSIS/09 §1 rests
on partial coverage: **60% of the mission packages were never searched**.

This probe measures the gap and closes it:

  1. coverage  -- per container: entries on disk, entries in the old report,
                  bytes searched vs bytes that exist
  2. sweep     -- decrypt every entry that the old report never touched (or
                  everything, with --all) and search it for the needles

Needles: the still-missing in-mission radio line
    "There's no one around - why not try some shooting practice?"   (Miller)
plus, as a control, a string we KNOW exists in the static text
("Investigate the Supply Facility") so a false negative is visible.

Decryption is pure-Python MT19937 (5.6 MB/s measured), so the sweep uses
PROCESSES, not threads -- the GIL makes threads useless here.

Usage:
  python _probe_fel_cover.py                      # coverage report only
  python _probe_fel_cover.py --sweep --procs 24   # decrypt + search
  python _probe_fel_cover.py --sweep --all
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
GAME = ROOT.parent.parent / ".."      # replaced below
KINDS = ROOT.parent / "ANALYSIS" / "_pkgscan_kinds.tsv"
HEAD = 8 << 20

NEEDLES = [b"shooting practice", b"no one around",
           b"Investigate the Supply Facility"]
ASCII_ONLY = False


def _game() -> Path:
    sys.path.insert(0, str(ROOT))
    import _probe_pkg_scan as S
    return S.GAME


def containers():
    g = _game()
    out = []
    for sub in ("ADEMO", "ADEMOHQ"):
        d = g / "MLG" / "disc0_rel" / sub
        out += sorted(p for p in d.glob("*.pdt") if p.is_file())
    return out


def old_rows():
    seen = {}
    with KINDS.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh, delimiter="\t"):
            seen.setdefault(r["container"].replace("\\", "/"),
                            set()).add(int(r["entry"]))
    return seen


def index_of(path: Path):
    import pwsf_archive as A
    size = path.stat().st_size
    with path.open("rb") as fh:
        head = fh.read(min(size, HEAD))
    try:
        arc = A.parse(head, path.stem, str(path), max_entries=200000)
    except ValueError as ex:
        return None, f"not a container: {ex}"
    if A.verify(arc, size):
        return None, "self-check failed"
    return arc, ""


def one(task) -> tuple:
    """(path, off, size, key, mode, lo) -> needle hits inside that payload.

    With --ascii it also reports the longest printable-ASCII run, which is the
    "does this payload hold any text at all" question -- the needle only
    answers it for the one line we are chasing.
    """
    path, off, size, key, mode, lo = task
    import re as _re
    import pwsf_crypto as C
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
    if not ASCII_ONLY:
        return None
    best, tail = "", b""
    for m in _re.finditer(rb"[ -~]{12,}", bytes(buf)):
        if len(m.group()) > len(best):
            best = m.group().decode("latin-1")
    if len(bytes(buf)) > 1 << 20:
        tail = bytes(buf)[-1 << 20:]
        for m in _re.finditer(rb"[ -~]{12,}", tail):
            if len(m.group()) > len(best):
                best = "…" + m.group().decode("latin-1")
    return (path, off, f"longest ASCII run {len(best)}", best[:60]) \
        if best else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--all", action="store_true",
                    help="sweep every entry, not just the unsearched ones")
    ap.add_argument("--procs", type=int, default=16)
    ap.add_argument("--ascii", action="store_true",
                    help="report the longest ASCII run of every payload "
                         "instead of only looking for the needles")
    args = ap.parse_args()
    global ASCII_ONLY
    ASCII_ONLY = args.ascii
    logging.basicConfig(format="%(asctime)s %(levelname)-7s %(message)s",
                        level=logging.INFO, datefmt="%H:%M:%S")
    log = logging.getLogger("felcover")

    g = _game()
    old = old_rows()
    tasks = []
    tot_bytes = miss_bytes = 0
    print(f"{'container':44} {'entries':>8} {'searched':>8} "
          f"{'MB total':>9} {'MB missed':>9}")
    for p in containers():
        arc, err = index_of(p)
        rel = str(p.relative_to(g)).replace("\\", "/")
        if arc is None:
            print(f"{rel:44} {err}")
            continue
        done = old.get(rel, set())
        sizes = [arc.entries[i].a for i in range(arc.count)]
        total = sum(sizes)
        missed_idx = [i for i in range(arc.count)
                      if args.all or i not in done]
        missed = sum(sizes[i] for i in missed_idx)
        tot_bytes += total
        miss_bytes += missed
        for i in missed_idx:
            tasks.append((str(p), arc.entries[i].c, sizes[i], arc.key,
                          arc.mode, arc.lo))
        print(f"{rel:44} {arc.count:8d} {len(done):8d} "
              f"{total >> 20:9d} {missed >> 20:9d}")
    print(f"\nTOTAL on disk {tot_bytes >> 20} MB | never searched "
          f"{miss_bytes >> 20} MB ({100 * miss_bytes / max(tot_bytes, 1):.0f}%)"
          f" | {len(tasks)} entries queued")

    if not args.sweep:
        return

    hits, done_n, bad = [], 0, 0
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=args.procs) as pool:
        futs = [pool.submit(one, t) for t in tasks]
        for fut in as_completed(futs):
            r = fut.result()
            done_n += 1
            if r == -1:
                bad += 1
            elif r:
                hits.append(r)
                log.info("HIT %s", r)
            if done_n % 50 == 0:
                log.info("%d/%d entries  %.0fs", done_n, len(tasks),
                         time.time() - t0)
    print(f"\nswept {done_n} entries ({bad} unreadable) in "
          f"{time.time() - t0:.0f}s")
    if args.ascii:
        def key(r):
            return int(r[2].rsplit(" ", 1)[-1])
        hits.sort(key=key, reverse=True)
        print(f"payloads with an ASCII run >= 12: {len(hits)}")
        for r in hits[:20]:
            print(f"  {r[0]} @{r[1]:#x}  {r[2]}  {r[3]!r}")
    else:
        print("needle hits:", hits or "none")


if __name__ == "__main__":
    main()

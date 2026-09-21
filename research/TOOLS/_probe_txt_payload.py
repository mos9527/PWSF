"""Probe: find every container payload that is PLAINTEXT text.

Why: the base game's radio chatter (the in-game codec bar: "Miller",
"Lock disengaged.", "Charging railgun.", ...) is not in the olang tables, the
CODEC container or SLOT.DAT.  It lives in payloads that decrypt straight to
text -- first seen as entry 1 of ms0\\EU\\DLCVOICE\\181ae463.PDT, whose head is
literally "Lock disengaged.\\0" followed by the other five languages: a
fixed-width, NUL-padded table of subtitle lines.

So "where is
    There's no one around - why not try some shooting practice?
stored" becomes: which payloads are text, and is that line in one of them.

Cost: only the first 64 KiB of a payload is decrypted for the decision, which
is legal because both unmask layers are sequential keystreams from offset 0
(MT19937 for every mode, LCG for mode 0x40).  A full sweep of the 6.4 GB of
mission packages therefore costs seconds instead of half an hour.

Text test: among the non-zero bytes of that prefix, >= 90% are printable ASCII.
The zero bytes are what a fixed-width table pads with, so they are excluded
rather than counted -- an earlier version counted them and missed every table.

Usage:  python _probe_txt_payload.py [--jobs 8] [--min 8] [--dump-dir DIR]
"""
import argparse
import logging
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import _probe_pkg_scan as S
import pwsf_archive as A

log = logging.getLogger("txtpayload")
NEEDLES = [b"shooting practice", b"no one around"]
RUN = re.compile(rb"[ -~]{4,}")
PROBE = 64 << 10


def is_text(plain: bytes) -> bool:
    nz = [c for c in plain if c]
    if len(nz) < 64:
        return False
    good = sum(1 for c in nz if 32 <= c < 127)
    return good / len(nz) >= 0.90


def scan(path: Path, dump_dir: Path = None) -> dict:
    rel = str(path.relative_to(S.GAME))
    out = {"rel": rel, "text": [], "hits": []}
    size = path.stat().st_size
    with path.open("rb") as f:
        try:
            arc = A.parse(f.read(min(size, S.HEAD_CAP)), path.stem, str(path),
                          max_entries=200000)
            if A.verify(arc, size):
                return out
        except ValueError:
            return out
        for i in range(arc.count):
            e = arc.entries[i]
            f.seek(e.c)
            head = S.unmask(arc, f.read(min(e.a, PROBE)))
            if not is_text(head):
                continue
            f.seek(e.c)
            plain = S.unmask(arc, f.read(e.a))
            runs = [m.group() for m in RUN.finditer(plain)]
            low = plain.lower()
            hits = [(nd.decode(), hex(low.find(nd)))
                    for nd in NEEDLES if nd in low]
            out["text"].append((i, f"{e.c:#x}", e.a, len(runs),
                                b" | ".join(runs[:4]).decode("latin-1")))
            if hits:
                out["hits"].append((i, hits))
                log.info("HIT %s entry %d %s", rel, i, hits)
            if dump_dir:
                name = path.stem.replace("/", "_")
                (dump_dir / f"{name}_e{i:03d}.txt").write_bytes(plain)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=0)
    ap.add_argument("--min", type=int, default=8,
                    help="only report payloads with at least this many runs")
    ap.add_argument("--dump-dir", type=Path, default=None)
    ap.add_argument("--needle", action="append", default=[])
    args = ap.parse_args()
    NEEDLES.extend(n.lower().encode() for n in args.needle)
    logging.basicConfig(format="%(asctime)s %(levelname)-7s %(message)s",
                        level=logging.INFO, datefmt="%H:%M:%S")
    if args.dump_dir:
        args.dump_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(p for p in S.GAME.rglob("*")
                   if p.is_file() and p.suffix.lower() in (".pdt", ".dat")
                   and p.name.lower() not in S.EXCLUDE_FILES)
    log.info("%d containers", len(files))
    rows, hits = [], []
    t0 = time.time()

    def collect(r):
        rows.extend([(r["rel"],) + t for t in r["text"]])
        hits.extend([(r["rel"],) + tuple(h) for h in r["hits"]])

    if args.jobs:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futs = [pool.submit(scan, p, args.dump_dir) for p in files]
            for fut in as_completed(futs):
                collect(fut.result())
    else:
        for p in files:
            collect(scan(p, args.dump_dir))
    log.info("done %.0fs", time.time() - t0)

    rows = [r for r in rows if r[4] >= args.min]
    print(f"\nplaintext payloads: {len(rows)}")
    for r in sorted(rows, key=lambda x: -x[4])[:40]:
        print(f"  {r[4]:5d} runs  {r[3]:>9} B  {r[0]}:entry{r[1]}  {r[5][:78]}")
    print("\nneedle hits:", hits or "none")


if __name__ == "__main__":
    main()

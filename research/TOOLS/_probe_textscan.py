"""Probe: sweep the game's UNCOLLECTED sources and preview their text.

Background (2026-09-21): the in-game codec hint

    "There's no one around - why not try some shooting practice?"   (Miller)

is in NONE of the extracted corpora (_dump_olang.tsv 137k lines /
subtitle_ingame.tsv / _briefing_lines.tsv 24k / _slot_olang_lines.tsv 91k).
A plain-string grep over those TSVs finds "practice" / "why not try" only in
unrelated lines, so the source of this line was never opened for text.

Already covered by earlier extraction (EXCLUDED here):
  - MLG/Text + EXLANG/Text  17 .olang      -> _dump_olang.tsv
  - 002aba34.DAT (SLOT.DAT) embedded olang -> _slot_olang_lines.tsv
  - 0076531d.DAT (BRIEFING)                -> _briefing_lines.tsv
  - 002aba34.KEY (SLOT.KEY)                -> index, analyzed
  - .xmx/.xsx movies                       -> 02_movie_subtitle.md §6.1 (no data)
  - .orig backups / .exe / .dll / IDA dbs  -> not game data

What this probe does, per file:
  1. PDT/DAT containers: parse, decrypt EVERY entry payload (mode 0x100; the
     sole mode 0x40 container 009645fa.PDT = STAGEDAT is unimplemented,
     logged as SKIP) and inspect it.
  2. any other file: raw + one-shot buffer_xor_decrypt(name_hash(stem)).

Per payload it reports:
  - needle hits (the missing line, and anything else you ask for with --needle)
  - a "is there English text in here?" preview: sentence-like ASCII runs
  - embedded RBX (olang) tables: parsed fully, strings dumped to the RBX TSV

Reports:
  ANALYSIS/_textscan_hits.tsv     needle hits
  ANALYSIS/_textscan_preview.tsv  per-entry text preview
  ANALYSIS/_textscan_rbx.tsv      every string of every embedded olang table

Usage:
  python _probe_textscan.py                        # sequential
  python _probe_textscan.py --jobs 8               # ThreadPoolExecutor
  python _probe_textscan.py --needle "try some"    # extra needle (repeatable)
  python _probe_textscan.py --budget-mb 64         # per-container payload cap
"""
import argparse
import logging
import re
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_crypto as C
import pwsf_olang as O

log = logging.getLogger("textscan")

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ROOT = Path(__file__).resolve().parent.parent
HITS_TSV = ROOT / "ANALYSIS" / "_textscan_hits.tsv"
PREV_TSV = ROOT / "ANALYSIS" / "_textscan_preview.tsv"
RBX_TSV = ROOT / "ANALYSIS" / "_textscan_rbx.tsv"

HEAD_CAP = 8 << 20      # container parse only needs header + tables
CTX = 64                # context bytes around a needle hit
STR_MIN = 12            # shortest run worth calling "text"
SAMPLES = 5             # preview samples per entry

NEEDLES = [b"shooting practice", b"no one around"]

# files whose text was already dumped (name-level, case-insensitive)
EXCLUDE_FILES = {"002aba34.dat", "002aba34.key", "0076531d.dat"}
EXCLUDE_EXTS = {".olang", ".xmx", ".xsx",          # dumped / no data (02 §6.1)
                ".orig", ".exe", ".dll", ".asi",   # binaries / backups
                ".i64", ".id0", ".id1", ".id2", ".nam", ".til"}  # IDA db

RUN_RE = re.compile(rb"[ -~]{%d,}" % STR_MIN)
WORD_RE = re.compile(rb"[A-Za-z]")


def find_hits(buf: bytes) -> list:
    low = buf.lower()
    out = []
    for nd in NEEDLES:
        start = 0
        while True:
            i = low.find(nd, start)
            if i < 0:
                break
            out.append((nd, i, buf[max(0, i - CTX):i + len(nd) + CTX]))
            start = i + 1
    return out


def sentences(buf: bytes, limit: int = 400) -> list:
    """Sentence-looking ASCII runs: >= STR_MIN, mostly letters, has a space."""
    out = []
    for m in RUN_RE.finditer(buf):
        s = m.group()
        if b" " not in s:
            continue
        if len(WORD_RE.findall(s)) / len(s) < 0.7:
            continue
        s = s.strip()
        if len(s) < STR_MIN:
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return out


def inspect(path: Path, where: str, buf: bytes, hits: list, prev: list,
            rbx: list) -> None:
    """Needle + preview + embedded-olang inspection of one decrypted buffer."""
    for nd, off, ctx in find_hits(buf):
        hits.append((where, nd, off, ctx))
        log.info("HIT %s needle=%r off=%#x", where, nd.decode(), off)

    strs = sentences(buf)
    magic = buf[:4]
    if magic == b"RBX\x00":
        try:
            tbl = O.parse(buf, where)
            for st in tbl.strings():
                txt = st.data.rstrip(b"\x00").decode("latin-1")
                if txt:
                    rbx.append((where, f"{tbl.table_id:#010x}",
                                f"g={st.group:#x} e={st.entry:#x} "
                                f"k={st.key:#x} meta={st.meta:#x}", txt))
            log.info("%s: embedded olang table_id=%#010x, %d strings",
                     where, tbl.table_id, len(rbx))
        except (ValueError, struct.error) as ex:
            log.warning("%s: RBX magic but parse failed: %s", where, ex)
    prev.append((where, len(buf), magic.hex(), len(strs),
                 " | ".join(s.decode("latin-1")[:120] for s in strs[:SAMPLES])))


def scan_container(path: Path, head: bytes, size: int, budget: int,
                   max_entry: int) -> tuple:
    """Parse + decrypt + inspect a PDT/DAT container."""
    arc = A.parse(head, path.stem, str(path), max_entries=200000)
    probs = A.verify(arc, size)
    if probs:
        log.warning("%s: self-check failed (%s)", path.name, "; ".join(probs[:1]))
    hits, prev, rbx = [], [], []
    spent = skipped = 0
    with path.open("rb") as f:
        for s in range(arc.count):
            e = arc.entries[s]
            if e.a > max_entry:
                skipped += 1
                continue
            if spent + e.a > budget:
                log.info("%s: budget %d MB reached at entry %d/%d",
                         path.name, budget >> 20, s, arc.count)
                break
            f.seek(e.c)
            blob = f.read(e.a)
            if len(blob) < e.a:
                skipped += 1
                continue
            try:
                out = A.decrypt_payload(arc, blob)
            except NotImplementedError:
                log.info("%s: entry %d mode 0x40 payload SKIP "
                         "(04_archive.md §6.2)", path.name, s)
                skipped += arc.count - s
                break
            except ValueError as ex:
                log.info("%s: entry %d payload %s", path.name, s, ex)
                skipped += 1
                continue
            spent += len(out)
            inspect(path, f"{path}:entry{s}@{e.c:#x}", out, hits, prev, rbx)
    return hits, prev, rbx, {"kind": "container", "mode": arc.mode,
                             "entries": arc.count, "bytes": spent,
                             "skipped": skipped}


def scan_raw(path: Path, data: bytes) -> tuple:
    hits, prev, rbx = [], [], []
    inspect(path, f"{path}:raw", data, hits, prev, rbx)
    key = C.name_hash(path.name)
    inspect(path, f"{path}:xor(name_hash)", bytes(C.buffer_xor_decrypt(
        bytearray(data), key)), hits, prev, rbx)
    return hits, prev, rbx, {"kind": "raw", "mode": 0, "entries": 0,
                             "bytes": 2 * len(data), "skipped": 0}


def scan_file(path: Path, budget: int, max_entry: int) -> tuple:
    rel = path.relative_to(GAME)
    size = path.stat().st_size
    res = None
    t0 = time.time()
    # Only PDT/DAT are containers. Parsing .txp/.xpr/.cmf as one "succeeds" by
    # accident and yields tens of thousands of bogus entries -- the self-check
    # is what separates a real container from noise (04_archive.md §2).
    if path.suffix.lower() in (".pdt", ".dat"):
        try:
            with path.open("rb") as f:
                head = f.read(min(size, HEAD_CAP))
            arc = A.parse(head, path.stem, str(path), max_entries=200000)
            if A.verify(arc, size):
                log.info("%s: rejected as container -> raw scan", rel)
            else:
                res = scan_container(path, head, size, budget, max_entry)
        except ValueError as ex:
            log.info("%s: not a container (%s) -> raw scan", rel, ex)
    if res is None:
        with path.open("rb") as f:
            data = f.read()
        res = scan_raw(path, data)
    hits, prev, rbx, stats = res
    log.info("%-52s %7d MB  %-9s mode=%#x entries=%-5d skip=%-3d "
             "textruns=%-5d %6.1fs hits=%d",
             rel, size >> 20, stats["kind"], stats["mode"], stats["entries"],
             stats["skipped"], sum(p[3] for p in prev), time.time() - t0,
             len(hits))
    return res


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=0,
                    help="ThreadPoolExecutor workers (0 = sequential)")
    ap.add_argument("--needle", action="append", default=[],
                    help="extra lowercase needle (repeatable)")
    ap.add_argument("--budget-mb", type=int, default=512,
                    help="payload bytes per container (default 512 MB)")
    ap.add_argument("--max-entry-mb", type=int, default=128,
                    help="skip entries larger than this (default 128 MB)")
    ap.add_argument("--skip-exlang", action="store_true",
                    help="skip the EXLANG copies (pt/sp duplicates of MLG)")
    ap.add_argument("--filter", action="append", default=[],
                    help="only files whose path contains this (repeatable)")
    args = ap.parse_args()
    NEEDLES.extend(n.lower().encode() for n in args.needle)
    budget = args.budget_mb << 20
    max_entry = args.max_entry_mb << 20

    logging.basicConfig(format="%(asctime)s %(levelname)-7s %(message)s",
                        level=logging.INFO, datefmt="%H:%M:%S")

    files = sorted(p for p in GAME.rglob("*") if p.is_file()
                   and p.suffix.lower() not in EXCLUDE_EXTS
                   and p.name.lower() not in EXCLUDE_FILES
                   and not (args.skip_exlang and "exlang" in str(p).lower())
                   and (not args.filter
                        or any(f.lower() in str(p).lower()
                               for f in args.filter)))
    log.info("%d files queued | needles: %s", len(files),
             ", ".join(n.decode() for n in NEEDLES))

    all_hits, all_prev, all_rbx = [], [], []
    containers = raw_files = total_bytes = 0
    t0 = time.time()

    def collect(res):
        nonlocal containers, raw_files, total_bytes
        hits, prev, rbx, stats = res
        all_hits.extend(hits)
        all_prev.extend(prev)
        all_rbx.extend(rbx)
        containers += stats["kind"] == "container"
        raw_files += stats["kind"] == "raw"
        total_bytes += stats["bytes"]

    if args.jobs:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futs = [pool.submit(scan_file, p, budget, max_entry)
                    for p in files]
            for fut in as_completed(futs):
                collect(fut.result())
    else:
        for p in files:
            collect(scan_file(p, budget, max_entry))

    log.info("done: %d files (%d containers, %d raw), %d MB decrypted, %.0fs",
             len(files), containers, raw_files, total_bytes >> 20,
             time.time() - t0)

    def write(tsv, header, rows):
        with tsv.open("w", encoding="utf-8") as f:
            f.write(header)
            for r in rows:
                f.write("\t".join(str(x) for x in r) + "\n")
        log.info("%s -> %d rows", tsv.name, len(rows))

    write(HITS_TSV, "location\tneedle\toff\tcontext\n",
          [(loc, nd.decode(), f"{off:#x}", re.sub(r"[\x00-\x1f]", ".",
                                                  ctx.decode("latin-1")))
           for loc, nd, off, ctx in all_hits])
    write(PREV_TSV, "location\tbytes\tmagic\ttext_runs\tsamples\n", all_prev)
    write(RBX_TSV, "location\ttable_id\tkeys\ttext\n", all_rbx)

    print("\nneedle hits:")
    for loc, nd, off, _ctx in all_hits:
        print(f"  {loc}  {nd.decode()} @ {off:#x}")
    print("\ntop text-bearing payloads:")
    for loc, _n, magic, n, samp in sorted(all_prev, key=lambda r: -r[3])[:30]:
        print(f"  {n:5d} runs  {magic}  {loc}\n           {samp[:150]}")


if __name__ == "__main__":
    main()

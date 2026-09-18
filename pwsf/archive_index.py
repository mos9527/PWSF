"""Build ANALYSIS/_archive_index.tsv: every PDT/DAT container with parse status,
resolved entry names and CRC-32 verification.

Usage:  python TOOLS/pwsf_archive_index.py [--full]

Only the header + tables are read for the index; payloads are read only for the
CRC check. By default large containers are spot-checked (8 entries); pass --full
to verify every entry (slow on the multi-hundred-MB archives).
"""
import sys
import time
from pathlib import Path

from . import config
from . import archive as A
from . import names as N

VERBOSE = "--verbose" in sys.argv or "-v" in sys.argv
_T0 = time.time()


def log(msg: str) -> None:
    if VERBOSE:
        print(f"[{time.time() - _T0:7.2f}s] {msg}", flush=True)

GAME = config.GAME_DIR
ROOT = config.REPO_ROOT
REPORT = config.ARCHIVE_INDEX_TSV
STRINGS = config.ANALYSIS_DIR / "_strings.tsv"
SPOT = 8
HEAD_CAP = 8 << 20
# CRC budget per container (bytes of payload). ADEMOHQ entries run to tens of MB
# each, so a per-container cap keeps the whole sweep in seconds.
CRC_BUDGET = 8 << 20

# names we know from the binary that actually occur as archive entries
KNOWN = {N.entry_name_hash(n): n for n in
         ["SUBTITLE", "DBMINFO", "MUSIC", "ZAPPIN", "SCRIPT", "TEXT", "MOVIE"]}


def load_keymap() -> dict:
    """hash -> name, from every string literal in the IDB."""
    keymap = {}
    if not STRINGS.exists():
        return keymap
    with STRINGS.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            _ea, _len, hexs = line.rstrip("\n").split("\t")
            raw = bytes.fromhex(hexs)
            keymap.setdefault(N.entry_name_hash(raw), raw)
    return keymap


def main() -> None:
    full = "--full" in sys.argv
    log("loading keymap")
    keymap = load_keymap()
    log(f"keymap ready ({len(keymap)} entries)")
    names = dict(KNOWN)
    for h, raw in keymap.items():
        names.setdefault(h, raw)

    files = sorted(p for p in GAME.rglob("*")
                   if p.suffix.lower() in (".pdt", ".dat") and p.is_file())
    rows, sound, bad = [], 0, 0
    for idx, p in enumerate(files, 1):
        size = p.stat().st_size
        t = time.time()
        log(f"[{idx}/{len(files)}] {p.relative_to(GAME)} ({size >> 20} MiB)")
        with p.open("rb") as f:
            head = f.read(min(size, HEAD_CAP))
        try:
            arc = A.parse(head, p.stem, str(p), max_entries=200000)
        except ValueError as e:
            rows.append((p, size, 0, -1, f"PARSE_FAIL {e}", "", ""))
            bad += 1
            continue
        probs = A.verify(arc, size)
        if probs:
            bad += 1
        else:
            sound += 1

        crc_ok = crc_bad = spent = 0
        if not probs and arc.mode == 0x100:
            with p.open("rb") as f:
                for s in range(arc.count):
                    e = arc.entries[s]
                    if (spent and spent + e.a > CRC_BUDGET and not full) or \
                            (spent > CRC_BUDGET and full):
                        break
                    f.seek(e.c)
                    blob = f.read(e.a)
                    spent += e.a
                    if len(blob) < e.a:
                        crc_bad += 1
                        continue
                    try:
                        out = A.decrypt_payload(arc, blob)
                    except (ValueError, NotImplementedError):
                        crc_bad += 1
                        continue
                    if A.entry_crc(out) == e.b:
                        crc_ok += 1
                    else:
                        crc_bad += 1
        crc = f"{crc_ok}/{crc_ok + crc_bad}" if (crc_ok or crc_bad) else "-"

        log(f"    parsed count={arc.count} crc={crc} "
            f"({time.time() - t:.2f}s)")
        named = []
        for nd in arc.nodes:
            if nd.key in names and nd.slot < len(arc.entries):
                e = arc.entries[nd.slot]
                nm = names[nd.key]
                nm = nm.decode("latin-1") if isinstance(nm, bytes) else nm
                named.append(f"{nm}@{e.c:#x}+{e.a:#x}")
        rows.append((p, size, arc.mode, arc.count,
                     "; ".join(probs[:2]) if probs else "ok",
                     crc, ", ".join(named)))

    with REPORT.open("w", encoding="utf-8") as f:
        f.write("path\tsize\tmode\tcount\tstatus\tcrc_ok\tresolved_entries\n")
        for p, size, mode, count, status, crc, named in rows:
            f.write(f"{p.relative_to(GAME)}\t{size}\t{mode:#x}\t{count}\t"
                    f"{status}\t{crc}\t{named}\n")

    crc_ok = crc_all = 0
    for _p, _s, _m, _c, _st, crc, _n in rows:
        if crc != "-":
            a, b = crc.split("/")
            crc_ok += int(a)
            crc_all += int(b)
    print(f"{len(files)} containers | sound={sound} rejected={bad}")
    print(f"entries in sound containers: "
          f"{sum(r[3] for r in rows if r[3] > 0):,}")
    print(f"payload CRC-32 verified: {crc_ok:,}/{crc_all:,} "
          f"(budget-capped, see CRC_BUDGET)")
    print(f"report -> {REPORT}")
    for p, size, mode, count, status, crc, named in rows:
        if status != "ok":
            print(f"  REJECT {p.relative_to(GAME)}: {status}")


if __name__ == "__main__":
    main()

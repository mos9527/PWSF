"""Probe: scan every PDT/DAT container on disk with full self-consistency checks,
and look for known entry names (SUBTITLE...).

Only the header + the two tables are read, never the payload, so multi-GB
archives are cheap to scan. The report is written to ANALYSIS/_archive_index.tsv.
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_archive as A
import pwsf_names as N

GAME = Path(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw")
ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "ANALYSIS" / "_archive_index.tsv"
HEAD_CAP = 8 << 20   # enough for ~230k entries

WANT = {N.entry_name_hash(n): n for n in
        ["SUBTITLE", "DBMINFO", "MUSIC", "ZAPPIN", "SCRIPT", "TEXT", "MOVIE"]}


def scan():
    files = sorted(p for p in GAME.rglob("*")
                   if p.suffix.lower() in (".pdt", ".dat") and p.is_file())
    sound = bad = named = 0
    ext_hist = Counter()
    rows = []
    for p in files:
        size = p.stat().st_size
        with p.open("rb") as f:
            raw = f.read(min(size, HEAD_CAP))
        try:
            arc = A.parse(raw, p.stem, str(p), max_entries=200000)
        except ValueError as e:
            bad += 1
            rows.append((p, size, -1, -1, f"PARSE: {e}", ""))
            continue
        probs = A.verify(arc, size)
        hits = [(WANT[nd.key], arc.entries[nd.slot]) for nd in arc.nodes
                if nd.key in WANT and nd.slot < len(arc.entries)]
        if probs:
            bad += 1
        else:
            sound += 1
            for nd in arc.nodes:
                if nd.key >> 24:
                    ext_hist[nd.key >> 24] += 1
        if hits:
            named += 1
        rows.append((p, size, arc.mode, arc.count,
                     "; ".join(probs[:2]) if probs else "ok",
                     ", ".join(f"{n}@{e.c:#x}+{e.a:#x}" for n, e in hits)))

    with REPORT.open("w", encoding="utf-8") as f:
        f.write("path\tsize\tmode\tcount\tstatus\tknown_entries\n")
        for p, size, mode, count, status, hits in rows:
            f.write(f"{p.relative_to(GAME)}\t{size}\t{mode:#x}\t{count}\t"
                    f"{status}\t{hits}\n")

    print(f"{len(files)} containers | sound={sound} rejected={bad} "
          f"with_known_names={named}")
    print(f"report -> {REPORT}")
    for p, size, mode, count, status, hits in rows:
        if status != "ok":
            print(f"  REJECT {p.relative_to(GAME)}: {status}")
    print("\nentries with a known name:")
    for p, size, mode, count, status, hits in rows:
        if hits:
            print(f"  {p.relative_to(GAME)}: {hits}")
    print("\nextension-id histogram:")
    for eid, c in ext_hist.most_common(25):
        print(f"   {eid:#04x} {','.join(N.ID_EXTS.get(eid, ['?'])):<12} {c}")


if __name__ == "__main__":
    scan()

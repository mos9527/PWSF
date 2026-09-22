"""Probe: can STAGEDAT (`009645fa.PDT`) be written back?

Everything `pwsf.stage` does today is read-only.  A write-back has to invert
the whole chain -- inner file archive -> zlib -> u32 prefix -> LCG mask -> MT
xor -> container -- and three things are not nailed down yet:

  Q1  is entry.b the CRC-32 of the ENCRYPTED payload or of the plain one?
  Q2  what is the u32 in front of the zlib stream (size? magic? checksum?)
  Q3  do the entries really consume the whole file, and how big is the job?

Usage:  python _probe_stage_wb.py [--entries 6]
"""
import argparse
import struct
import sys
import time
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from pwsf import stage                              # noqa: E402
from pwsf.archive import entry_crc, parse as arc_parse, verify as arc_verify
from pwsf.crypto import buffer_xor_decrypt


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--entries", type=int, default=6)
    args = ap.parse_args()

    p = stage.container_path()
    size = p.stat().st_size
    print(f"{p.name}  {size >> 20} MB")
    with p.open("rb") as f:
        head = f.read(stage.HEAD_CAP)
    arc = arc_parse(head, p.stem, str(p), max_entries=200000)
    problems = arc_verify(arc, size)
    print(f"mode {arc.mode:#x}  count {arc.count}  "
          f"names_off {arc.names_off:#x}  verify: {problems or 'ok'}")
    print(f"payload bytes on disk: "
          f"{sum(e.a for e in arc.entries) >> 20} MB")

    state0, inc = stage.seeding(arc)
    t0 = time.time()
    with p.open("rb") as f:
        for i in range(min(args.entries, arc.count)):
            e = arc.entries[i]
            f.seek(e.c)
            enc = f.read(e.a)
            plain = stage.payload(arc, enc, state0, inc)
            crc_enc = entry_crc(enc)
            crc_plain = entry_crc(plain)
            body, note = stage.inflate(plain)
            if body is None:
                print(f"  entry {i}: {note} -- skipped")
                continue
            prefix, = struct.unpack_from("<I", plain, 0)
            files, err = stage.inner_files(body)
            tail = body[sum(1 for _ in files):] if False else None
            # how many bytes does the layout consume?
            used = None
            if files:
                name, sz, _d = files[-1]
                used = "see below"
            print(f"  entry {i}: a={e.a:#x} b={e.b:#010x} "
                  f"crc(enc)={crc_enc:#010x} crc(plain)={crc_plain:#010x} "
                  f"-> b is {'ENCRYPTED' if crc_enc == e.b else 'plain' if crc_plain == e.b else '???'}")
            print(f"      zlib {note}  u32 prefix {prefix:#010x} "
                  f"(body {len(body):#x}) -> prefix is "
                  f"{'SIZE' if prefix == len(body) else 'not the size'}")
            print(f"      inner files {len(files)} err={err or 'none'}")
            for nm, sz, _d in files[:6]:
                print(f"        {nm:44} {sz:#x}")
            if err:
                continue
            # does the parse consume every byte?
            o = 4
            for nm, sz, _d in files:
                o = body.find(b"\x00", o) + 1
                o += (-o) % 4
                o += 4
                o += (-o) % 16
                o += sz + 1
            print(f"      layout ends at {o:#x} of {len(body):#x} "
                  f"({'exact' if o == len(body) else 'MISMATCH'})")
    print(f"({time.time() - t0:.1f}s for {args.entries} entries)")


if __name__ == "__main__":
    main()

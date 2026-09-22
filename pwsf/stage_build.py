"""STAGEDAT (`009645fa.PDT`) write-back -- the corpus that had none.

`pwsf.stage` reads the container; this is its inverse, and every step is the
exact mirror of what ANALYSIS/09 documented:

    container entry, 0x800-aligned and contiguous (ANALYSIS/04 §3)
      -> buffer_xor_decrypt(name_hash(stem)) + per-entry LCG unmask
         both are XOR layers, so they are their own inverse; the LCG is
         re-seeded FRESH per entry from the header (stage.seeding)
      -> u32 = the INFLATED size, then a zlib stream
         (measured: prefix == len(body) on every entry, _probe_stage_wb.py)
      -> inner file archive:
             u32 count
             per file: name (NUL-terminated, padded to 4)
                       u32 size
                       data at the next 16-byte boundary
                       1 zero byte after the data, not counted in size
      -> `*.olang` members are RBX tables, rebuilt by `pwsf.olang_build`

and the container's own tables:

    header   40 B, kept VERBATIM: the game unmasks header+0x0C..0x27 and then
             zeroes header+0x0C itself, so shipping the original bytes is
             both correct and the only thing that keeps the LCG stream aligned
    index    12 B per entry: u32 a = payload size
                             u32 b = CRC-32 of the PLAIN payload
                                     (measured, not guessed: crc(plain) == b on
                                      every entry, crc(encrypted) never does)
                             u32 c = offset
    names    24 B per entry, the name BST -- never touched

    Both tables are stored LCG-masked first and then MT-xor'd, with ONE LCG
    stream running header-scratch -> index -> names, so they have to be
    re-masked in that order.  The MT stream is one continuous run over
    header+index+names, which is why the header is included in the buffer and
    then thrown away.

Only the entries that actually carry a translation are decompressed; the other
544 are copied byte for byte.  Offsets are recomputed, so a payload may grow.

Usage:
    python -m pwsf.stage_build --check      # round-trip the shipped container
"""

import argparse
import struct
import zlib
from pathlib import Path

from . import config
from . import stage
from .archive import (HDR_SIZE, IDX_ENTRY, NAM_ENTRY, SCRATCH_OFF,
                      SCRATCH_SIZE, Entry, _unmask_lcg, _xor_stream,
                      entry_crc, parse as arc_parse, verify as arc_verify)
from .crypto import MT19937, buffer_xor_decrypt
from .olang import parse as olang_parse
from .olang_build import OlangBuilder

ALIGN = 0x800
MAX_ENTRIES = 200000


def source_path() -> Path:
    return stage.container_path()


def _align(n: int, a: int = ALIGN) -> int:
    return (n + a - 1) & ~(a - 1)


def _inner_pack(files: list) -> bytes:
    """[(name, data)] -> the inner file archive, mirroring stage.inner_files."""
    out = bytearray(struct.pack("<I", len(files)))
    for name, data in files:
        out += name.encode("latin-1") + b"\x00"
        out += b"\x00" * ((-len(out)) % 4)
        out += struct.pack("<I", len(data))
        out += b"\x00" * ((-len(out)) % 16)
        out += data
        out += b"\x00"
    return bytes(out)


def _encrypt(arc, plain: bytes, state0: int, inc: int) -> bytes:
    """Plain payload -> the bytes that go on disk (both layers are XORs)."""
    buf = bytearray(plain)
    dwords = len(buf) & ~3
    if dwords:
        _unmask_lcg(memoryview(buf)[:dwords], state0, inc)
    return bytes(buffer_xor_decrypt(buf, arc.key))


def _walk_end(body: bytes, files: list) -> int:
    """Where the inner-archive walk ends.  It has to be len(body).

    `stage.inner_files` stops as soon as `count` files parse, so a payload that
    is not an inner archive at all can yield a handful of tiny "files" and look
    fine -- 36 of the 557 entries do exactly that (they contribute no strings,
    the corpus only ever saw the 92 real ones).  Re-packing one of those would
    destroy it, hence the check.
    """
    o = 4
    for _name, size, _data in files:
        o = body.find(b"\x00", o) + 1
        o += (-o) % 4
        o += 4
        o += (-o) % 16
        o += size + 1
    return o


def _rebuild_plain(plain: bytes, want: dict, lang: int, level: int,
                   counter: list, problems: list) -> bytes:
    """One entry's plain payload with its olang members patched.

    Returns None when the entry holds nothing we translate -- then the shipped
    bytes are copied through untouched.
    """
    body, _note = stage.inflate(plain)
    if body is None:
        return None
    files, err = stage.inner_files(body)
    if err:
        problems.append(f"inner archive: {err}")
        return None
    if _walk_end(body, files) != len(body):
        problems.append(f"inner archive: walk ends at {_walk_end(body, files):#x}"
                        f" of {len(body):#x} -- not an inner archive, left alone")
        return None

    changed = False
    out = []
    for name, _size, data in files:
        if name in want and name.endswith(".olang") and data[:4] == b"RBX\x00":
            try:
                tbl = olang_parse(data, name)
            except (ValueError, struct.error) as exc:
                problems.append(f"{name}: {exc}")
                out.append((name, data))
                continue
            if lang not in {k[0] for k in tbl.keys}:
                out.append((name, data))
                continue
            b = OlangBuilder(tbl)
            n = 0
            for (gk, ek), text in want[name].items():
                try:
                    b.set_text(gk, ek, lang, text)
                except KeyError:
                    continue
                n += 1
            if n:
                data = b.serialize()
                changed = True
                counter[0] += n
        out.append((name, data))
    if not changed:
        return None
    packed = _inner_pack(out)
    return struct.pack("<I", len(packed)) + zlib.compress(packed, level)


def _tables(arc, head: bytes, entries: list) -> tuple:
    """(index, names) ready to write: re-masked, then MT-xor'd."""
    state0, inc = stage.seeding(arc)
    index = bytearray()
    for e in entries:
        index += struct.pack("<III", e.a, e.b, e.c)
    names = bytearray(arc.names)
    # one LCG stream: header scratch, then index, then names
    scratch = bytearray(head[SCRATCH_OFF:SCRATCH_OFF + SCRATCH_SIZE])
    st = _unmask_lcg(scratch, state0, inc)
    st = _unmask_lcg(index, st, inc)
    _unmask_lcg(names, st, inc)

    mt = MT19937(arc.key)
    mt.advance(20)
    buf = bytearray(head[:HDR_SIZE]) + index + names
    _xor_stream(buf, mt)
    return (bytes(buf[HDR_SIZE:HDR_SIZE + len(index)]),
            bytes(buf[HDR_SIZE + len(index):]))


def rebuild(translations: dict, lang: int = None, outdir: Path = None,
            level: int = 9, verbose: bool = True) -> tuple:
    """Write `{(rec, file, group, entry): text}` into a fresh `009645fa.PDT`.

    Returns (path, stats).  The shipped container is never modified: the
    result lands in `outdir` and only `install` puts it in the game.
    """
    lang = config.LANG_EN if lang is None else lang
    src = source_path()
    size = src.stat().st_size
    with src.open("rb") as f:
        head = f.read(stage.HEAD_CAP)
    arc = arc_parse(head, src.stem, str(src), max_entries=MAX_ENTRIES)
    problems = arc_verify(arc, size)
    if problems:
        raise SystemExit(f"{src.name}: container self-check failed: {problems}")
    if arc.mode != 0x40:
        raise SystemExit(f"{src.name}: expected mode 0x40, got {arc.mode:#x}")
    state0, inc = stage.seeding(arc)

    by_rec = {}
    for (rec, file, gk, ek), text in translations.items():
        by_rec.setdefault(rec, {}).setdefault(file, {})[(gk, ek)] = text

    counter, notes = [0], []
    new_plain = {}
    with src.open("rb") as f:
        for rec in sorted(by_rec):
            e = arc.entries[rec]
            f.seek(e.c)
            plain = stage.payload(arc, f.read(e.a), state0, inc)
            built = _rebuild_plain(plain, by_rec[rec], lang, level,
                                   counter, notes)
            if built is None:
                notes.append(f"entry {rec}: nothing to write")
                continue
            new_plain[rec] = built

    entries = list(arc.entries)
    off = _align(arc.names_off + NAM_ENTRY * arc.count)
    for i, e in enumerate(entries):
        p = new_plain.get(i)
        a, b = (len(p), entry_crc(p)) if p is not None else (e.a, e.b)
        entries[i] = Entry(a=a, b=b, c=off)
        off = _align(off + a)

    index, names = _tables(arc, head, entries)
    outdir = Path(outdir or config.BUILD_DIR)
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"{src.stem}.PDT"

    with src.open("rb") as fin, out.open("wb") as fout:
        fout.write(head[:HDR_SIZE])
        fout.write(index)
        fout.write(names)
        fout.write(b"\x00" * (entries[0].c - fout.tell()))
        for i, e in enumerate(entries):
            if i in new_plain:
                blob = _encrypt(arc, new_plain[i], state0, inc)
            else:
                old = arc.entries[i]
                fin.seek(old.c)
                blob = fin.read(old.a)
            if len(blob) != e.a:
                raise SystemExit(f"entry {i}: built {len(blob)} B, index says "
                                 f"{e.a} B")
            fout.write(blob)
            fout.write(b"\x00" * (_align(len(blob)) - len(blob)))

    stats = dict(entries=arc.count, rebuilt=len(new_plain),
                 strings=counter[0], size=out.stat().st_size,
                 source=size, problems=notes)
    if verbose:
        print(f"STAGEDAT: {len(by_rec)} entry/entries asked for, "
              f"{len(new_plain)} rebuilt, {counter[0]} string(s) written")
        print(f"  {out.name}  {stats['size'] >> 20} MB "
              f"(source {size >> 20} MB)")
    return out, stats


def verify(path: Path, translations: dict, lang: int = None,
           source: Path = None) -> list:
    """Re-read a built container: translations present, everything else intact.

    Unchanged entries are copied byte for byte, so only the rebuilt ones are
    opened -- and for those every inner file that was not rewritten must come
    back identical to the shipped container.
    """
    lang = config.LANG_EN if lang is None else lang
    src = Path(source or source_path())
    problems = []

    def inner(path_, arc, state0, inc, e):
        with path_.open("rb") as f:
            f.seek(e.c)
            plain = stage.payload(arc, f.read(e.a), state0, inc)
        body, _n = stage.inflate(plain)
        if body is None:
            return None
        files, err = stage.inner_files(body)
        return None if err else files

    def load(path_):
        size = path_.stat().st_size
        with path_.open("rb") as f:
            head = f.read(stage.HEAD_CAP)
        arc = arc_parse(head, path_.stem, str(path_), max_entries=MAX_ENTRIES)
        problems_ = arc_verify(arc, size)
        return arc, stage.seeding(arc), problems_

    arc_new, (s0, i0), p_new = load(Path(path))
    problems += [f"built: {x}" for x in p_new]
    arc_old, (s1, i1), _p = load(src)

    by_rec = {}
    for (rec, file, gk, ek), text in translations.items():
        by_rec.setdefault(rec, {}).setdefault(file, {})[(gk, ek)] = text

    for rec in sorted(by_rec):
        new_files = inner(Path(path), arc_new, s0, i0, arc_new.entries[rec])
        old_files = inner(src, arc_old, s1, i1, arc_old.entries[rec])
        if new_files is None or old_files is None:
            problems.append(f"entry {rec}: cannot re-read the inner archive")
            continue
        if len(new_files) != len(old_files):
            problems.append(f"entry {rec}: {len(new_files)} file(s) vs "
                            f"{len(old_files)}")
            continue
        for (nname, nsize, ndata), (oname, osize, odata) in zip(new_files,
                                                                old_files):
            if nname != oname:
                problems.append(f"entry {rec}: file {nname} != {oname}")
                continue
            if nname in by_rec[rec]:
                tbl = olang_parse(ndata, nname)
                b = OlangBuilder(tbl)
                for (gk, ek), text in by_rec[rec][nname].items():
                    try:
                        got = b.get_text(gk, ek, lang)
                    except KeyError:
                        problems.append(f"entry {rec} {nname}: "
                                        f"group {gk:#x}/entry {ek:#x} gone")
                        continue
                    if got != text:
                        problems.append(f"entry {rec} {nname}: {got!r} != "
                                        f"{text!r}")
            elif ndata != odata:
                problems.append(f"entry {rec}: {nname} changed but was not "
                                f"translated")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="round-trip the shipped container without changing "
                         "anything: re-pack every entry and compare")
    ap.add_argument("--outdir", type=Path, default=config.BUILD_DIR)
    args = ap.parse_args()
    config.require_game()
    if args.check:
        _check(args.outdir)
        return
    print(__doc__)


def _check(outdir: Path) -> None:
    """Round-trip oracle: an empty translation set must reproduce the source."""
    src = source_path()
    size = src.stat().st_size
    with src.open("rb") as f:
        head = f.read(stage.HEAD_CAP)
    arc = arc_parse(head, src.stem, str(src), max_entries=MAX_ENTRIES)
    problems = arc_verify(arc, size)
    if problems:
        raise SystemExit(f"source self-check failed: {problems}")
    state0, inc = stage.seeding(arc)

    n_same = n_diff = n_skip = 0
    with src.open("rb") as f:
        for i, e in enumerate(arc.entries):
            f.seek(e.c)
            enc = f.read(e.a)
            plain = stage.payload(arc, enc, state0, inc)
            body, _note = stage.inflate(plain)
            if body is None:
                n_skip += 1
                continue
            files, err = stage.inner_files(body)
            if err:
                n_skip += 1
                continue
            packed = _inner_pack([(nm, d) for nm, _s, d in files])
            if packed == body and _encrypt(arc, plain, state0, inc) == enc:
                n_same += 1
            else:
                n_diff += 1
                if n_diff < 4:
                    print(f"  entry {i}: repack differs "
                          f"({len(packed):#x} vs {len(body):#x})")
    print(f"round-trip: {n_same} entry/entries byte-identical, {n_diff} differ, "
          f"{n_skip} not an inner archive")


if __name__ == "__main__":
    main()

"""STAGEDAT (`009645fa.PDT`): payload decryption, inner file archive, olang tables.

Why this module exists: the 17 on-disk `.olang` files, SLOT.DAT and BRIEFING
are NOT the whole corpus.  STAGEDAT carries 92 inner file archives with 738
`.olang` tables (mission info, stage telops, Mother Base staff comments, item
and weapon text) -- 97,989 strings, of which 10,570 are not in SLOT.DAT.

Everything below is backed by ANALYSIS/09_stagedat_payload.md:

  entry_payload_transform   0x140123E90   mode 0x40 payload unmask
  sub_140123DB0             0x140123DB0   LCG key derive (header/index/names)
  archive_index_load        0x1401238C0   container parse (pwsf.archive)

Payload chain, each link verified:

    entry payload
      -> buffer_xor_decrypt(name_hash(stem))                04_archive.md §4
      -> LCG unmask, FRESH per entry, seeded from the header:
             s = hi ^ lo
             state = s | ((s ^ 0x6576) << 16)
             inc   = m * s
         Proven by CRC-32 oracle (_probe_stagedat.py): 6/6 under this seeding,
         0/6 under "stream continues across entries" and 0/6 under MT-only.
      -> u32 + zlib (0x78 0xda)
      -> inner file archive:
             u32  count
             per file:  name (NUL-terminated, padded to 4)
                        u32  size
                        data at the next 16-byte boundary
                        1 byte 0x00 after the data, not counted in size
         Layout selected by exhaustive search (_probe_inner_layout.py) whose
         only survivor is (pad 4, no extra u32, align 16, tail 1) -- the
         criterion is objective: `count` files AND every byte consumed.
      -> `*.olang` members are plain RBX tables (pwsf.olang)

Usage:
    python -m pwsf.stage                       # -> ANALYSIS/_stage_olang_lines.tsv
    python -m pwsf.stage -o out.tsv --langs en
"""

import argparse
import struct
import zlib
from pathlib import Path

from . import config
from .archive import parse as arc_parse, verify as arc_verify, entry_crc
from .archive import _unmask_lcg
from .crypto import buffer_xor_decrypt
from .olang import parse as olang_parse, string_at

STEM = "009645fa"
MASK32 = 0xFFFFFFFF
HEAD_CAP = 8 << 20              # a parse only needs the header + the two tables

# language tag of an inner olang file, taken from its name:
#   lang_mission_info.olang     -> ""  (Japanese, the base file)
#   lang_mission_info_en.olang  -> "en"
_LANG_SUFFIXES = ("_en", "_fr", "_ge", "_it", "_sp")


def container_path() -> Path:
    """The STAGEDAT container, through config.pristine() like every source."""
    return config.pristine(config.GAME_DIR / "MLG" / "disc0_rel"
                           / f"{STEM}.PDT")


def seeding(arc) -> tuple:
    """(state0, inc) for the mode 0x40 payload unmask, from the header."""
    s = (arc.hi ^ arc.lo) & MASK32
    return (s | ((s ^ 0x6576) << 16)) & MASK32, (arc.m * s) & MASK32


def payload(arc, blob: bytes, state0: int, inc: int) -> bytes:
    """MT layer + per-entry LCG; CRC-32 of the result is the entry's own."""
    buf = buffer_xor_decrypt(bytearray(blob), arc.key)
    dwords = len(buf) & ~3
    if dwords:
        _unmask_lcg(memoryview(buf)[:dwords], state0, inc)
    return bytes(buf)


def inflate(plain: bytes) -> tuple:
    """u32 header + zlib stream -> (body, note); (None, note) if not zlib."""
    if plain[4:6] == b"\x78\xda":
        raw, off = plain[4:], 4
    elif plain[:2] == b"\x78\xda":
        raw, off = plain[2:], 2
    else:
        return None, "raw"
    try:
        return zlib.decompressobj().decompress(raw), f"zlib@{off}"
    except zlib.error as exc:
        return None, f"zlib_fail:{exc}"


def inner_files(body: bytes) -> tuple:
    """Parse the inner file archive.  Returns (files, err).

    files is a list of (name, size, data).  err is "" only when `count` files
    were read AND every byte of `body` is accounted for -- that is what makes
    the layout trustworthy rather than eyeballed.
    """
    if len(body) < 4:
        return [], "shorter than the 4-byte count"
    count, = struct.unpack_from("<I", body, 0)
    if not 0 < count <= 4096:
        return [], f"implausible count {count}"
    files, o = [], 4
    for _ in range(count):
        end = body.find(b"\x00", o)
        if end < 0 or end - o > 256:
            return [], f"unterminated/oversized name at {o:#x}"
        name = body[o:end]
        p = end + 1
        p += (-p) % 4
        if p + 4 > len(body):
            return [], f"size cut at {p:#x}"
        size, = struct.unpack_from("<I", body, p)
        p += 4
        p += (-p) % 16
        data = body[p:p + size]
        if size == 0 or len(data) < size:
            return [], f"data cut at {p:#x} ({size:#x} B)"
        files.append((name.decode("latin-1"), size, data))
        o = p + size + 1
    return files, ""


def lang_of(filename: str) -> str:
    stem = filename[:-6] if filename.endswith(".olang") else filename
    for suf in _LANG_SUFFIXES:
        if stem.endswith(suf):
            return suf[1:]
    return "ja"       # the base file (no suffix) carries Japanese


def iter_records(container: Path = None, langs=None, on_entry=None):
    """Yield one record per olang string in STAGEDAT.

    Fields: rec (container entry index), file, table_id, lang, group, entry,
    key, meta, text.
    """
    container = container or container_path()
    with container.open("rb") as f:
        arc = arc_parse(f.read(min(container.stat().st_size, HEAD_CAP)),
                        container.stem, str(container), max_entries=200000)
    problems = arc_verify(arc, container.stat().st_size)
    if problems:
        raise SystemExit(f"{container.name}: container self-check failed: "
                         f"{problems}")
    if arc.mode != 0x40:
        raise SystemExit(f"{container.name}: expected mode 0x40, got "
                         f"{arc.mode:#x}")
    state0, inc = seeding(arc)

    with container.open("rb") as f:
        for i in range(arc.count):
            e = arc.entries[i]
            f.seek(e.c)
            plain = payload(arc, f.read(e.a), state0, inc)
            body, _note = inflate(plain)
            if body is None:
                continue
            files, err = inner_files(body)
            if err:
                continue
            if on_entry:
                on_entry(i, arc.count, len(files))
            for name, _size, data in files:
                if not name.endswith(".olang") or data[:4] != b"RBX\x00":
                    continue
                lang = lang_of(name)
                if langs and lang not in langs:
                    continue
                try:
                    tbl = olang_parse(data, name)
                except (ValueError, struct.error):
                    continue
                for st in tbl.strings():
                    text = string_at(tbl, st.offset).decode("utf-8", "replace")
                    if not text:
                        continue
                    yield dict(rec=i, file=name, table_id=tbl.table_id,
                               lang=lang, group=st.group, entry=st.entry,
                               key=st.key, meta=st.meta, text=text)


HEADER = ("rec\tfile\ttable_id\tlang\tgroup\tentry\tkey\tmeta\ttext")


def dump_lines(out: Path = None, langs=None, container: Path = None) -> int:
    """Write ANALYSIS/_stage_olang_lines.tsv.  Returns the row count."""
    out = out or config.STAGE_OLANG_TSV
    n = 0
    with out.open("w", encoding="utf-8") as f:
        f.write(HEADER + "\n")
        for r in iter_records(container, langs):
            f.write(f"{r['rec']}\t{r['file']}\t{r['table_id']:#010x}\t"
                    f"{r['lang']}\t{r['group']:#08x}\t{r['entry']:#08x}\t"
                    f"{r['key']:#08x}\t{r['meta']:#06x}\t"
                    f"{r['text']}\n")
            n += 1
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--out", type=Path, default=config.STAGE_OLANG_TSV)
    ap.add_argument("--langs", default="",
                    help="comma separated languages (default: all six)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    config.require_game()
    langs = tuple(x for x in args.langs.split(",") if x) or None

    done = [0]

    def note(i, total, files):
        done[0] = i
        if args.verbose:
            print(f"  entry {i}/{total}: {files} file(s)", flush=True)

    n = 0
    with args.out.open("w", encoding="utf-8") as f:
        f.write(HEADER + "\n")
        for r in iter_records(on_entry=note if args.verbose else None,
                              langs=langs):
            f.write(f"{r['rec']}\t{r['file']}\t{r['table_id']:#010x}\t"
                    f"{r['lang']}\t{r['group']:#08x}\t{r['entry']:#08x}\t"
                    f"{r['key']:#08x}\t{r['meta']:#06x}\t{r['text']}\n")
            n += 1
    print(f"{n} line(s) -> {args.out}")


if __name__ == "__main__":
    main()

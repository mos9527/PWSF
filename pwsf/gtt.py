"""GTT pools -- the second text container inside SLOT.DAT (ANALYSIS/11).

The 462 `GTT\\x00` pools of SLOT.DAT (records 0..365) hold the in-mission radio
and hint lines.  They are NOT olang: `slotdat_find_res_entry` @ 0x1400A61F0 only
accepts entries with `(id & 0x7F000000) == 0x20000000`, and these pools are
`0x1c??????`, which is why every previous extraction walked straight past them.

Layout (measured on pool 0x1c79f20b / record 84, blocks with n = 1,2,3,5):

    a pool is a concatenation of blocks; per block
        +0x00  "GTT\\x00"
        +0x04  u32 n            lines in the block
        +0x08  u32 pool_off     header size == start of the string pool
        +0x0c  u32 ident        per-block id, kept as-is by write-back
        +0x10  u16, u16         (not interpreted)
        +0x14  u32 1
        +0x18  u32 0
        +0x1c  u16 array, length 4 + 10*n
                   [0..3]  four copies of the start offset of line 1
                   per line i, ten words: [a, b, 1, X,X,X, Y,Y,Y, Y]
                   X = start offset of line i+1, Y = start of line i+2
                   (the last group is zero padding)
        pool   suffix-merged: one NUL-terminated run holds the head of another
               language immediately followed by a whole line of the primary
               language, e.g. `Je t\\xe2The signal is unidirectional.`
               -> a line reads as pool[start : next NUL]

`a` and `b` are the line's TIMING, not pointers (`_probe_gtt8.py`): they exceed
the pool length 618 / 3,672 times over the whole corpus, so they cannot be
offsets; `a[i+1] - b[i]` has median 3 (the next line starts a few frames after
the one before it ended) and `(b - a)` tracks the line length at a median of
1.35 frames per character.  So the group reads
`[start_frame, end_frame, 1, X,X,X, Y,Y,Y, Y]`.

Write-back nevertheless never changes a pool's length: every offset in the
header -- X, Y and the unknown fields of the fixed part -- keeps pointing where
it did, and the shipped timing is left alone (the Chinese line simply shows for
the duration the English one had).  That is the same bargain
`pwsf.briefing_build` makes with its pool budget (ANALYSIS/03 §9); the budget
is reported by `po_lint` as `gtt-budget`.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from . import config

MAGIC = b"GTT\x00"
ARRAY_AT = 0x1C
GROUP = 10          # u16 per line in the header array
PREFIX = 4          # u16 before the per-line groups

MASK16 = 0xFFFF


@dataclass(frozen=True)
class Block:
    """One `GTT\\x00` block of a pool."""
    off: int        # offset of the block inside the pool
    end: int        # one past the last byte of the block
    n: int
    pool_off: int
    ident: int
    array: tuple    # the u16 header array
    pool: bytes     # the string pool (blob[off + pool_off : end])

    @property
    def starts(self) -> list:
        """Start offset of every line inside the pool.

        Line 0 is at 0 (never stored); the array carries the rest, three or
        four times each -- `X` of group i is the start of line i+1.
        """
        out = [0]
        body = self.array[PREFIX:]
        for i in range(max(self.n - 1, 0)):
            g = body[GROUP * i:GROUP * i + GROUP]
            if len(g) < 4 or not g[3]:
                continue
            out.append(g[3])
        return out

    def line(self, i: int) -> bytes:
        """The line's bytes: from its start offset up to the next NUL."""
        st = self.starts[i]
        if st >= len(self.pool):
            return b""
        j = self.pool.find(b"\x00", st)
        return self.pool[st:] if j < 0 else self.pool[st:j]

    def budget(self, i: int) -> int:
        """How many bytes a translation may use (the English run's length)."""
        return len(self.line(i))

    def limit(self, i: int) -> int:
        """Offset the line may NOT write into (the NUL that ends the run)."""
        st = self.starts[i]
        j = self.pool.find(b"\x00", st)
        return len(self.pool) if j < 0 else j


def block_offsets(blob: bytes) -> list:
    return [i for i in range(len(blob) - 3) if blob.startswith(MAGIC, i)]


def parse_block(blob: bytes, off: int, end: int) -> Block:
    n, pool_off, ident = struct.unpack_from("<III", blob, off + 4)
    if pool_off <= ARRAY_AT:
        raise ValueError(f"block @{off:#x}: pool_off {pool_off:#x} too small")
    nwords = (pool_off - ARRAY_AT) // 2
    array = struct.unpack_from("<%dH" % nwords, blob, off + ARRAY_AT)
    return Block(off, end, n, pool_off, ident, array,
                 blob[off + pool_off:end])


def parse(blob: bytes) -> list:
    """Every block of one GTT pool."""
    offs = block_offsets(blob)
    out = []
    for k, o in enumerate(offs):
        end = offs[k + 1] if k + 1 < len(offs) else len(blob)
        try:
            out.append(parse_block(blob, o, end))
        except (struct.error, ValueError):
            continue
    return out


def lines(blob: bytes) -> list:
    """[(block_index, line_index, ident, text, budget)] of one pool."""
    out = []
    for bi, b in enumerate(parse(blob)):
        for li in range(b.n):
            if li >= len(b.starts):
                continue
            out.append((bi, li, b.ident, b.line(li), b.budget(li)))
    return out


# ------------------------------------------------------------------ write-back

def patch(blob: bytes, changes: dict, problems: list = None) -> bytes:
    """Write `{(block_offset, line_index): text}` into a pool, in place.

    Blocks are addressed by their offset in the pool, not by their index: the
    offset is what a `gtt/...` reference carries and it does not move when an
    earlier block is skipped.

    The pool length never changes: the new bytes are written at the line's
    offset and the rest of the original run is zero-filled, so the NUL that
    ended the English line stays where it was.  A change that does not fit is
    skipped and reported through `problems`.
    """
    problems = [] if problems is None else problems
    by_off = {b.off: b for b in parse(blob)}
    out = bytearray(blob)
    for (boff, li), text in sorted(changes.items()):
        b = by_off.get(boff)
        if b is None:
            problems.append(f"block @{boff:#x} does not exist")
            continue
        if li >= len(b.starts):
            problems.append(f"block @{boff:#x} line {li} does not exist")
            continue
        raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        if b"\x00" in raw:
            problems.append(f"block @{boff:#x} line {li}: NUL in the "
                            f"translation")
            continue
        budget = b.budget(li)
        if len(raw) > budget:
            problems.append(f"block @{boff:#x} line {li}: needs {len(raw)} B, "
                            f"budget {budget} B ({b.line(li)[:40]!r})")
            continue
        st = b.off + b.pool_off + b.starts[li]
        limit = b.off + b.pool_off + b.limit(li)
        out[st:st + len(raw)] = raw
        if st + len(raw) < limit:
            out[st + len(raw):limit] = b"\x00" * (limit - st - len(raw))
    return bytes(out)


def verify(blob: bytes, changes: dict) -> list:
    """Re-read `changes` back out of a patched pool.  Returns problems."""
    by_off = {b.off: b for b in parse(blob)}
    problems = []
    for (boff, li), text in sorted(changes.items()):
        b = by_off.get(boff)
        if b is None:
            problems.append(f"block @{boff:#x} vanished")
            continue
        raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        try:
            got = b.line(li)
        except IndexError:
            problems.append(f"block @{boff:#x} line {li} vanished")
            continue
        if got != raw:
            problems.append(f"block @{boff:#x} line {li}: {got!r} != {raw!r}")
    return problems


# ---------------------------------------------------------------- pool walker

def to_game_text(s: str) -> bytes:
    """A `.po` msgstr -> the bytes the game stores.

    Like CODEC and olang, a line break is a two-character `\\n` escape in the
    binary, while a `.po` carries a real newline.  Budget accounting goes
    through here, because the escape is two bytes.
    """
    return s.replace("\n", "\\n").encode("utf-8")


# One text set ships as one pool per language: the English pool is the base id
# and every other language sits at a fixed offset above it.  Measured on all
# 181 pools -- 36 sets, no singletons, and the base pool of each set is the one
# whose lines are pure ASCII:
#     0x1c767903 en  0x1c767927 fr  0x1c76793a de  0x1c767989 it  0x1c767ac5 es
#     0x1c79f20b en  0x1c79f22f fr  0x1c79f242 de  0x1c79f291 it  0x1c79f3cd es
#     0x1c0fb1c9 en  0x1c0fb1ed fr  0x1c0fb200 de  0x1c0fb24f it  0x1c0fb38b es
# (+0x0a2 shows up once, a single-line pool -- language unidentified, and it is
#  not exported either way.)
LANG_OFFSETS = {0x000: "en", 0x024: "fr", 0x037: "de", 0x086: "it",
                0x0A2: "?", 0x1C2: "es"}


def english_pools(ids) -> set:
    """The ids that are the English (base) pool of their set.

    A pool sitting at a known language offset above another pool is that
    language's copy, so it is dropped -- the corpus is English-only, exactly
    like the olang and CODEC corpora.
    """
    ids = set(ids)
    return {i for i in ids
            if not any(i - off in ids for off in LANG_OFFSETS if off)}


def is_ascii(text: str) -> bool:
    return all(ord(c) < 0x80 for c in text)


def escape(s: str) -> str:
    """Inverse of `pwsf.slotdat.unescape`: backslash first, restored last."""
    return (s.replace("\\", "\\\\").replace("\n", "\\n")
            .replace("\t", "\\t").replace("\r", "\\r"))


def dump(out=None, verbose: bool = True) -> int:
    """Extract every GTT line to `ANALYSIS/_gtt_lines.tsv` (ANALYSIS/11 §1).

    Columns: pool / block / ident / line / budget / record / text.  `budget`
    is what `po_lint`'s `gtt-budget` rule measures a translation against.
    """
    out = Path(out) if out else config.GTT_TSV
    blobs = list(pool_blobs())
    ids = {eid for _rec, eid, _b in blobs}
    keep = english_pools(ids)
    rows, non_ascii = [], []
    for rec, eid, blob in blobs:
        if eid not in keep:
            continue
        for b in parse(blob):
            for li in range(len(b.starts)):
                txt = b.line(li)
                if not txt:
                    continue
                s = txt.decode("utf-8", "replace")
                if not is_ascii(s):
                    non_ascii.append((f"{eid:#010x}", s[:40]))
                rows.append((f"{eid:#010x}", f"{b.off:#x}", f"{b.ident:#x}",
                             str(li), str(b.budget(li)), str(rec), escape(s)))
    seen, uniq = set(), []
    for r in rows:
        if r[6] in seen:
            continue
        seen.add(r[6])
        uniq.append(r)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        fh.write("pool\tblock\tident\tline\tbudget\trecord\ttext\n")
        for r in uniq:
            fh.write("\t".join(r) + "\n")
    if verbose:
        print(f"{len(ids)} GTT pools, {len(keep)} English "
              f"({len(ids) - len(keep)} other-language copies dropped)")
        print(f"wrote {len(uniq)} lines ({len(rows)} with duplicates) -> "
              f"{out}")
        if non_ascii:
            print(f"  {len(non_ascii)} non-ASCII line(s) in an English pool "
                  f"(first: {non_ascii[:3]})")
    return len(uniq)


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()
    config.require_game()
    dump(args.out)


def pool_blobs(ks: bytes = None, dat_path=None):
    """(record_index, pool_id, blob) for every GTT pool in SLOT.DAT.

    Same shape as `pwsf.slotdat.embedded_olang`'s generator argument: pass the
    result to `parse()` per blob.
    """
    from . import slotdat as S

    recs = S.load_index()
    state, inc = S.lcg_params()
    nd = max(r.stored for r in recs) * S.SECTOR // 4 + 16
    ks = ks or S.keystream(nd, state, inc)
    for rec in recs:
        try:
            pools = S.pools(rec, ks, dat_path)
        except Exception:                                # noqa: BLE001
            continue
        for eid, _off, blob in pools:
            if len(blob) >= 0x20 and blob[:4] == MAGIC:
                yield rec.index, eid, blob


if __name__ == "__main__":
    main()

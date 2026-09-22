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

### Write-back: the block is re-laid-out, its length never changes

`a` / `b` being timing (and every language having its own pool) is what makes a
rebuild safe: no other structure points into the string area except the line
starts themselves, and all of them are known.  A block's runs are laid out
`boundary = [0, start_1 .. start_{n-1}, end_of_strings]` and the header array
is nothing but copies of that list:

    array[0..3]      = boundary[1]
    X(i) = array[..] = boundary[i + 1]       (words 3,4,5 of group i)
    Y(i)             = boundary[i + 2]       (words 6..9 of group i)
    group n-1        = zero padding

(proved on every English block: `_probe_gtt_rebuild.py`, 5,878 blocks rebuilt
and read back byte-identical).  So `rebuild_block` drops the suffix merging,
writes the runs back to back and zero-fills the rest -- **the pool keeps its
exact length**, so the SLOT.DAT record's byte budget is untouched, while the
fragments' bytes become slack a translation can grow into.  Over the whole
corpus that is 146,764 B reclaimed against 266,616 B of translations, i.e. the
budget stops being a constraint at all (ANALYSIS/11 §5.2).
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

    @property
    def slack(self) -> int:
        """Bytes of the pool no line needs: the suffix-merged fragments.

        `rebuild_block` drops those fragments, so this is what a translation
        may grow into.  Measured over all 5,878 English blocks: 146,764 B,
        median 23 B per block, and only 11 blocks have none.
        """
        return len(self.pool) - sum(len(self.line(i)) + 1
                                    for i in range(len(self.starts)))

    def budget(self, i: int) -> int:
        """How many bytes a translation may use.

        The block is re-laid-out unmerged, so a line is no longer capped at its
        English length -- it may also take the fragments' bytes.  The share
        quoted here is `slack // n`, which every line of the block can take
        simultaneously (the build itself only needs the block total to fit).
        """
        n = len(self.starts)
        return len(self.line(i)) + (max(self.slack, 0) // n if n else 0)


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

def rebuild_block(blob: bytes, texts: dict) -> bytes:
    """Re-lay-out one `GTT\\x00` block; returns the same number of bytes.

    `texts` is `{line_index: bytes}`; lines it omits keep their English.  The
    runs are written back to back at the start of the pool and the rest is
    zero-filled, which drops the suffix-merged fragments and frees their bytes
    for longer translations -- without changing the block's length, so the
    SLOT.DAT record still has exactly the byte budget it had.

    The header array is then rebuilt from the new boundaries
    (`boundary = [0, start_1 .. start_{n-1}, end_of_strings]`):

        array[0..3] = boundary[1]
        X(i)        = boundary[i + 1]      group i, words 3,4,5
        Y(i)        = boundary[i + 2]      group i, words 6..9

    Group `n-1` is zero padding and `a` / `b` (the timing) are left alone.
    Raises `ValueError` when the runs do not fit.
    """
    b = parse_block(blob, 0, len(blob))
    n = len(b.starts)
    runs = []
    for i in range(n):
        raw = texts.get(i)
        if raw is None:
            raw = b.line(i)
        raw = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
        if b"\x00" in raw:
            raise ValueError(f"line {i}: NUL in the text")
        runs.append(raw)
    need = sum(len(r) + 1 for r in runs)
    if need > len(b.pool):
        raise ValueError(f"the lines need {need} B, the pool holds "
                         f"{len(b.pool)} B")

    pool = bytearray(len(b.pool))
    starts, at = [], 0
    for r in runs:
        starts.append(at)
        pool[at:at + len(r)] = r
        at += len(r) + 1                    # the NUL
    boundary = starts + [at]

    arr = list(b.array)
    for i in range(n - 1):
        g = PREFIX + GROUP * i
        if g + GROUP > len(arr) or i + 1 >= len(boundary):
            break
        arr[g + 3] = arr[g + 4] = arr[g + 5] = boundary[i + 1] & MASK16
        if i + 2 < len(boundary):
            arr[g + 6] = arr[g + 7] = arr[g + 8] = arr[g + 9] = \
                boundary[i + 2] & MASK16
    if len(arr) >= 4:
        arr[0] = arr[1] = arr[2] = arr[3] = boundary[1] & MASK16
    head = bytearray(blob[:b.pool_off])
    struct.pack_into("<%dH" % len(arr), head, ARRAY_AT, *arr)
    return bytes(head) + bytes(pool)


def patch(blob: bytes, changes: dict, problems: list = None) -> bytes:
    """Write `{(block_offset, line_index): text}` into a pool.

    Blocks are addressed by their offset in the pool, not by their index: the
    offset is what a `gtt/...` reference carries and it does not move when an
    earlier block is skipped.

    Every block that carries a change is rebuilt by `rebuild_block`, so a line
    is no longer capped at its English byte length -- it may grow into the
    slack the suffix-merged fragments used to occupy.  The block length, and
    with it the record's byte budget, never changes.  A block whose lines do
    not all fit is left alone and reported through `problems`.
    """
    problems = [] if problems is None else problems
    by_off = {b.off: b for b in parse(blob)}
    per_block = {}
    for (boff, li), text in sorted(changes.items()):
        per_block.setdefault(boff, {})[li] = text
    out = bytearray(blob)
    for boff, texts in sorted(per_block.items()):
        b = by_off.get(boff)
        if b is None:
            problems.append(f"block @{boff:#x} does not exist")
            continue
        raw = {}
        for li, text in sorted(texts.items()):
            if li >= len(b.starts):
                problems.append(f"block @{boff:#x} line {li} does not exist")
                continue
            raw[li] = text
        if not raw:
            continue
        try:
            rebuilt = rebuild_block(blob[b.off:b.end], raw)
        except ValueError as exc:
            problems.append(f"block @{boff:#x}: {exc}")
            continue
        if len(rebuilt) != b.end - b.off:
            problems.append(f"block @{boff:#x}: rebuilt length changed")
            continue
        out[b.off:b.end] = rebuilt
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
    # Deduplicate by ADDRESS, not by text: one pool lives in several records
    # (so its rows repeat), but the same English sentence also sits at several
    # different addresses inside one pool -- and an address that is not listed
    # here gets no reference, so its line stays English even though the very
    # same words are translated elsewhere.  `po_export` merges by msgid, so
    # this costs no extra entries, only extra `#:` lines.
    seen, uniq = set(), []
    for r in rows:
        key = (r[0], r[1], r[3])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(r)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        fh.write("pool\tblock\tident\tline\tbudget\trecord\ttext\n")
        for r in uniq:
            fh.write("\t".join(r) + "\n")
    if verbose:
        texts = {r[6] for r in uniq}
        print(f"{len(ids)} GTT pools, {len(keep)} English "
              f"({len(ids) - len(keep)} other-language copies dropped)")
        print(f"wrote {len(uniq)} addresses / {len(texts)} distinct texts "
              f"({len(rows)} rows, the rest are other records' copies) -> "
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

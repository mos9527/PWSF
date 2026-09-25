r"""Write translations back into the CODEC / BRIEFING container.

    src/codec/*.po  -->  0076531d.DAT     (rewritten in place, same size)

Why it is an in-place rewrite and not a rebuild
-----------------------------------------------
A record is addressed from the outside by its *absolute file offset*: the
request word packs ``idx | sector<<8 | (pages-1)<<24`` and the runtime calls
``sub_1408C57D0(buffer + 16*idx)`` with ``sector = off >> 12``,
``idx = (off & 0xFFF) >> 4`` (ANALYSIS/03 §9.2).  The TOPIC -> req table that
holds those words is filled at runtime by ``sub_14025A6C0`` out of the token
stream of *another* script file, which has not been located.  So a record may
not move, and the file may not change size: the gap to the next record is only
0-15 bytes of alignment padding.  No translatable text lives in the bytecode
either (§9.1), so nothing there has to be re-emitted.  What is left:

    rewrite the string pool, rebuild the u32 offset table, keep everything else

The pool: `off1` -> u32 offset table, `off2` -> NUL-terminated UTF-8 strings,
`off3 = off0 - 4` -> end of the pool.  Budget is therefore ``off3 - off2``, and
``off0..off3`` are never touched.

Evidence (research/TOOLS/_probe_bri53.py)
-----------------------------------------
    [A]  off3 == off0 - 4, off2 - off1 == 4 * n_lines, table[0] == 0
         2049 / 2049 records
    [E3] relayout = strings packed back to back + cumulative offsets + the
         bytes past the new end left exactly as they were; replaying the
         *original* lines through it reproduces the original file
         2049 / 2049, byte for byte -- so the rule is the generator's own
    [B]  the budget is nearly exhausted by the shipped text: the two English
         blocks hold 358 records with 252,504 pool bytes of which 251,949 are
         in use -- 555 free bytes.  Chinese is shorter than English in UTF-8
         (median byte ratio 0.75 measured on the olang translations), so it
         fits, but a translation that is *longer* than the English it replaces
         does not, and there is no way to make room for it.  Such a record is
         reported and left in English rather than moved.

That last point is why `rebuild` reports instead of silently shortening: the
alternative -- relocating records -- would need the TOPIC table's script file.
"""

import struct
from dataclasses import dataclass, field
from pathlib import Path

from . import briefing as B
from . import config
from . import slots
from .crypto import buffer_xor_decrypt, name_hash

STEM = "0076531d"
SECTOR = B.SECTOR


def key() -> int:
    """The container key.  name_hash stops at the first '.', so a *.orig
    backup keys identically."""
    return name_hash(STEM)


def source_path() -> Path:
    return config.pristine(config.BRIEFING_DAT)


def crypt(raw: bytes) -> bytearray:
    """Decrypt or encrypt: every 4096-byte sector is seeded afresh, so each
    one gets the same keystream (`briefing.decrypt_sectors`, _probe_bri8.py).
    XOR is its own inverse, hence one function for both directions."""
    out = bytearray(raw)
    for off in range(0, len(out), SECTOR):
        blk = bytearray(out[off:off + SECTOR])
        buffer_xor_decrypt(blk, key())
        out[off:off + len(blk)] = blk
    return out


decrypt = encrypt = crypt


@dataclass
class Pool:
    """The writable window of one record: [table, pool_end)."""
    table: int          # absolute offset of the u32 offset table
    pool: int           # absolute offset of the string pool
    budget: int         # pool bytes, == off3 - off2
    n: int              # number of strings

    @property
    def end(self) -> int:
        return self.pool + self.budget


def pool_of(rec: B.Record) -> Pool:
    v10 = rec.v10
    return Pool(v10 + rec.off1, v10 + rec.off2, rec.off3 - rec.off2,
                len(rec.lines))


def needed(lines) -> int:
    """Pool bytes `lines` would occupy, NUL terminators included."""
    return sum(len(s.encode("utf-8")) + 1 for s in lines)


def display_lines(lines, n_text: int) -> list:
    """Blank out the non-dialogue tail (`lines[n_text:]`) before any budget
    or rewrite math.

    `n_text` comes from the parser, not from a guess: the pool is laid out
    back-to-back, so real entries satisfy ``table[i+1] == table[i] + len + 1``
    and the last one stays inside off3.  Entries past the first violation point
    into the binary blob behind the text -- the strings read there have no NUL
    anywhere near and their lengths are fiction (ANALYSIS/03 §10.6,
    `_probe_bri58.py`).  They never enter the corpus, so they rewrite as empty
    strings: the table keeps all its entries, they just all point at one NUL.

    2026-09-25 复核（`_probe_bri57.py`）：想改成「原样保留字节」是不行的 ——
    79 条带伪影行且有译文的记录里，72 条会撑爆池（伪影行原始长度 2~15 KB，
    比整条记录的预算还大一个量级），长度确实是虚构的。所以清空保留，但
    不再静默：`Stats.blanked` 会计数。
    """
    return [t if i < n_text else "" for i, t in enumerate(lines)]


def rewrite(data, rec: B.Record, lines) -> tuple:
    """Re-lay `lines` into `rec`'s pool -> (bytes, need), or (None, need).

    Bytes past the new end are copied verbatim: [E3] shows the shipped pools
    carry tail garbage there (1537 of 2049 records have non-zero bytes after
    the last string), and keeping it is what makes an untranslated rewrite
    byte-identical.  Nothing reads it -- strings are taken by offset + NUL --
    and a pool that grows simply overwrites part of it.
    """
    p = pool_of(rec)
    need = needed(lines)
    if need > p.budget:
        return None, need
    body = bytearray()
    tbl = bytearray()
    for s in lines:
        tbl += len(body).to_bytes(4, "little")
        body += s.encode("utf-8") + b"\x00"
    tail = bytes(data[p.pool + need:p.end])
    return bytes(tbl) + bytes(body) + tail, need


# ------------------------------------------------------------------ whole file

def by_record(translations: dict) -> dict:
    """{ref or (group, off, line): text} -> {(group, off): {line: text}}."""
    out = {}
    for ref, text in translations.items():
        if isinstance(ref, str):
            parsed = slots.parse_ref(ref)
            if parsed.kind != slots.CODEC:
                continue
            g, off, line = parsed.group, parsed.off, parsed.line
        else:
            g, off, line = ref
        out.setdefault((g, off), {})[line] = text
    return out


@dataclass
class Stats:
    records: int = 0            # records in the container
    targeted: int = 0           # records we were asked to write
    rewritten: int = 0          # records actually rewritten
    strings: int = 0            # strings written
    bytes_free: int = 0         # budget - needed, over the rewritten records
    blanked: int = 0            # artifact lines cleared by display_lines
    overflow: list = field(default_factory=list)     # (group, off, need, budget)
    missing: list = field(default_factory=list)      # refs with no record

    def __str__(self) -> str:
        extra = (f", {self.blanked} artifact line(s) blanked"
                 if self.blanked else "")
        return (f"{self.rewritten}/{self.targeted} record(s) rewritten, "
                f"{self.strings} string(s), {self.bytes_free} pool byte(s) "
                f"left over" + extra)


def rebuild(translations: dict, lang: int = None, outdir: Path = None,
            verbose: bool = True) -> tuple:
    """Write `translations` into a fresh 0076531d.DAT under `outdir`.

    Returns (path, stats).  `stats.overflow` lists the records that did not
    fit; they are left in English, never relocated.
    """
    lang = config.LANG_EN if lang is None else lang
    if lang != config.LANG_EN:
        raise SystemExit(
            f"CODEC write-back only targets the English block: a reference "
            f"names the English record it was exported from, and the "
            f"{config.LANG_KEYS[lang]} copy of that line lives in a record "
            f"whose offset the corpus does not carry")
    outdir = Path(outdir or config.BUILD_DIR)
    outdir.mkdir(parents=True, exist_ok=True)

    want = by_record(translations)
    src = source_path()
    data = crypt(src.read_bytes())
    recs = {r.off: r for r in B.iter_records(bytes(data))}
    st = Stats(records=len(recs), targeted=len(want))

    for (group, off), by_line in sorted(want.items()):
        rec = recs.get(off)
        if rec is None:
            st.missing.append((group, off))
            continue
        lines = list(rec.lines)
        for line, text in by_line.items():
            if not (0 <= line < len(lines)):
                st.missing.append((group, off, line))
                continue
            lines[line] = text
        st.blanked += sum(1 for i in range(rec.n_text, len(lines))
                          if i not in by_line)
        blob, need = rewrite(data, rec, display_lines(lines, rec.n_text))
        if blob is None:
            st.overflow.append((group, off, need, pool_of(rec).budget))
            continue
        p = pool_of(rec)
        data[p.table:p.end] = blob
        st.rewritten += 1
        st.strings += len(by_line)
        st.bytes_free += p.budget - need

    out = outdir / f"{STEM}.DAT"
    out.write_bytes(bytes(crypt(bytes(data))))
    if verbose:
        print(f"  {out.name}  {st}  ({len(out.read_bytes())} bytes, "
              f"original {src.stat().st_size})")
        if st.overflow:
            print(f"  {len(st.overflow)} record(s) did not fit and were left "
                  f"in English; the first ones:")
            for g, off, need, budget in st.overflow[:5]:
                print(f"    codec/{g}/{off >> 12}/{off:#x}: needs {need} "
                      f"bytes, the pool holds {budget}")
    return out, st


def verify(path: Path, translations: dict, lang: int = None) -> list:
    """Read the rebuilt container back.  Returns a list of problems.

    Three things are checked, in the order they can fail:

    1. every translated line reads back as the translation;
    2. every other line still reads back as the original English;
    3. outside the pools that were rewritten, the file is byte-identical to
       the original -- the record headers, the bytecode, the alignment padding
       and every untouched record.
    """
    lang = config.LANG_EN if lang is None else lang
    want = by_record(translations)
    problems = []
    src = source_path()
    orig = crypt(src.read_bytes())
    new = crypt(Path(path).read_bytes())
    if len(new) != len(orig):
        problems.append(f"size {len(new)} != original {len(orig)}")

    old_recs = {r.off: r for r in B.iter_records(bytes(orig))}
    new_recs = B.iter_records(bytes(new))
    if len(new_recs) != len(old_recs):
        problems.append(f"{len(new_recs)} records, original has "
                        f"{len(old_recs)}")
    new_recs = {r.off: r for r in new_recs}

    for (group, off), by_line in sorted(want.items()):
        old = old_recs.get(off)
        rec = new_recs.get(off)
        if rec is None:
            problems.append(f"codec/{group}/{off:#x}: record vanished")
            continue
        if old is None:
            continue
        for line, text in by_line.items():
            if line >= len(rec.lines):
                problems.append(f"codec/{group}/{off:#x}/{line}: no such line")
                continue
            if rec.lines[line] != text:
                problems.append(f"codec/{group}/{off:#x}/{line}: "
                                f"{rec.lines[line]!r} != {text!r}")
        # every line we were not asked to write must be untouched --
        # the non-dialogue tail (lines[n_text:]) is blanked by display_lines on
        # both sides, so blanking it in the rebuild is not a change
        expected = display_lines(old.lines, old.n_text)
        for i, (a, b) in enumerate(zip(expected, rec.lines)):
            if i in by_line:
                continue
            if a != b:
                problems.append(f"codec/{group}/{off:#x}/{i}: untranslated "
                                f"line changed: {a!r} -> {b!r}")

    # 3. byte comparison outside the rewritten windows
    spans = sorted((pool_of(old_recs[off]).table, pool_of(old_recs[off]).end)
                   for (_g, off) in want if off in old_recs)
    pos = 0
    limit = min(len(orig), len(new))
    for lo, hi in spans:
        if lo > limit or pos > limit:
            break
        if lo > pos and orig[pos:lo] != new[pos:lo]:
            i = next(i for i in range(pos, lo) if orig[i] != new[i])
            problems.append(f"byte {i:#x} changed outside a rewritten pool "
                            f"({orig[i]:#04x} -> {new[i]:#04x})")
        pos = max(pos, hi)
    if pos < limit and orig[pos:limit] != new[pos:limit]:
        i = next(i for i in range(pos, limit) if orig[i] != new[i])
        problems.append(f"byte {i:#x} changed outside a rewritten pool "
                        f"({orig[i]:#04x} -> {new[i]:#04x})")
    return problems


def overflows(translations: dict) -> list:
    """[(group, off, need, budget)] for records whose pool cannot hold the
    translations they were given.

    `po_lint` runs this so an over-long line is reported at lint time, with
    the .po entry still on screen, instead of halfway through a build.
    """
    data = crypt(source_path().read_bytes())
    recs = {r.off: r for r in B.iter_records(bytes(data))}
    out = []
    for (group, off), by_line in sorted(by_record(translations).items()):
        rec = recs.get(off)
        if rec is None:
            continue
        lines = list(rec.lines)
        for line, text in by_line.items():
            if 0 <= line < len(lines):
                lines[line] = text
        need = needed(display_lines(lines, rec.n_text))
        budget = pool_of(rec).budget
        if need > budget:
            out.append((group, off, need, budget))
    return out


def budgets(translations: dict = None) -> dict:
    """{(group, off): (budget, needed)} for the records `translations` touch.

    `po_lint` uses this to reject a translation that will not fit before the
    build ever runs; with no argument it returns every record.
    """
    data = crypt(source_path().read_bytes())
    out = {}
    for r in B.iter_records(bytes(data)):
        out[(r.group, r.off)] = (pool_of(r).budget, needed(r.lines))
    if translations is None:
        return out
    want = by_record(translations)
    touched = {}
    for key_ in want:
        if key_ in out:
            touched[key_] = out[key_]
    return touched


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--outdir", type=Path, default=config.BUILD_DIR)
    ap.add_argument("--stats", action="store_true",
                    help="only report the pool budget of every record")
    a = ap.parse_args()
    config.require_game()

    if a.stats:
        bs = budgets()
        total = sum(v[0] for v in bs.values())
        used = sum(v[1] for v in bs.values())
        print(f"{len(bs)} records, {total} pool bytes, {used} in use "
              f"({total - used} free)")
        return
    print("no translations given on the command line; use "
          "python -m pwsf.po_import")


if __name__ == "__main__":
    main()

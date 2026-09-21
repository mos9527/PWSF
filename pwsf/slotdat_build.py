"""Write translations back into SLOT.DAT -- the inverse of `pwsf.slotdat`.

Why a whole rebuild instead of patching in place
-----------------------------------------------
A resource entry is `(id, _, offset, _)` with **no length**: a pool runs up to
the next pool's offset, so its size is a property of the layout, not a field.
The embedded pools are packed to ~99% of their slot, so a CJK translation does
not fit (ANALYSIS/08 §8.1, `_probe_slot27/28.py`: 14 of 43 tables fit).

The inflated slot is not a fixed image though -- the offsets are plain u32s --
so the way out is to lay the pools out again and rewrite every offset, then
re-compress and re-emit the container.  Measured on a Japanese-into-English
rewrite the whole thing comes out *smaller* (A +4 / B -9 sectors, 36 KB under
the original), because repacking drops the padding between pools
(`_probe_slot29.py`).

What has to hold
----------------
    inflated  <= A * 4096     A is 12 bits in SLOT.KEY (it truncates above
                              4095 -- records 1764/1847 in the shipped file)
    compressed <= B * 4096 - 16

Since B changes, every later record moves, so SLOT.KEY's start/end are
rewritten too and the whole 544 MB is re-emitted.  Records that carry none of
the translated tables are copied cipher-text byte for byte: the two XOR layers
are a function of the offset *within* a block, so moving a block does not
change its cipher text.

The `extra` block (sectors `end - start - B`, a second independent zlib stream
that slotdat_load_and_verify inflates separately) is never touched; it is moved
as cipher text.

Layout evidence: slotdat_load_and_verify @ 0x1400A6290,
slotdat_find_res_entry @ 0x1400A61F0, io_cmd_dispatch @ 0x14045D600 case 0x10.
"""

import struct
import zlib
from pathlib import Path

from . import config
from . import olang
from . import slotdat as S
from . import slots
from .crypto import buffer_xor_decrypt, name_hash

SECTOR = S.SECTOR
KEY_HDR, KEY_REC = S.KEY_HDR, S.KEY_REC
MASK20 = S.MASK20


# ----------------------------------------------------------------- slot level

def repack_slot(data: bytes, patch) -> bytes:
    """Lay the pools out again, compactly, and rewrite every entry offset.

    `patch(blob) -> blob` is applied to each pool; it may return the input
    unchanged.  Pools are emitted back to back (no padding) in their existing
    order, and each entry's `+0x08` offset field is updated to match.
    Sentinel entries get the end of the data area, which is what the shipped
    file does too.
    """
    count, entries, area = S.res_table(data)
    pools = S.slot_pools(data)
    if not pools:
        return data

    blobs = [patch(blob, eid) for _i, eid, _o, blob in pools]

    body = bytearray()
    offsets = {}
    for (idx, _eid, _o, _old), blob in zip(pools, blobs):
        offsets[idx] = len(body)
        body += blob
        while len(body) % 4:            # the XOR layers work in dwords
            body.append(0)
    end = len(body)

    table = bytearray(data[:area])
    for i in range(count):
        struct.pack_into("<I", table, 8 + 16 * i + 8, offsets.get(i, end))
    return bytes(table) + bytes(body)


def make_patch(by_table: dict, lang: int, gtt_by_pool: dict = None):
    """patch(blob, pool_id) writing the olang and GTT translations.

    Two pool types live in a slot: RBX (olang tables, rebuilt through
    `olang_build`) and GTT (ANALYSIS/11, patched in place by `pwsf.gtt`
    because the string pool is suffix-merged and only the primary language's
    runs are known).
    """
    from . import gtt

    counter = [0]
    problems = []

    def patch(blob: bytes, eid: int = 0) -> bytes:
        if gtt_by_pool and len(blob) >= 0x20 and blob[:4] == b"GTT\x00":
            texts = gtt_by_pool.get(eid)
            if not texts:
                return blob
            raw = {k: gtt.to_game_text(v) for k, v in texts.items()}
            out = gtt.patch(blob, raw, problems)
            counter[0] += len(raw) - len(problems)
            return out
        if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
            return blob
        tid = struct.unpack_from("<I", blob, 4)[0]
        texts = by_table.get(tid)
        if not texts:
            return blob
        tbl = olang.parse(blob, "")
        if lang not in {k[0] for k in tbl.keys}:
            return blob
        from .olang_build import OlangBuilder
        b = OlangBuilder(tbl)
        for (gk, ek), text in texts.items():
            try:
                b.set_text(gk, ek, lang, text)
            except KeyError:
                continue
            counter[0] += 1
        return b.serialize()

    patch.written = counter
    patch.gtt_problems = problems
    return patch


def touches(data: bytes, by_table: dict, lang: int,
            gtt_by_pool: dict = None) -> bool:
    """Does this slot hold one of the tables (or GTT pools) we translate?"""
    for _i, eid, _o, blob in S.slot_pools(data):
        if gtt_by_pool and len(blob) >= 0x20 and blob[:4] == b"GTT\x00" \
                and eid in gtt_by_pool:
            return True
        if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
            continue
        if struct.unpack_from("<I", blob, 4)[0] not in by_table:
            continue
        if lang in {k[0] for k in olang.parse(blob, "").keys}:
            return True
    return False


# --------------------------------------------------------------- whole file

def _norm_translations(translations: dict) -> dict:
    """{ref or (table, group, entry): text} -> {table_id: {(g, e): text}}."""
    by_table = {}
    for key, text in translations.items():
        if isinstance(key, str):
            r = slots.parse_ref(key)
            if r.kind != slots.SLOT:
                continue
            tid, gk, ek = r.table, r.group, r.entry
        else:
            tid, gk, ek = key
        by_table.setdefault(tid, {})[(gk, ek)] = text
    return by_table


def rebuild(translations: dict, lang: int = None, outdir: Path = None,
            level: int = 9, verbose: bool = True, gtt: dict = None) -> tuple:
    """Write `translations` into a fresh SLOT.DAT / SLOT.KEY under `outdir`.

    `gtt` is `{(pool_id, block_off, line): text}` -- the GTT corpus,
    ANALYSIS/11.  Returns (dat_path, key_path, stats).
    """
    lang = config.LANG_EN if lang is None else lang
    gtt_by_pool = {}
    for (pool, block, line), text in (gtt or {}).items():
        gtt_by_pool.setdefault(pool, {})[(block, line)] = text
    outdir = Path(outdir or config.BUILD_DIR)
    outdir.mkdir(parents=True, exist_ok=True)

    by_table = _norm_translations(translations)
    recs = S.load_index()
    state, inc = S.lcg_params()
    # 2x the biggest record: a repacked, re-compressed block may outgrow the
    # original, and the folded stream is generated once for the whole file
    nd = max(r.stored for r in recs) * SECTOR // 4 * 2 + 4096
    ks = S.keystream(nd, state, inc)
    patch = make_patch(by_table, lang, gtt_by_pool)
    used = [patch]          # + one entry per record that fell back

    src_dat, src_key = S.dat_path(), S.key_path()
    # name the outputs after STEM, not after src_dat.name: the source goes
    # through config.pristine, so once a .orig backup exists the build would
    # be written to BUILD/002aba34.DAT.orig and the manifest would carry that
    # name with it (seen 2026-09-20)
    out_dat, out_key = outdir / f"{S.STEM}.DAT", outdir / f"{S.STEM}.KEY"

    new_records = []
    stats = dict(records=len(recs), patched=0, strings=0, gtt_dropped=[],
                 gtt_dropped_pools=set(), gtt_partial=[], gtt_written=set())
    with open(src_dat, "rb") as fin, open(out_dat, "wb") as fout:
        lead = recs[0].start            # sector 0 is not part of any record
        if lead:
            fout.write(fin.read(lead * SECTOR))
        sector = lead

        for rec in recs:
            fin.seek(rec.start * SECTOR)
            main = fin.read(rec.stored * SECTOR)
            extra_n = rec.end - rec.start - rec.stored
            extra = fin.read(extra_n * SECTOR) if extra_n > 0 else b""
            if len(extra) != extra_n * SECTOR:
                raise SystemExit(f"record {rec.index}: short read of the "
                                 f"extra block ({len(extra)} of "
                                 f"{extra_n * SECTOR})")

            plain = S.decrypt(main, ks)
            data = S.inflate(plain)
            if touches(data, by_table, lang, gtt_by_pool):
                magic, hdr_size, const, _c, _r = S.parse_header(plain)
                need = rec.stored * SECTOR
                # Two ways a repacked block can fail to fit its slot:
                #   1. the compressor -- Chinese does not pack as well as the
                #      English it replaced, so try a few zlib strategies and
                #      keep the smallest (record 186 needed 169 B, 2026-09-21);
                #   2. still too big -- drop this record's GTT lines and keep
                #      the olang ones: a record's byte budget is a constant, and
                #      one record must never fail the whole container.
                eids_here = [eid for _i, eid, _o, blob in S.slot_pools(data)
                             if len(blob) >= 0x20 and blob[:4] == b"GTT\x00"]
                block = None
                data2 = repack_slot(data, patch)
                if data2 == data:                # 这一条没有要写的
                    block = main
                else:
                    comp = _compress(data2, level)
                    cand = struct.pack("<HHIII", magic, hdr_size, const,
                                       len(comp), len(data2)) + comp
                    if len(cand) <= need:
                        data, block = data2, cand
                        for eid in eids_here:
                            for k in gtt_by_pool.get(eid, ()):
                                stats["gtt_written"].add((eid, k))
                if block is None and gtt_by_pool:
                    # 整条降级太浪费：按译文长度从大到小丢、二分找临界，
                    # 只把装不下的那几条留英文
                    keys = [(eid, k, len(gtt_by_pool[eid][k]))
                            for _i, eid, _o, blob in S.slot_pools(data)
                            if len(blob) >= 0x20 and blob[:4] == b"GTT\x00"
                            and eid in gtt_by_pool
                            for k in gtt_by_pool[eid]]
                    keys.sort(key=lambda x: -x[2])
                    lo, hi = 0, len(keys) - 1
                    while lo <= hi:
                        mid = (lo + hi) // 2
                        sub = _without(gtt_by_pool, keys[mid:])
                        p = make_patch(by_table, lang, sub)
                        data2 = repack_slot(data, p)
                        comp = _compress(data2, level)
                        cand = struct.pack("<HHIII", magic, hdr_size, const,
                                           len(comp), len(data2)) + comp
                        if len(cand) <= need:     # 留得越多越难装下 -> 取最大可行
                            # NB: 只换本记录用的补丁，`patch` 是循环外变量 ——
                            # 早先这里直接赋值，导致后面 2,000 条记录全用了这个
                            # 少了几百行的残缺补丁（2026-09-21）
                            block, data = cand, data2
                            used.append(p)
                            lo = mid + 1
                        else:
                            hi = mid - 1
                    if block is not None:
                        kept = lo - 1               # keys[:kept] 写进去了
                        for eid, k, _n in keys[:kept]:
                            stats["gtt_written"].add((eid, k))
                        if kept == 0:
                            stats["gtt_dropped"].append(rec.index)
                            for _i, eid, _o, blob in S.slot_pools(data):
                                if len(blob) >= 0x20 and blob[:4] == b"GTT\x00":
                                    stats["gtt_dropped_pools"].add(eid)
                        else:
                            stats["gtt_partial"].append(
                                (rec.index, len(keys) - kept))
                if block is None:
                    raise SystemExit(
                        f"record {rec.index}: repacked block does not fit the "
                        f"slot ({need} bytes) even with the GTT lines left in "
                        f"English -- translate less of this record, or lower "
                        f"--level")
                # Pad back to the record's ORIGINAL sector count. zlib level 9
                # routinely beats the shipped compressor, so a repacked block
                # comes out shorter -- and every following record is addressed
                # by absolute sector, so one shorter block drags all 2,136
                # later records forward and the file shrinks (132,948 ->
                # 132,933 sectors on 2026-09-20). Loading a save then hangs on
                # a black screen. The slot size is a constant: pad, never move.
                if len(block) < need:
                    block += b"\x00" * (need - len(block))
                    block = _xor(block, ks)
                inflated = len(data)
                stats["patched"] += 1
            else:
                block = main
                inflated = max(len(data), 0)

            new_b = len(block) // SECTOR
            new_a = max(rec.a_copy, -(-inflated // SECTOR))
            fout.write(block)
            if extra:
                fout.write(extra)
            new_records.append((sector, sector + new_b + extra_n,
                                new_a, new_b, rec.id_hash))
            sector += new_b + extra_n

    stats["strings"] = sum(p.written[0] for p in used)
    stats["sectors"] = sector
    stats["gtt_problems"] = [x for p in used for x in p.gtt_problems]
    if stats["gtt_problems"] and verbose:
        print(f"  {len(patch.gtt_problems)} GTT line(s) did not fit and stay "
              f"English (budget is the English run's length, ANALYSIS/11 §5)")
        for p in patch.gtt_problems[:5]:
            print(f"      {p}")
    if stats["gtt_partial"] and verbose:
        lost = sum(n for _, n in stats["gtt_partial"])
        print(f"  {len(stats['gtt_partial'])} record(s) could not hold every "
              f"GTT line after repacking: {lost} line(s) left English")
    if stats["gtt_dropped"] and verbose:
        print(f"  {len(stats['gtt_dropped'])} record(s) could not hold any GTT "
              f"line after repacking: those stay English")

    _write_key(new_records, src_key, out_key)
    if verbose:
        print(f"  {out_dat.name}  {stats['patched']}/{stats['records']} "
              f"records repacked, {stats['strings']} string(s) written, "
              f"{sector * SECTOR} bytes")
        print(f"  {out_key.name}  {len(new_records)} records")
    return out_dat, out_key, stats


def _without(gtt_by_pool: dict, drop: list) -> dict:
    """`gtt_by_pool` minus the `[(pool, (block, line), _len)]` entries listed."""
    out = {p: dict(m) for p, m in gtt_by_pool.items()}
    for pool, key, _n in drop:
        if pool in out:
            out[pool].pop(key, None)
    return {p: m for p, m in out.items() if m}


def _compress(data: bytes, level: int) -> bytes:
    """Smallest zlib stream over a few strategies.

    A repacked block has to fit the record's ORIGINAL byte budget, and Chinese
    does not pack as well as the English it replaced: record 186 came out 169 B
    over with the default level-9 stream (2026-09-21).  Trying the other
    strategies costs one extra pass and can win exactly that margin.
    """
    best = zlib.compress(data, level)
    for strat in (zlib.Z_FILTERED, zlib.Z_FIXED, zlib.Z_RLE,
                  zlib.Z_HUFFMAN_ONLY):
        c = zlib.compressobj(level, zlib.DEFLATED, 15, 9, strat)
        out = c.compress(data) + c.flush()
        if len(out) < len(best):
            best = out
    return best


def _xor(block: bytes, ks: bytes) -> bytes:
    """Apply both XOR layers.  They commute, so one folded stream does it."""
    n = len(block) & ~3
    if n > len(ks):
        raise SystemExit(f"keystream too short: need {n} bytes, have "
                         f"{len(ks)} (a record grew past the pre-generated "
                         f"stream; raise the headroom in rebuild())")
    merged = int.from_bytes(block[:n], "little") ^ \
        int.from_bytes(ks[:n], "little")
    return merged.to_bytes(n, "little") + block[n:]


def _write_key(records: list, src_key: Path, out_key: Path) -> None:
    """Re-emit SLOT.KEY with new start / end / A / B.

    The 12-byte header is left alone: it is the seed material for the LCG layer
    (ANALYSIS/08 §5.5), so re-deriving it must stay possible.
    """
    buf = bytearray(src_key.read_bytes())
    buffer_xor_decrypt(buf, name_hash("002aba34"))
    for i, (start, end, a, b, h) in enumerate(records):
        struct.pack_into("<IIIII", buf, KEY_HDR + KEY_REC * i,
                         (start & MASK20) | ((a & 0xFFF) << 20),
                         (end & MASK20) | ((b & 0xFFF) << 20),
                         h, a, b)
    buffer_xor_decrypt(buf, name_hash("002aba34"))
    out_key.write_bytes(bytes(buf))


# ------------------------------------------------------------------ verify

def verify(dat_path: Path, key_path: Path, translations: dict,
           lang: int = None, gtt: dict = None, dropped: set = None,
           written: set = None) -> list:
    """Read the rebuilt container back.  Returns a list of problems.

    `written` is `stats["gtt_written"]`: the GTT lines the rebuild actually
    managed to write.  A record whose block cannot be compressed into its slot
    drops some of them (longest first), so only what was written is checked --
    otherwise a known limitation would look like a broken build.
    """
    from . import gtt as G

    lang = config.LANG_EN if lang is None else lang
    by_table = _norm_translations(translations)
    dropped = dropped or set()
    gtt_by_pool = {}
    for (pool, block, line), text in (gtt or {}).items():
        if written is not None and (pool, (block, line)) not in written:
            continue
        if pool in dropped:
            continue
        gtt_by_pool.setdefault(pool, {})[(block, line)] = text
    # pools in `dropped` never entered gtt_by_pool, so they are not checked
    problems = []
    found = {}          # (pool, (block, line)) -> seen with the translation

    recs = S.load_index(key_path)
    state, inc = S.lcg_params(key_path)
    nd = max(r.stored for r in recs) * SECTOR // 4 + 16
    ks = S.keystream(nd, state, inc)
    if max(len(ks), 0) < max((r.stored for r in recs), default=0) * SECTOR:
        return ["keystream shorter than the largest record"]

    for rec in recs:
        try:
            plain = S.decrypt(S.read_block(rec, dat_path), ks)
            data = S.inflate(plain)
        except Exception as exc:                           # noqa: BLE001
            problems.append(f"record {rec.index}: {exc}")
            continue
        _magic, hdr_size, _const, comp, raw = S.parse_header(plain)
        if hdr_size != S.REC_HDR:
            problems.append(f"record {rec.index}: hdr {hdr_size}")
        if raw != len(data):
            problems.append(f"record {rec.index}: inflated {len(data)} "
                            f"!= header raw {raw}")
        if len(data) > rec.a_copy * SECTOR:
            problems.append(f"record {rec.index}: inflated {len(data)} "
                            f"exceeds A {rec.a_copy} sectors")
        for _i, eid, _o, blob in S.slot_pools(data):
            if len(blob) >= 0x20 and blob[:4] == b"GTT\x00":
                texts = gtt_by_pool.get(eid)
                if texts:
                    # a record that could not hold every line drops some, so a
                    # line counts as written when ANY copy of the pool has it
                    # (the pool repeats in several records, like the olang ones)
                    for (boff, li), text in texts.items():
                        ok = any(b.off == boff and b.line(li) ==
                                 G.to_game_text(text)
                                 for b in G.parse(blob))
                        if ok:
                            found[(eid, (boff, li))] = True
                continue
            if len(blob) < 0x20 or blob[:4] != b"RBX\x00":
                continue
            tid = struct.unpack_from("<I", blob, 4)[0]
            want = by_table.get(tid)
            if not want:
                continue
            tbl = olang.parse(blob, "")
            if lang not in {k[0] for k in tbl.keys}:
                continue
            from .olang_build import OlangBuilder
            rb = OlangBuilder(tbl)
            for (gk, ek), text in want.items():
                try:
                    got = rb.get_text(gk, ek, lang)
                except KeyError:
                    problems.append(f"table {tid:#010x}: "
                                    f"{gk:#08x}/{ek:#08x} vanished")
                    continue
                if got != text:
                    problems.append(
                        f"table {tid:#010x} {gk:#08x}/{ek:#08x}: "
                        f"{got!r} != {text!r}")

    for pool, mapping in gtt_by_pool.items():
        for (boff, li), text in mapping.items():
            if found.get((pool, (boff, li))):
                continue
            problems.append(f"gtt {pool:#010x} block @{boff:#x} line {li}: "
                            f"not found with the translation "
                            f"({text[:30]!r})")
    return problems

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

    blobs = [patch(blob) for _i, _eid, _o, blob in pools]

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


def make_patch(by_table: dict, lang: int):
    """patch(blob) that writes `by_table[table_id]` into the `lang` strings."""
    counter = [0]

    def patch(blob: bytes) -> bytes:
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
    return patch


def touches(data: bytes, by_table: dict, lang: int) -> bool:
    """Does this slot hold one of the tables we are translating?"""
    for _i, _eid, _o, blob in S.slot_pools(data):
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
            level: int = 9, verbose: bool = True) -> tuple:
    """Write `translations` into a fresh SLOT.DAT / SLOT.KEY under `outdir`.

    Returns (dat_path, key_path, stats).
    """
    lang = config.LANG_EN if lang is None else lang
    outdir = Path(outdir or config.BUILD_DIR)
    outdir.mkdir(parents=True, exist_ok=True)

    by_table = _norm_translations(translations)
    recs = S.load_index()
    state, inc = S.lcg_params()
    # 2x the biggest record: a repacked, re-compressed block may outgrow the
    # original, and the folded stream is generated once for the whole file
    nd = max(r.stored for r in recs) * SECTOR // 4 * 2 + 4096
    ks = S.keystream(nd, state, inc)
    patch = make_patch(by_table, lang)

    src_dat, src_key = S.dat_path(), S.key_path()
    # name the outputs after STEM, not after src_dat.name: the source goes
    # through config.pristine, so once a .orig backup exists the build would
    # be written to BUILD/002aba34.DAT.orig and the manifest would carry that
    # name with it (seen 2026-09-20)
    out_dat, out_key = outdir / f"{S.STEM}.DAT", outdir / f"{S.STEM}.KEY"

    new_records = []
    stats = dict(records=len(recs), patched=0, strings=0)
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
            if touches(data, by_table, lang):
                magic, hdr_size, const, _c, _r = S.parse_header(plain)
                data = repack_slot(data, patch)
                comp = zlib.compress(data, level)
                block = struct.pack("<HHIII", magic, hdr_size, const,
                                    len(comp), len(data)) + comp
                # Pad back to the record's ORIGINAL sector count. zlib level 9
                # routinely beats the shipped compressor, so a repacked block
                # comes out shorter -- and every following record is addressed
                # by absolute sector, so one shorter block drags all 2,136
                # later records forward and the file shrinks (132,948 ->
                # 132,933 sectors on 2026-09-20). Loading a save then hangs on
                # a black screen. The slot size is a constant: pad, never move.
                need = rec.stored * SECTOR
                if len(block) > need:
                    raise SystemExit(
                        f"record {rec.index}: repacked block needs "
                        f"{len(block)} bytes, the slot holds {need} "
                        f"(translate less of this record, or lower --level)")
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

    stats["strings"] = patch.written[0]
    stats["sectors"] = sector

    _write_key(new_records, src_key, out_key)
    if verbose:
        print(f"  {out_dat.name}  {stats['patched']}/{stats['records']} "
              f"records repacked, {stats['strings']} string(s) written, "
              f"{sector * SECTOR} bytes")
        print(f"  {out_key.name}  {len(new_records)} records")
    return out_dat, out_key, stats


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
           lang: int = None) -> list:
    """Read the rebuilt container back.  Returns a list of problems."""
    lang = config.LANG_EN if lang is None else lang
    by_table = _norm_translations(translations)
    problems = []

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
        for _i, _eid, _o, blob in S.slot_pools(data):
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
    return problems

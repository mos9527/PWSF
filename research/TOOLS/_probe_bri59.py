"""推翻 §1.1「逐扇区（4096）各自 seed」：密钥流按**记录**连续，从记录起点
所在扇区的扇区首开始（`ANALYSIS/03_codec.md` §11）。

起因：`_briefing_lines.tsv` 里 `0x387f00`（组 2/en）第 2 行
"...tough\\ntracking th" 之后全是乱码，n_text 被截成 2/18。断点正好是
0x388000 = 扇区 904 的起点；扇区 904 用密钥流第 1 段（偏移 4096）才解得开。

模型（R）：记录 r 占 [r.off, 下一条记录起点)，其中字节 x 用
    keystream[x - (r.off & ~0xFFF)]
解密（keystream = mt_seed(key) + advance(20)，与 buffer_xor_decrypt 一致）。
这正是 `briefing_dat_request_pages` 的行为：从 req 的扇区号开始读
4*页数 个扇区，**一次** buffer_xor_decrypt（§1.2 汇编）。

记录边界本身依赖解密结果（表在记录头之后），所以先用现行逐扇区模型扫出
记录起点，按 R 重解，再扫一遍、再重解，直到不动点。

    python research\\TOOLS\\_probe_bri59.py
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import briefing as B      # noqa: E402
from pwsf import config             # noqa: E402

S = B.SECTOR
NEEDLE_REC = 0x387F00
DATE_REC = 0x397F00                 # §10.1 那条 DATE 电台预览


def xor(a: bytes, b: bytes) -> bytes:
    n = len(a)
    return (int.from_bytes(a, "little") ^ int.from_bytes(b[:n], "little")
            ).to_bytes(n, "little")


def decrypt_by_record(raw: bytes, offs, ks: bytes) -> bytes:
    out = bytearray(len(raw))
    head = offs[0] if offs else len(raw)
    out[:head] = xor(raw[:head], ks)
    for i, o in enumerate(offs):
        base = o & ~(S - 1)
        e = offs[i + 1] if i + 1 < len(offs) else len(raw)
        out[o:e] = xor(raw[o:e], ks[o - base:e - base])
    return bytes(out)


def summ(recs, data):
    return {
        "记录": len(recs),
        "真台词行": sum(r.n_text for r in recs),
        "en 真台词": sum(r.n_text for r in recs if r.lang == "en"),
        "带伪影记录": sum(1 for r in recs if r.artifacts),
        "真区含FFFD行": sum(1 for r in recs for t in r.lines[:r.n_text]
                         if "\ufffd" in t),
        "relaxed-entry": sum(1 for r in recs if "relaxed-entry" in r.problems),
        "含语音ID": sum(1 for r in recs if r.voice_ids(data)),
        "含0x6d": sum(1 for r in recs if r.cues(data)),
        "语言判据冲突": sum(1 for r in recs if r.lang_conflict),
    }


def main() -> int:
    path = config.pristine(config.BRIEFING_DAT)
    raw = path.read_bytes()
    key = B.name_hash(path.stem)
    print(f"{path.name}  {len(raw):#x} B  key={key:#010x}")

    cur = bytes(B.decrypt_sectors(raw, key))
    old = B.iter_records(cur)

    # ---- [A] 针 ----
    r = next(x for x in old if x.off == NEEDLE_REC)
    pool = r.v10 + r.off2
    hit = cur.find(b"tracking th", pool) + 11
    ks3 = B._keystream(3 * S, key)
    print(f"\n[A] {NEEDLE_REC:#x}: 池 {pool:#x}..{r.v10 + r.off3:#x}  "
          f"n_text={r.n_text}/{len(r.lines)}")
    print(f"    'tracking th' 止于 {hit:#x}，扇区首 = {hit % S == 0}"
          f"（扇区 {hit // S}）")
    for k in range(3):
        print(f"    扇区 {hit // S} 用第 {k} 段密钥流: "
              f"{xor(raw[hit:hit + 40], ks3[k * S:])!r}")

    # ---- [B] 按记录重解，迭代到不动点 ----
    offs = [x.off for x in old]
    span = max((offs[i + 1] if i + 1 < len(offs) else len(raw)) - (o & ~(S - 1))
               for i, o in enumerate(offs))
    ks = B._keystream((span // S + 8) * S, key)
    for it in range(1, 6):
        fix = decrypt_by_record(raw, offs, ks)
        new = B.iter_records(fix)
        n_offs = [x.off for x in new]
        print(f"\n[B] 迭代 {it}: 记录 {len(new)}")
        if n_offs == offs:
            break
        offs = n_offs
    else:
        print("    未收敛")
        return 1

    a, b = summ(old, cur), summ(new, fix)
    print(f"\n    {'':<14}{'逐扇区(现行)':>14}{'按记录(R)':>12}")
    for k in a:
        print(f"    {k:<14}{a[k]:>14}{b[k]:>12}")
    o = {x.off: x for x in old}
    lost = sorted(set(o) - set(n_offs))
    gained = sorted(set(n_offs) - set(o))
    more = [x for x in new if x.off in o and x.n_text > o[x.off].n_text]
    print(f"    只在 R 下出现的记录 {len(gained)}，只在现行下出现的 {len(lost)}")
    print(f"    n_text 变多的记录 {len(more)}，合计 "
          f"+{sum(x.n_text - o[x.off].n_text for x in more)} 行")
    print(f"    组/语言记录数（R）: "
          f"{sorted(Counter((x.group, x.lang) for x in new).items())}")
    nn = {x.off: x for x in new}
    for off in gained[:4]:
        print(f"      新记录 {off:#08x} {nn[off].lang}: {nn[off].lines[0][:40]!r}")

    # 针与 DATE 记录
    nr = nn[NEEDLE_REC]
    print(f"    针 {NEEDLE_REC:#x}: n_text {r.n_text} -> {nr.n_text}/"
          f"{len(nr.lines)}，第 2 行 = {nr.lines[2]!r}")
    dr = nn[DATE_REC]
    print(f"    DATE {DATE_REC:#x}: problems={dr.problems} "
          f"voice={dr.voice_ids(fix)}")

    # 跨扇区分布（为什么逐扇区模型「大体能用」）
    spans, phase = Counter(), Counter()
    for i, x in enumerate(new):
        e = new[i + 1].off if i + 1 < len(new) else len(raw)
        s0, s1 = x.off // S, (e - 1) // S
        spans[s1 - s0 + 1] += 1
        for s in range(s0, s1 + 1):
            phase[s - s0] += min(e, (s + 1) * S) - max(x.off, s * S)
    print(f"    记录跨扇区数: {sorted(spans.items())}")
    print(f"    字节按段号 k: {sorted(phase.items())}"
          f"（k=0 即逐扇区模型碰巧正确的部分）")

    # ---- [C] §10「第二种记录格式」是不是同一个错误 ----
    rel = [x for x in old if "relaxed-entry" in x.problems]
    rel_x = sum(1 for x in rel if (x.v10 + x.off0) // S != x.off // S)
    print(f"\n[C] 现行 relaxed-entry {len(rel)} 条，其中脚本区首 dword(v11) "
          f"不在记录首扇区的: {rel_x}")
    print(f"    R 下 relaxed-entry: {b['relaxed-entry']}")

    # ---- [D] 现行写回的暴露面 ----
    cross = [x for x in new if (x.v10 + x.off3 - 1) // S != x.off // S]
    print(f"\n[D] 文本池伸进记录首扇区之后的记录: {len(cross)} "
          f"（en {sum(1 for x in cross if x.lang == 'en')}）"
          f" —— briefing_build 按逐扇区加密，这些池里越过扇区边界的改动字节"
          f"会被游戏用错误的密钥段解出")

    # ---- [E] 恒等 ----
    enc = decrypt_by_record(fix, n_offs, ks)
    print(f"\n[E] R 重新加密 == 磁盘原文件: {enc == raw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

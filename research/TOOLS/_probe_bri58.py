"""能不能用「几何判据」取代「像不像人话」：池内串紧凑排布不变量。

`po_export._codec_junk` / U+FFFD 判据都是启发式，本质上是在猜这串是不是台词。
真正可证的判据来自池的排布规则（`_probe_bri53.py` [E3]：把原 lines 重放回去
能逐字节还原原文件）—— 池里的串是 back-to-back 紧挨着的，所以真表项必然满足

    table[i+1] == table[i] + len(串 i) + 1          （NUL 结尾）

一旦某行跨过了下一个表项（或跨过池尾 off3），那一项就不可能是台词指针。
本探针逐条记录验证这个不变量，并跟 U+FFFD 判据对表：

    python research\\TOOLS\\_probe_bri58.py
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import briefing as B                # noqa: E402
from pwsf import briefing_build as BB         # noqa: E402

NUL_WINDOW = 8192      # 提取器 `parse_record` 用的同一个窗口


def raw_len(data: bytes, pool: int, off: int) -> int:
    start = pool + off
    e = data.find(b"\x00", start, min(len(data), start + NUL_WINDOW))
    return (len(data) - start) if e < 0 else e - start


def first_break(rec, data, p) -> int:
    """第一条破坏不变量的行号；-1 = 整条记录都成立。"""
    n = len(rec.lines)
    for i in range(n):
        rlen = raw_len(data, p.pool, rec.table[i])
        if i + 1 < n:
            # 紧挨着下一项：串必须正好填满到它
            if rlen + 1 != rec.table[i + 1] - rec.table[i]:
                return i
        else:
            # 最后一项：池尾有 tail garbage（[E3] 1537/2049 条），只要求不越界
            if rlen + 1 > p.budget - rec.table[i]:
                return i
    return -1


def main() -> int:
    data = BB.crypt(BB.source_path().read_bytes())
    recs = list(B.iter_records(bytes(data)))

    stat = Counter()
    mismatch = []
    for rec in recs:
        if not rec.lines:
            continue
        p = BB.pool_of(rec)
        fb = first_break(rec, data, p)
        n_fffd = sum(1 for t in rec.lines if "\ufffd" in t)
        first_fffd = next((i for i, t in enumerate(rec.lines) if "\ufffd" in t),
                          -1)
        if n_fffd == 0:
            stat["clean: invariant holds" if fb < 0
                 else "clean: invariant BROKEN"] += 1
            if fb >= 0:
                mismatch.append((rec.off, fb, first_fffd, len(rec.lines)))
        else:
            if fb < 0:
                stat["artifact: invariant holds (!)"] += 1
            elif fb == first_fffd:
                stat["artifact: break == first U+FFFD"] += 1
            else:
                stat["artifact: break != first U+FFFD"] += 1
                mismatch.append((rec.off, fb, first_fffd, len(rec.lines)))

    print(f"记录总数: {len(recs)}")
    for k in sorted(stat):
        print(f"  {k:<34}: {stat[k]}")

    bad = stat["clean: invariant BROKEN"] + stat["artifact: break != first U+FFFD"]
    print(f"\n两个判据不一致的记录: {bad}")
    print(f"{'记录':<12}{'破坏@':>8}{'首个FFFD@':>10}{'行数':>6}")
    for off, fb, ff, n in mismatch[:25]:
        print(f"{off:#010x}{fb:>8}{ff:>10}{n:>6}")
    if len(mismatch) > 25:
        print(f"  ... 其余 {len(mismatch) - 25} 条")

    # ---- U+FFFD 判据 vs 几何判据：误杀 / 漏网（只算 en 记录）----
    # （`_codec_junk` 那道启发式已随 §10.6 退役，不再对照）
    from pwsf import config
    rows = config.BRIEFING_TSV.read_text(encoding="utf-8").splitlines()
    col = {n: i for i, n in enumerate(rows[0].split("\t"))}
    en_offs = set()
    for r in rows[1:]:
        c = r.split("\t")
        if len(c) > col["lang"] and c[col["lang"]] == "en":
            en_offs.add(int(c[col["off"]], 16))
    print(f"en 记录偏移: {len(en_offs)}，容器记录: {len(recs)}")
    conf = Counter()
    samples = {"误杀:真区含 U+FFFD": [], "漏网:伪影区无 U+FFFD": []}
    for rec in recs:
        if not rec.lines or rec.off not in en_offs:
            continue
        p = BB.pool_of(rec)
        fb = first_break(rec, data, p)
        cut = len(rec.lines) if fb < 0 else fb
        for i, t in enumerate(rec.lines):
            real = i < cut
            fffd = "\ufffd" in t
            if real:
                if fffd:
                    # 几何判据说它是台词，U+FFFD 判据会把它丢掉（误杀）
                    conf["误杀:真区含 U+FFFD"] += 1
                    samples["误杀:真区含 U+FFFD"].append((rec.off, i, t))
                else:
                    conf["正确:真区进语料"] += 1
            else:
                if not fffd and t.strip():
                    # 几何判据说它不是台词，U+FFFD 判据会把它放进语料（漏网）
                    conf["漏网:伪影区无 U+FFFD"] += 1
                    samples["漏网:伪影区无 U+FFFD"].append((rec.off, i, t))
                else:
                    conf["正确:伪影区被拦下"] += 1

    print("\n== U+FFFD 判据 vs 几何判据 ==")
    for k in sorted(conf):
        print(f"  {k:<24}: {conf[k]}")
    for k, items in samples.items():
        if not items:
            continue
        print(f"\n-- {k} ({len(items)}) 前 5 条")
        for off, i, t in items[:5]:
            print(f"  {off:#010x}/{i}\n    {t.encode('unicode_escape').decode()[:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

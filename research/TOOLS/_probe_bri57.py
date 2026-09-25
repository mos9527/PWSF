"""display_lines 清空的代价：改成「原样保留字节」会不会撑爆池。

`briefing_build.display_lines` 把非台词表项（`lines[n_text:]`，03 号文档
§10.6）清成空串（§10.3 的假设：那些行游戏不显示）。实机出现空白对话框后，
这条假设要复核 —— 但直接去掉清空有代价：那些行的串跨过 off3、长度是虚构的，
原样保留可能装不下。

本探针按记录量一遍：

    need_blank     当前做法（伪影行清空）
    need_verbatim  伪影行保留原始字节（含到那个远处的 NUL）

    python research\\TOOLS\\_probe_bri57.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import briefing as B                # noqa: E402
from pwsf import briefing_build as BB         # noqa: E402
from pwsf import config                       # noqa: E402
from pwsf import po                           # noqa: E402
from pwsf import slots                        # noqa: E402


def raw_len(data: bytes, pool: int, off: int, limit: int = 8192) -> int:
    """串的原始字节长度：从 pool+off 到下一个 NUL（提取器用的同一窗口）。"""
    start = pool + off
    e = data.find(b"\x00", start, min(len(data), start + limit))
    return (len(data) - start) if e < 0 else e - start


def main() -> int:
    tr = {}
    for path, e in po.iter_entries(config.PO_DIR):
        if not e.msgstr:
            continue
        for r in e.refs:
            k = slots.parse_ref(r)
            if k.kind == slots.CODEC:
                tr[(k.group, k.off, k.line)] = e.msgstr
    want = BB.by_record(tr)

    data = BB.crypt(BB.source_path().read_bytes())
    recs = {r.off: r for r in B.iter_records(bytes(data))}

    worse = []
    art_recs = 0
    art_lines = 0
    for (group, off), by_line in sorted(want.items()):
        rec = recs.get(off)
        if rec is None:
            continue
        art = list(range(rec.n_text, len(rec.lines)))
        if not art:
            continue
        art_recs += 1
        art_lines += sum(1 for i in art if i not in by_line)
        p = BB.pool_of(rec)
        lines = list(rec.lines)
        for i, t in by_line.items():
            if 0 <= i < len(lines):
                lines[i] = t
        need_blank = BB.needed(BB.display_lines(lines, rec.n_text))
        need_verbatim = 0
        for i, t in enumerate(lines):
            if i in by_line:
                need_verbatim += len(t.encode("utf-8")) + 1
            else:
                need_verbatim += raw_len(data, p.pool, rec.table[i]) + 1
        if need_verbatim > p.budget >= need_blank:
            worse.append((group, off, need_blank, need_verbatim, p.budget,
                          len(art)))

    print(f"带伪影行、且有译文的记录      : {art_recs}")
    print(f"其中会被 display_lines 清空的行: {art_lines}")
    print(f"清空能装下、原样保留装不下的 : {len(worse)}")
    print(f"{'记录':<12}{'清空':>8}{'原样':>10}{'预算':>10}{'伪影行':>8}")
    for group, off, nb, nv, bud, n in worse[:30]:
        print(f"{off:#010x}{nb:>8}{nv:>10}{bud:>10}{n:>8}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

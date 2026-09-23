"""Probe: 被入口启发式误杀的第二种记录格式（2026-09-23，截图取证）

任务选择器里一条 DATE 任务的电台预览 "The Boss has infiltrated the area
around the coastal supply facility" 仍是英文，全语料（olang/codec/slot/
stage/gtt）都搜不到这句英文；`_briefing_lines.tsv` 里 `v_fop_kaz_0210` 这段
通话 ja/fr/de/it/es 五语俱全、唯独没有 en 行。

根因：`pwsf.briefing.parse_record` 沿用 _probe_bri18 的入口白名单
（op&0xF0==0 或 op∈{0x8D,0x8E}），把入口不合白名单的记录当假阳性剔除。
而 IDA `briefing_record_parse` @ 0x1400A3230 的反编译证明**真解析器对入口
不做任何检查**（只算指针 A->entry = v11 + u32@v11 + 8）。

  [A] 现场文件（装了汉化）按原始字节搜针 -> 命中 0x397f34（扇区 919，
      组 2/en），落在被拒记录 0x397f00 的池里 —— 修复前 lines=2。
  [E] 原版 .orig：0x397000..0x398200 逐 16 字节验头。0x397f00 表合法
      （5 项单调、tbl[0]=0）、池里正是 DATE 通话的 5 句英文，
      parse_record 因入口 op=0x15 拒绝。
  [G] 全文件：旧白名单口径下被拒但表校验通过的头共 621 个。首行干净度
      直方图（1 - U+FFFD 占比）：574 个首行 100% 可读（Paz 日记、ZEKE 命名、
      kaz0650 的 fr/it/es 缺本……），纯垃圾头首行即乱码 —— 这就是
      parse_record 新门槛（首行替换率 >= 0.2 剔除）的依据。
      尾部若干表项指进文本之后的二进制块（同一通话的 it/en 副本脚本区
      首 dword 逐字节相同，如 0x8a68fbf0 —— 「脚本按引用共享」的旁证），
      行数语义未定，故提取保持 cnt 行、垃圾行由 po_export 过滤 +
      briefing_build.display_lines 清空。

修复后：记录 2049 -> 2634，台词 24,438 -> 39,887；六语言块记录数首次齐平
（组1 ja/en/fr/de/it/es = 345/345/341/340/341/339，组2 = 104/99/95/96/95/94），
此前「en vs ja 独有 84、缺失 62」的失衡消失。

Usage:  python research/TOOLS/_probe_bri55.py
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from pwsf import briefing as B          # noqa: E402
from pwsf import config                 # noqa: E402

NEEDLES = [
    b"The Boss has",
    b"infiltrated",
    b"coastal",
    b"v_fop_kaz_0210",
]


def block_lang(off: int) -> str:
    try:
        g, lang = B.block_of(off)
        return f"group{g}/{lang}"
    except Exception:
        return "?"


def covering_record(br, off):
    cands = [r for r in br.records if r.off <= off < r.end]
    return cands[0] if cands else None


def section_a(br, data) -> None:
    """[A] 实装现场文件：绕过记录解析按原始字节搜针。"""
    print("=== [A] installed file, raw byte needles ===")
    for nd in NEEDLES:
        hits = []
        i = data.find(nd)
        while i != -1:
            hits.append(i)
            i = data.find(nd, i + 1)
        print(f"  {nd!r}: {len(hits)} hit(s)")
        for off in hits[:8]:
            rec = covering_record(br, off)
            tag = (f"rec off{rec.off:#x} lines={rec.n_lines} "
                   f"relaxed={'relaxed-entry' in rec.problems}") if rec \
                else "(no record covers)"
            print(f"    off {off:#010x} sector {off // B.SECTOR:5d} "
                  f"{block_lang(off):14s} {tag}")


def section_e(do: bytes) -> None:
    """[E] 原版：DATE 通话所在的 0x397f00 记录头与池。"""
    print("\n=== [E] original: header 0x397f00 (DATE conversation, en) ===")
    a1 = 0x397f00
    v10 = a1 + 12
    o0, o1, o2, o3 = struct.unpack_from("<IIII", do, v10)
    cnt = (o2 - o1) // 4
    p1, p2 = v10 + o1, v10 + o2
    tbl = [int.from_bytes(do[p1 + 4 * i:p1 + 4 * i + 4], "little")
           for i in range(cnt)]
    print(f"  off0={o0:#x} off1={o1:#x} off2={o2:#x} off3={o3:#x} cnt={cnt}")
    print(f"  table = {[hex(t) for t in tbl]}  "
          f"monotonic={all(tbl[i] < tbl[i + 1] for i in range(cnt - 1))}")
    v11 = v10 + o0
    print(f"  u32@v11 (entry rel) = {int.from_bytes(do[v11:v11 + 4], 'little'):#x}"
          f"  -> entry 指针越界（这就是被白名单拒绝的原因）")
    for i, v in enumerate(tbl):
        e = do.find(b"\x00", p2 + v, min(len(do), p2 + v + 8192))
        s = do[p2 + v:e] if e >= 0 else b"??"
        print(f"  [{i}] pool+{v:#06x} {s[:64]!r}")


def section_g(do: bytes) -> None:
    """[G] 全文件：被拒但表校验通过的头，按首行干净度分布。"""
    import collections
    print("\n=== [G] rejected-but-valid headers, line0 cleanliness ===")
    # 口径 = 旧入口白名单：只把「白名单内」的记录当作已认领，
    # 这样修复前的 615 个候选头在这里可以被复现
    claimed = {r.off for r in B.iter_records(do)
               if "relaxed-entry" not in r.problems}
    rows = []
    for a1 in range(0, len(do) - 28, 16):
        if do[a1:a1 + 4] != b"\x6f\x45\x62\x4e" or a1 in claimed:
            continue
        v10 = a1 + 12
        o0, o1, o2, o3 = struct.unpack_from("<IIII", do, v10)
        if not (0 < o1 < o2 < o3 < len(do)) or ((o2 - o1) & 3):
            continue
        cnt = (o2 - o1) // 4
        if cnt < 1 or cnt > 128:
            continue
        p1, p2 = v10 + o1, v10 + o2
        tbl = [int.from_bytes(do[p1 + 4 * i:p1 + 4 * i + 4], "little")
               for i in range(cnt)]
        if any(tbl[i] >= tbl[i + 1] for i in range(cnt - 1)) or tbl[0] != 0:
            continue
        e = do.find(b"\x00", p2 + tbl[0], min(len(do), p2 + tbl[0] + 8192))
        if e < 0:
            continue
        s = do[p2:e].decode("utf-8", "replace")
        rows.append((a1, 1 - s.count("\ufffd") / max(1, len(s)), s))
    print(f"  rejected-but-valid headers: {len(rows)}")
    hist = collections.Counter(round(cl, 1) for _, cl, _ in rows)
    print(f"  line0 clean histogram(0.1): {dict(sorted(hist.items()))}")
    print(f"  line0 100% clean: {sum(1 for _, cl, _ in rows if cl >= 1.0)}")
    for a1, cl, s in sorted(rows, key=lambda x: -x[1])[:6]:
        g, lang = B.block_of(a1)
        print(f"    {a1:#010x} group{g}/{lang:3s} clean={cl:.3f}  {s[:56]!r}")


def section_h(br) -> None:
    """[H] 修复后：记录数、行数、语言块齐平性。"""
    import collections
    print("\n=== [H] fixed parse: counts ===")
    print(f"  records={len(br.records)}  lines={sum(r.n_lines for r in br.records)}")
    per = collections.Counter((r.group, r.lang) for r in br.records)
    for (g, lang), n in sorted(per.items()):
        print(f"  group{g} {lang}: {n}")


def main() -> None:
    orig = config.pristine(config.BRIEFING_DAT)
    live = config.BRIEFING_DAT
    print(f"live     {live}")
    print(f"original {orig}")

    br_live = B.load(live)
    section_a(br_live, br_live.data)

    bo = B.load(orig)
    section_e(bo.data)
    section_g(bo.data)
    section_h(bo)


if __name__ == "__main__":
    main()

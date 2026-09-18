"""_probe_bri41.py —— 语言块边界的定位与验证

判据（_probe_bri40.py 已取得）：同一语音 ID（如 v_bri_amd0010_000_0）在
文件的 6 个位置重复出现，各自对应一种语言的同一段台词。因此：

  1. 以「记录 0 的语音 ID 集合」为锚，找回全部块首记录 -> 6 个语言块；
  2. 逐块用字符集特征判语言（日=假名，德=ä ö ü ß，西=ñ ¿ ¡，
     法=œ Œ 及 ç/è/ê/à 组合，意=仅 grave 重音，英=其余纯 ASCII）；
  3. 交叉验证：块内语音 ID 序列与其它块的语音 ID 序列应逐位对齐。
"""
import collections
import re
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

# 语言特征字符（按判别力从强到弱）
FEAT = [
    ("ja", r"[぀-ヿ一-鿿ｦ-ﾟ]"),
    ("de", r"[äöüßÄÖÜ]"),
    ("es", r"[ñÑ¿¡áéíóúÁÉÍÓÚ]"),
    ("fr", r"[œŒ]"),
    ("it", r"[àèìòùÀÈÌÒÙ]"),
    ("en", r"[A-Za-z]"),
]


def score(text: str) -> str:
    """按最具判别力的特征字符判语言。"""
    for lang, pat in FEAT:
        if re.search(pat, text):
            return lang
    return "-"


def main():
    br = load(DAT)
    recs = br.records
    n = len(recs)
    vids = [tuple(sorted(set(r.voice_ids(br.data)))) for r in recs]

    # --- 1. 以记录 0 的语音 ID 为锚找块首 ---
    anchor = vids[0]
    print(f"[1] 锚：记录 0  sec{recs[0].sector}  voice={anchor}")
    starts = [i for i in range(n) if vids[i] == anchor and anchor]
    print(f"    同锚记录索引：{starts}")

    # --- 2. 用「语音 ID 序列重复」独立复核：找周期 d 使 vids[i]==vids[i+d] 命中最多 ---
    print("\n[2] 序列周期复核（语音 ID 集合逐位相等的比例）")
    best = []
    for d in range(1, n):
        m = sum(1 for i in range(n - d) if vids[i] and vids[i] == vids[i + d])
        if m >= 10:
            best.append((m, d))
    best.sort(reverse=True)
    for m, d in best[:12]:
        print(f"    d={d:5d}  命中 {m:5d}")

    # --- 3. 按锚切块并判语言 ---
    if len(starts) < 2:
        print("\n锚点不足以切块，改用 [2] 的主周期。")
        if not best:
            return 1
        d = best[0][1]
        starts = list(range(0, n, d))
    bounds = starts + [n]
    print(f"\n[3] 块划分（{len(bounds)-1} 块）")
    blocks = []
    for k in range(len(bounds) - 1):
        lo, hi = bounds[k], bounds[k + 1]
        grp = recs[lo:hi]
        txt = "".join("".join(r.lines) for r in grp)
        lang = collections.Counter(score(t) for t in
                                   ("".join(r.lines) for r in grp)
                                   if t.strip())
        blocks.append((lo, hi, grp))
        print(f"  块{k}  rec {lo:5d}-{hi-1:5d} ({hi-lo:4d})  "
              f"sec {grp[0].sector:4d}-{grp[-1].sector:4d}  "
              f"off {grp[0].off:#8x}-{grp[-1].off:#8x}  "
              f"行 {sum(r.n_lines for r in grp):6d}  {dict(lang)}")

    # --- 4. 交叉验证：块间语音 ID 逐位对齐率 ---
    print("\n[4] 块间语音 ID 逐位对齐率（对角线应为高值，且各块长度接近）")
    L = [hi - lo for lo, hi, _ in blocks]
    m0 = min(L)
    print("      " + "".join(f"  块{j}" for j in range(len(blocks))))
    for i in range(len(blocks)):
        row = []
        for j in range(len(blocks)):
            li, lj = blocks[i][0], blocks[j][0]
            m = sum(1 for k in range(m0)
                    if vids[li + k] and vids[li + k] == vids[lj + k])
            row.append(f"{m*100//m0:4d}%")
        print(f"  块{i}  " + " ".join(row))

    # --- 5. 抽样：跨块同一语音 ID 的首行对照 ---
    print("\n[5] 跨块同锚文本对照（每块取前 3 条记录的语音 ID 所在记录）")
    v2i = collections.defaultdict(list)
    for i, v in enumerate(vids):
        for x in v:
            v2i[x].append(i)
    shown = 0
    for v, idxs in sorted(v2i.items()):
        blks = {next(k for k in range(len(bounds) - 1)
                     if bounds[k] <= x < bounds[k + 1]) for x in idxs}
        if len(blks) < len(blocks) - 1:
            continue
        print(f"\n  == {v}")
        for i in idxs:
            k = next(k for k in range(len(bounds) - 1)
                     if bounds[k] <= i < bounds[k + 1])
            t = recs[i].lines[0] if recs[i].lines else ""
            print(f"    块{k}({score(''.join(recs[i].lines))}) sec{recs[i].sector:4d} "
                  f"n={recs[i].n_lines:3d}  {t[:64]}")
        shown += 1
        if shown >= 4:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())

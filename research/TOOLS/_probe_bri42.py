"""_probe_bri42.py —— 语言块的精确定位与判定

方法
----
1. **块首定位**：语言块内记录顺序一致（同一套 TOPIC 顺序），故每个块的前
   若干条记录，其语音 ID 序列应与块 0 的前若干条逐一相等。对全部 i 计算
   ``m(i) = |{k<W : vids[i+k] == vids[k]}|``，尖峰即块首。

2. **语言判定**：把每块的全部台词聚合，用各语言的高频虚词（停用词）计数
   打分。词频法远比字符集法可靠（法语 é/à 与西语重叠，无法区分）。

3. **交叉验证**：块间同一语音 ID 的记录文本，用同一判据复判，应全部自洽。
"""
import collections
import re
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

W = 24  # 块首对齐窗口

STOP = {
    "ja": "の に は を が と で も から まで です ます だ な か ね よ 私 俺 君 こと それ この その".split(),
    "en": "the you and to of is that I a it in we for on be do not have with this".split(),
    "fr": "le la les de des un une est et vous nous je que qui pour dans pas il elle "
          "sur avec ne ce mais ou comme plus tout".split(),
    "de": "der die das den dem und ich nicht ist sind zu ein eine wir sie für auf mit "
          "es auch aber noch nur schon kann hat habe".split(),
    "it": "il lo la i gli le di a da in con su per tra fra che non più come ma se "
          "sono ho hai abbiamo questo quello mi ti ci vi".split(),
    "es": "el los las la de del un una que y en a con por para no es son lo se "
          "como pero más mi tu este esta hemos tengo".split(),
}
STOP = {k: [w.lower() for w in v] for k, v in STOP.items()}


def words(text: str):
    return re.findall(r"[^\W\d_]+", text.lower(), re.UNICODE)


def judge(text: str):
    """停用词频打分 -> (语言, 各语言得分)"""
    ws = collections.Counter(words(text))
    total = sum(ws.values()) or 1
    sc = {k: sum(ws[w] for w in v) * 1000 // total for k, v in STOP.items()}
    best = max(sc, key=lambda k: sc[k])
    return best, sc


def main():
    br = load(DAT)
    recs = br.records
    n = len(recs)
    vids = [tuple(sorted(set(r.voice_ids(br.data)))) for r in recs]

    # --- 1. 块首定位 ---
    prof = [(i, sum(1 for k in range(W) if vids[i + k] and vids[i + k] == vids[k]))
            for i in range(n - W)]
    peaks = [i for i, m in prof if m >= W // 2]
    print(f"[1] 块首候选（窗口 W={W}，命中 >= {W//2}）：{peaks}")
    print("    各候选的命中数：", {i: m for i, m in prof if m >= W // 2})

    # 合并相邻的候选（取局部最大）
    starts, last = [], -99
    for i, m in sorted(prof, key=lambda x: -x[1]):
        if m < W // 2:
            break
        if all(abs(i - s) > W for s in starts):
            starts.append(i)
    starts = sorted(starts)
    print(f"    去重后块首：{starts}")

    bounds = starts + [n]
    print(f"\n[2] 块划分（{len(bounds)-1} 块）+ 停用词语言判定")
    blocks = []
    for k in range(len(bounds) - 1):
        lo, hi = bounds[k], bounds[k + 1]
        grp = recs[lo:hi]
        txt = "\n".join("\n".join(r.lines) for r in grp)
        lang, sc = judge(txt)
        blocks.append((lo, hi, lang, sc))
        top = sorted(sc.items(), key=lambda x: -x[1])[:3]
        print(f"  块{k}  rec {lo:5d}-{hi-1:5d} ({hi-lo:4d})  "
              f"sec {grp[0].sector:4d}-{grp[-1].sector:4d}  "
              f"off {grp[0].off:#8x}-{grp[-1].off:#8x}  "
              f"行 {sum(r.n_lines for r in grp):6d}  -> {lang}   {top}")

    # --- 3. 逐记录复判：块内每条记录单独判定，统计一致性 ---
    print("\n[3] 逐记录语言判定与块判定一致率")
    for k, (lo, hi, blang, _) in enumerate(blocks):
        c = collections.Counter()
        for r in recs[lo:hi]:
            t = "".join(r.lines)
            if len(t.strip()) < 12:
                c["(短)"] += 1
                continue
            c[judge(t)[0]] += 1
        agree = c[blang] * 100 // max(1, hi - lo)
        print(f"  块{k} -> {blang:3s}  一致 {agree}%   {dict(c.most_common(5))}")

    # --- 4. 跨块同锚文本对照（终检）---
    print("\n[4] 跨块同一语音 ID 的文本对照")
    v2i = collections.defaultdict(list)
    for i, v in enumerate(vids):
        for x in v:
            v2i[x].append(i)
    shown = 0
    for v, idxs in sorted(v2i.items()):
        ks = [next(k for k in range(len(bounds) - 1)
                   if bounds[k] <= x < bounds[k + 1]) for x in idxs]
        if len(set(ks)) < len(blocks):
            continue
        print(f"\n  == {v}")
        for i, k in zip(idxs, ks):
            t = recs[i].lines[0] if recs[i].lines else ""
            t = t.replace("\n", " ")
            print(f"    块{k} {blocks[k][2]:3s} sec{recs[i].sector:4d} "
                  f"n={recs[i].n_lines:3d}  {t[:66]}")
        shown += 1
        if shown >= 5:
            break

    # --- 5. 边界精修：检查块首尾是否有跨块污染 ---
    print("\n[5] 块边界邻近记录的判定（检查边界是否准确）")
    for k, (lo, hi, blang, _) in enumerate(blocks):
        edge = list(range(max(0, lo - 2), min(n, lo + 3)))
        seq = []
        for i in edge:
            r = recs[i]
            t = "".join(r.lines)
            seq.append(f"{i}:{judge(t)[0] if len(t.strip())>12 else '?'}")
        print(f"  块{k}({blang}) 起点 rec{lo} 附近： {' '.join(seq)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

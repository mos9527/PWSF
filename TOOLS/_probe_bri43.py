"""_probe_bri43.py —— 逐记录语言判定 -> 游程压缩 -> 语言块边界

前两轮证明：
  * 文件里同一语音 ID 的同一段台词会出现 6 次，每次一种语言（_probe_bri40）；
  * 但块首无法用「语音 ID 序列首部对齐」定位——各块记录数不等（JA 的台词
    更短，记录数也不同），故 W 窗口对齐失效（_probe_bri42）。

本轮改用自下而上的办法：先给每条记录单独判语言，再按文件顺序做游程压缩，
语言游程 = 语言块。判据是停用词词频（_probe_bri42 已证其对六语种都有效，
且块内一致率远高于块间）。
"""
import collections
import re
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

STOP = {
    "ja": "の に は を が と で も から まで です ます だ な か ね よ 私 俺 君 こと それ この その そう いる ある する れる".split(),
    "en": "the you and to of is that I a it in we for on be do not have with this "
          "what but they my me your".split(),
    "fr": "le la les de des un une est et vous nous je que qui pour dans pas il elle "
          "sur avec ne ce mais ou comme plus tout sont être avoir fait".split(),
    "de": "der die das den dem und ich nicht ist sind zu ein eine wir sie für auf mit "
          "es auch aber noch nur schon kann hat habe wird werden".split(),
    "it": "il lo la i gli le di a da in con su per tra fra che non più come ma se "
          "sono ho hai abbiamo questo quello mi ti ci vi del della".split(),
    "es": "el los las la de del un una que y en a con por para no es son lo se "
          "como pero más mi tu este esta hemos tengo su sus".split(),
}
STOP = {k: [w.lower() for w in v] for k, v in STOP.items()}
LANGS = list(STOP)


def words(t):
    return re.findall(r"[^\W\d_]+", t.lower(), re.UNICODE)


def judge(t, smooth=0):
    """返回 (语言, 归一化得分 dict)；smooth 为给每语言加的伪计数。"""
    ws = collections.Counter(words(t))
    tot = sum(ws.values()) + smooth * len(LANGS) or 1
    sc = {k: sum(ws[w] for w in v) for k, v in STOP.items()}
    tot = sum(sc.values()) + smooth * len(LANGS) or 1
    sc = {k: (v + smooth) * 1000 // tot for k, v in sc.items()}
    return max(sc, key=lambda k: sc[k]), sc


def main():
    br = load(DAT)
    recs = br.records
    n = len(recs)

    # --- 1. 逐记录判定 ---
    per = []
    for r in recs:
        t = "\n".join(r.lines)
        if len(t.strip()) < 8:
            per.append(("-", None))
        else:
            per.append(judge(t))

    print("[1] 逐记录判定的游程压缩（文件顺序；'?' = 文本过短无法判定）")
    runs = []
    cur, lo = per[0][0], 0
    for i in range(1, n):
        if per[i][0] != cur:
            runs.append((cur, lo, i - 1))
            cur, lo = per[i][0], i
    runs.append((cur, lo, n - 1))
    print(f"    共 {len(runs)} 个游程（>20 条的用 >>> 标出）")
    for lang, lo, hi in runs:
        mark = ">>>" if hi - lo + 1 > 20 else "   "
        print(f"    {mark} {lang:3s} rec {lo:5d}-{hi:5d} ({hi-lo+1:5d})  "
              f"sec {recs[lo].sector:4d}-{recs[hi].sector:4d}")

    # --- 2. 只保留长度 > 20 的游程作为语言块 ---
    big = [r for r in runs if r[2] - r[1] + 1 > 20]
    print(f"\n[2] 长度 > 20 的游程 = 语言块（{len(big)} 块）")
    for k, (lang, lo, hi) in enumerate(big):
        txt = "\n".join("\n".join(r.lines) for r in recs[lo:hi + 1])
        bl, sc = judge(txt)
        top = sorted(sc.items(), key=lambda x: -x[1])[:3]
        print(f"  块{k}  {bl:3s}  rec {lo:5d}-{hi:5d} ({hi-lo+1:4d})  "
              f"sec {recs[lo].sector:4d}-{recs[hi].sector:4d}  "
              f"off {recs[lo].off:#8x}-{recs[hi].off:#8x}  "
              f"行 {sum(r.n_lines for r in recs[lo:hi+1]):6d}   {top}")

    # --- 3. 块内一致率 ---
    print("\n[3] 块内逐记录一致率")
    for k, (lang, lo, hi) in enumerate(big):
        c = collections.Counter(per[i][0] for i in range(lo, hi + 1))
        tot = hi - lo + 1
        print(f"  块{k} {lang:3s} 一致 {c[lang]*100//tot:3d}%   {dict(c.most_common(6))}")

    # --- 4. 块间语音 ID 对齐（验证块确实是「同一套内容的 6 份副本」）---
    print("\n[4] 块间语音 ID 序列对齐率（只看有语音 ID 的记录）")
    seqs = []
    for lang, lo, hi in big:
        seqs.append([tuple(sorted(set(r.voice_ids(br.data))))
                     for r in recs[lo:hi + 1]])
    print("        " + "".join(f"   块{j}({big[j][0]})" for j in range(len(big))))
    for i in range(len(big)):
        row = []
        for j in range(len(big)):
            a, b = seqs[i], seqs[j]
            m = min(len(a), len(b))
            hit = sum(1 for k in range(m) if a[k] and a[k] == b[k])
            nz = sum(1 for k in range(m) if a[k] or b[k])
            row.append(f"{hit*100//max(1,nz):4d}%")
        print(f"  块{i}({big[i][0]})  " + " ".join(row))

    # --- 5. 终检：跨块同语音 ID 文本 ---
    print("\n[5] 跨块同一语音 ID 的文本对照")
    v2i = collections.defaultdict(list)
    for k, (lang, lo, hi) in enumerate(big):
        for i in range(lo, hi + 1):
            for v in set(recs[i].voice_ids(br.data)):
                v2i[v].append((k, i))
    shown = 0
    for v, lst in sorted(v2i.items()):
        if len({k for k, _ in lst}) < len(big):
            continue
        print(f"\n  == {v}")
        for k, i in lst:
            t = (recs[i].lines[0] if recs[i].lines else "").replace("\n", " ")
            print(f"    块{k} {big[k][0]:3s} sec{recs[i].sector:4d} "
                  f"n={recs[i].n_lines:3d}  {t[:66]}")
        shown += 1
        if shown >= 4:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())

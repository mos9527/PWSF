"""_probe_bri44.py —— 语言归属定稿：平滑 -> 合并 -> 12 块 -> 交叉验证

流程
----
1. 逐记录用停用词词频判语言（_probe_bri43 已证块内一致 100%）；
2. 对过短/无法判定的记录用「左右邻居的多数」填补（平滑），消除单条噪声；
3. 合并相邻同语言游程 -> 得到最终语言块；
4. 交叉验证：
   a) 块内语音 ID 集合与其它同组块的对应位置逐一比对（对齐率）；
   b) 块内再抽样复核语言一致率；
5. 输出可嵌入 pwsf_briefing.py 的块表。
"""
import collections
import json
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
MINTEXT = 8


def words(t):
    return re.findall(r"[^\W\d_]+", t.lower(), re.UNICODE)


def judge(t):
    ws = collections.Counter(words(t))
    sc = {k: sum(ws[w] for w in v) for k, v in STOP.items()}
    tot = sum(sc.values()) or 1
    return max(sc, key=lambda k: sc[k]), {k: v * 1000 // tot for k, v in sc.items()}


def main():
    br = load(DAT)
    recs = br.records
    n = len(recs)

    # --- 1. 逐记录判定 ---
    raw = []
    for r in recs:
        t = "\n".join(r.lines)
        raw.append(judge(t)[0] if len(t.strip()) >= MINTEXT else "?")

    # --- 2. 平滑：'?' 与孤立的单条异类 -> 取左右多数 ---
    lang = list(raw)
    for i in range(n):
        if lang[i] != "?":
            continue
        L = next((lang[j] for j in range(i - 1, -1, -1) if lang[j] != "?"), "?")
        R = next((lang[j] for j in range(i + 1, n) if lang[j] != "?"), "?")
        lang[i] = L if L == R else (L if L != "?" else R)
    changed = 1
    while changed:
        changed = 0
        for i in range(1, n - 1):
            if lang[i] == lang[i - 1] or lang[i] == lang[i + 1]:
                continue
            if lang[i - 1] == lang[i + 1]:
                lang[i] = lang[i - 1]
                changed = 1
    print(f"[1] 平滑前 '?' {sum(1 for x in raw if x=='?')} 条；"
          f"平滑修正 {sum(1 for a,b in zip(raw,lang) if a!=b)} 条")

    # --- 3. 合并相邻同语言游程 ---
    runs, lo = [], 0
    for i in range(1, n):
        if lang[i] != lang[lo]:
            runs.append([lang[lo], lo, i - 1])
            lo = i
    runs.append([lang[lo], lo, n - 1])
    print(f"\n[2] 平滑后的游程 = {len(runs)} 个")
    for l, a, b in runs:
        print(f"    {l:3s}  rec {a:5d}-{b:5d} ({b-a+1:4d})  "
              f"sec {recs[a].sector:4d}-{recs[b].sector:4d}  "
              f"off {recs[a].off:#8x}-{recs[b].off:#8x}")

    # --- 4. 交叉验证 a)：同语言游程之间的语音 ID 位置对齐 ---
    vids = [tuple(sorted(set(r.voice_ids(br.data)))) for r in recs]
    print("\n[3] 游程间语音 ID 位置对齐率（分子=两者都非空且相等，分母=min 长度）")
    ids = [f"{l}({a})" for l, a, b in runs]
    print("        " + " ".join(f"{x:>9s}" for x in ids))
    for i, (l1, a1, b1) in enumerate(runs):
        row = []
        for j, (l2, a2, b2) in enumerate(runs):
            m = min(b1 - a1, b2 - a2) + 1
            hit = sum(1 for k in range(m)
                      if vids[a1 + k] and vids[a1 + k] == vids[a2 + k])
            row.append(f"{hit*100//m:8d}%" if i != j else "       -")
        print(f"  {ids[i]:>9s} " + " ".join(row))

    # --- 5. 交叉验证 b)：逐记录复判一致率 ---
    print("\n[4] 逐记录复判与游程语言的一致率")
    for l, a, b in runs:
        c = collections.Counter(raw[i] for i in range(a, b + 1))
        print(f"    {l:3s} rec{a}-{b}: 一致 {c[l]*100//(b-a+1):3d}%  "
              f"{dict(c.most_common(4))}")

    # --- 6. 输出块表 ---
    tbl = [[l, a, b] for l, a, b in runs]
    print("\n[5] 块表（JSON）")
    print(json.dumps(tbl, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

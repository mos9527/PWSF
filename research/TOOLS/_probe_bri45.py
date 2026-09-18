"""_probe_bri45.py —— 12 块的最终验证：LCS 序列对齐 + 增补记录定位

背景
----
_probe_bri44 得到的 12 块（2 组 x 6 语言）块内逐记录语言一致率 96~100%，
但块间「同位置语音 ID 相等率」只有 ~10%。原因是各块记录数不等
（ja 248 / en 270 / fr 258 / de 254 / it 251 / es 258），严格的位置比对失效。

本轮用 **LCS（最长公共子序列）** 对齐语音 ID 序列：若两块是同一套内容的
两种语言，则 LCS 长度应接近 min(长度)，且对齐后剩余的「增补记录」很少。

同时定位：
  * 各块中语言为 en 的小岛（相对位置 ~78 的 5 条）——疑似未翻译的占位记录；
  * 各块的「dummy. not used」记录数——解释块长差异。
"""
import collections
import re
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

# _probe_bri44 [2] 的产物：合并 <10 条的语言岛后得到的 12 块
BLOCKS = [
    # (组, 语言, rec_lo, rec_hi)
    (1, "ja", 0, 247), (1, "en", 248, 517), (1, "fr", 518, 775),
    (1, "de", 776, 1029), (1, "it", 1030, 1280), (1, "es", 1281, 1538),
    (2, "ja", 1539, 1625), (2, "en", 1626, 1713), (2, "fr", 1714, 1793),
    (2, "de", 1794, 1877), (2, "it", 1878, 1961), (2, "es", 1962, 2048),
]


def lcs(a, b):
    """返回 LCS 长度与对齐后的 (i,j) 配对。"""
    n, m = len(a), len(b)
    # 只关心两边都非空的项，用 value 做键
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        ai = a[i]
        row, nxt = dp[i], dp[i + 1]
        for j in range(m - 1, -1, -1):
            row[j] = nxt[j + 1] + 1 if (ai and ai == b[j]) else max(nxt[j], row[j + 1])
    pairs, i, j = [], 0, 0
    while i < n and j < m:
        if a[i] and a[i] == b[j]:
            pairs.append((i, j))
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            i += 1
        else:
            j += 1
    return dp[0][0], pairs


def main():
    br = load(DAT)
    recs = br.records
    vids = [tuple(sorted(set(r.voice_ids(br.data)))) for r in recs]

    print("[1] 块概览")
    for g, l, a, b in BLOCKS:
        grp = recs[a:b + 1]
        vs = {v for r in grp for v in r.voice_ids(br.data)}
        dummy = sum(1 for r in grp if r.lines and "dummy" in r.lines[0])
        print(f"  组{g} {l:3s} rec{a:5d}-{b:5d} ({b-a+1:4d})  "
              f"sec {grp[0].sector:4d}-{grp[-1].sector:4d}  "
              f"行 {sum(r.n_lines for r in grp):6d}  "
              f"语音ID {len(vs):4d}  dummy {dummy:3d}")

    print("\n[2] 组内 LCS 对齐（以 ja 为基准；对齐率 = LCS / min(长度)）")
    for g in (1, 2):
        bl = [(l, a, b) for gg, l, a, b in BLOCKS if gg == g]
        base_l, base_a, base_b = bl[0]
        A = vids[base_a:base_b + 1]
        print(f"\n  组{g}（基准 {base_l}，长度 {len(A)}）")
        for l, a, b in bl:
            B = vids[a:b + 1]
            k, pairs = lcs(A, B)
            m = min(len(A), len(B))
            # 只统计两边都非空的位置作分母更公平
            nz = sum(1 for x in A if x)
            print(f"    vs {l:3s}  长度 {len(B):4d}  LCS {k:4d}  "
                  f"对齐率 {k*100//m:3d}%  (非空项 {nz} / {sum(1 for x in B if x)})  "
                  f"缺口 {len(A)-k}/{len(B)-k}")
            if l != base_l and pairs:
                d = collections.Counter(j - i for i, j in pairs)
                print(f"          位移分布（j-i）: {dict(d.most_common(5))}")

    print("\n[3] 与 ja 块相比，其它块的「增补记录」（LCS 未对齐上的项）")
    for g in (1, 2):
        bl = [(l, a, b) for gg, l, a, b in BLOCKS if gg == g]
        base_l, base_a, base_b = bl[0]
        A = vids[base_a:base_b + 1]
        print(f"\n  组{g}")
        for l, a, b in bl[1:]:
            B = vids[a:b + 1]
            k, pairs = lcs(A, B)
            used = {j for _, j in pairs}
            extra = [(j, B[j]) for j in range(len(B)) if j not in used and B[j]]
            print(f"    {l:3s} 增补 {len(extra)} 条有语音 ID 的记录；"
                  f"示例 {[f'{a+j}:{v[0]}' for j, v in extra[:6]]}")
            for j, v in extra[:3]:
                r = recs[a + j]
                t = (r.lines[0] if r.lines else "").replace("\n", " ")
                print(f"        rec{a+j} sec{r.sector} n={r.n_lines} {t[:60]}")

    print("\n[4] 各块中相对位置 74~84 的 5 条 en 小岛")
    for g, l, a, b in BLOCKS:
        for rel in range(74, 85):
            i = a + rel
            if i > b:
                break
            r = recs[i]
            t = (r.lines[0] if r.lines else "").replace("\n", " ")
            v = r.voice_ids(br.data)
            if v:
                continue
            if l == "en" or rel not in (74, 75, 76, 77, 78, 79, 80, 81, 82):
                continue
            print(f"  {l} rec{i} rel{rel} n={r.n_lines}  {t[:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

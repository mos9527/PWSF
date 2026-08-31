"""_probe_bri46.py —— 验证「语音 ID = 跨语言对齐键」

命题：语音资源 ID（如 v_bri_amd0010_000_0）在 6 个语言块中各出现一次，
标识同一段对话。若成立，则本地化可直接以语音 ID（+ 行号）为键做对齐，
无需依赖记录位置。
"""
import collections
import sys

from pwsf_briefing import load, SECTOR

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

BLOCKS = [
    (1, "ja", 0, 247), (1, "en", 248, 517), (1, "fr", 518, 775),
    (1, "de", 776, 1029), (1, "it", 1030, 1280), (1, "es", 1281, 1538),
    (2, "ja", 1539, 1625), (2, "en", 1626, 1713), (2, "fr", 1714, 1793),
    (2, "de", 1794, 1877), (2, "it", 1878, 1961), (2, "es", 1962, 2048),
]
LANGS = ["ja", "en", "fr", "de", "it", "es"]


def main():
    br = load(DAT)
    recs = br.records

    # rec -> (组, 语言)
    owner = {}
    for g, l, a, b in BLOCKS:
        for i in range(a, b + 1):
            owner[i] = (g, l)

    v2 = collections.defaultdict(lambda: collections.defaultdict(list))
    for i, r in enumerate(recs):
        g, l = owner[i]
        for v in set(r.voice_ids(br.data)):
            v2[v][(g, l)].append(i)

    for g in (1, 2):
        print(f"\n===== 组{g} =====")
        ids = [v for v in v2 if any(k[0] == g for k in v2[v])]
        print(f"语音 ID 总数 {len(ids)}")
        dist = collections.Counter(len({k[1] for k in v2[v] if k[0] == g})
                                   for v in ids)
        print("每个 ID 覆盖的语言数分布：", dict(sorted(dist.items())))

        # 每个 ID 在每种语言里的记录数是否都恰好为 1
        bad = [v for v in ids
               if any(len(v2[v].get((g, l), [])) != 1 for l in LANGS)]
        print(f"并非『每语言恰好 1 条记录』的 ID：{len(bad)}")
        for v in bad[:8]:
            print(f"    {v}: " + "  ".join(
                f"{l}={len(v2[v].get((g,l),[]))}" for l in LANGS))

        # 集合差
        sets = {l: {v for v in ids if (g, l) in v2[v]} for l in LANGS}
        for l in LANGS:
            print(f"    {l}: {len(sets[l])} 个 ID")
        base = sets["ja"]
        for l in LANGS[1:]:
            only = sets[l] - base
            miss = base - sets[l]
            print(f"    {l} vs ja: 独有 {len(only)}  缺失 {len(miss)}")
            if only:
                print(f"        独有示例 {sorted(only)[:5]}")
            if miss:
                print(f"        缺失示例 {sorted(miss)[:5]}")

    # --- 用语音 ID 做键的跨语言文本对照（终检）---
    print("\n===== 以语音 ID 为键的六语对照（组1 抽样 3 个）=====")
    ok = [v for v in v2
          if len({k[1] for k in v2[v] if k[0] == 1}) == 6
          and all(len(v2[v][(1, l)]) == 1 for l in LANGS)]
    print(f"六语齐全且一一对应的 ID：{len(ok)} / "
          f"{len([v for v in v2 if any(k[0]==1 for k in v2[v])])}")
    for v in sorted(ok)[:3]:
        print(f"\n  == {v}")
        for l in LANGS:
            i = v2[v][(1, l)][0]
            r = recs[i]
            print(f"    [{l}] rec{i} sec{r.sector} n={r.n_lines}")
            for t in r.lines[:2]:
                print(f"        {t.replace(chr(10), ' ')[:72]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

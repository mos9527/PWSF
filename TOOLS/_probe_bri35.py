"""_probe_bri35 —— 用「在 group A 上标定、在 group B 上判定」的方法定语言块边界。

标定集（由样例文本**目视确认**，见 _probe_bri24.py）：
    记录 0..247    ja      248..517  en      518..775   fr
    776..1029 de     1030..1280 it     1281..1538 es

方法：
  1. 以标定集每条记录的台词构建「字符 4-gram 频次向量」（取每类前 N 个）
  2. 余弦相似度分类
  3. 先回判标定集自己的准确率（自检验），再判定全部 2049 条记录
  4. 输出记录序号的 RLE，得到语言块的边界
"""
import collections
import math
import re

from pwsf_briefing import load

DAT = (r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
       r"\MLG\disc0_rel\0076531d.DAT")

TRAIN = [("ja", 0, 248), ("en", 248, 518), ("fr", 518, 776),
         ("de", 776, 1030), ("it", 1030, 1281), ("es", 1281, 1539)]

br = load(DAT)
recs = br.records


def norm(s: str) -> str:
    s = re.sub(r"<R=[^>]*>", "", s)          # 去掉振假名标记
    return " " + s.lower() + " "


def grams(s: str, n: int = 4):
    return [s[i:i + n] for i in range(len(s) - n + 1)]


# ---- 建profile ----
prof = {}
for lang, a, b in TRAIN:
    c = collections.Counter()
    for r in recs[a:b]:
        c.update(grams(norm("".join(r.lines))))
    prof[lang] = c

TOPN = 3000
keys = set()
for c in prof.values():
    keys.update(k for k, _ in c.most_common(TOPN))
keys = sorted(keys)
vec = {}
for lang, c in prof.items():
    v = [float(c.get(k, 0)) for k in keys]
    n = math.sqrt(sum(x * x for x in v))
    vec[lang] = [x / n for x in v]


def classify(r) -> str:
    g = collections.Counter(grams(norm("".join(r.lines))))
    v = [float(g.get(k, 0)) for k in keys]
    best, bs = "?", -1.0
    for lang, pv in vec.items():
        s = sum(x * y for x, y in zip(v, pv))
        if s > bs:
            best, bs = lang, s
    return best


# ---- 自检验 ----
print("=== 标定集自检验 ===")
ok = tot = 0
for lang, a, b in TRAIN:
    cc = collections.Counter(classify(r) for r in recs[a:b])
    ok += cc[lang]
    tot += b - a
    print(f"  {lang} ({b-a:4d} 条) -> {dict(cc)}")
print(f"  自检验准确率 {ok}/{tot} = {ok/tot:.4f}")

# ---- 全文件判定 + RLE ----
labels = [classify(r) for r in recs]
runs = []
cur = [labels[0], 0, 0]
for i, L in enumerate(labels):
    if L == cur[0]:
        cur[2] = i
    else:
        runs.append(tuple(cur))
        cur = [L, i, i]
runs.append(tuple(cur))

print(f"\n=== 全部 {len(labels)} 条记录的判定游程（共 {len(runs)} 段）===")
for L, a, b in runs:
    print(f"  {L}  记录 {a:5d}..{b:5d} ({b-a+1:4d} 条)  "
          f"扇区 {recs[a].sector:4d}..{recs[b].sector:4d}")

# ---- 汇总每段的样例，供人工核对 ----
print("\n=== 每段样例（首条首行 60 字）===")
for L, a, b in runs:
    t = (recs[a].lines[0] or "").replace("\n", "\\n")[:60]
    print(f"  [{L}] #{a:5d} s{recs[a].sector:4d}  {t}")

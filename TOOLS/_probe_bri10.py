"""Probe: 用停用词做语言判定，并画出「扇区 -> 语言」地图。"""
import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pwsf_briefing as B

STOP = {
    "en": "the and you that for with this have not are but they from",
    "fr": "les des une vous pour avec dans est pas que qui sur sont",
    "de": "der die und das ist nicht ein den mit sich auf für sind",
    "it": "che non una per con del sono questo ma anche più come",
    "es": "que para con los una por como pero esto del más son las",
    "pt": "que para com uma não por como mas isso dos mais são nas",
}
STOP = {k: set(v.split()) for k, v in STOP.items()}
KANA = re.compile(r"[぀-ヿ]")
KANJI = re.compile(r"[一-鿿]")


def detect(s: str) -> str:
    if KANA.search(s) or KANJI.search(s):
        return "ja"
    w = re.findall(r"[A-Za-zÀ-ÿ]+", s.lower())
    if not w:
        return "-"
    best, bn = "-", 0.0
    for lg, st in STOP.items():
        c = sum(1 for x in w if x in st)
        sc = c / (len(w) ** 0.5)
        if sc > bn:
            best, bn = lg, sc
    return best if bn > 0.4 else "-"


br = B.load(r"C:\Program Files (x86)\Steam\steamapps\common\MGS_PW\mgspw"
            r"\MLG\disc0_rel\0076531d.DAT")
print(f"记录 {len(br.records)}  台词 {sum(r.n_lines for r in br.records)}")

for r in br.records:
    r.lang = detect(" ".join(r.lines))

print("记录语言计数：", dict(collections.Counter(r.lang for r in br.records)))

# 每扇区主导语言
sec_lang = {}
for r in br.records:
    sec_lang.setdefault(r.sector, collections.Counter())[r.lang] += 1
rows = []
for sec in sorted(sec_lang):
    lg, n = sec_lang[sec].most_common(1)[0]
    tot = sum(sec_lang[sec].values())
    rows.append((sec, lg, n, tot))

print("\n扇区 -> 语言（压缩游程；n/tot = 主导语言记录数/该扇区记录数）")
prev, start = None, 0
zones = []
for sec, lg, n, tot in rows:
    if lg != prev:
        if prev is not None:
            zones.append((start, sec - 1, prev))
        prev, start = lg, sec
zones.append((start, rows[-1][0], prev))
for a, b, lg in zones:
    sub = [r for r in rows if a <= r[0] <= b]
    nn = sum(x[2] for x in sub)
    tt = sum(x[3] for x in sub)
    print(f"  扇区 {a:5}..{b:5} ({b - a + 1:4})  {lg}   {nn}/{tt}")

# 各语言记录数（按扇区主导语言归并后）
cnt = collections.Counter()
for sec, lg, n, tot in rows:
    cnt[lg] += n
print("\n归并后语言记录数：", dict(cnt))

# 各语言台词数
lc = collections.Counter()
for r in br.records:
    key = sec_lang[r.sector].most_common(1)[0][0]
    lc[key] += r.n_lines
print("归并后语言台词数：", dict(lc))

# 语音 ID 前缀分布
pat = re.compile(rb"([a-z])_([a-z]{3})_([a-z]+)([0-9]+)_([0-9]+)_([0-9]+)")
c1 = collections.Counter()
c2 = collections.Counter()
for r in br.records:
    seg = br.data[r.script_off:min(len(br.data), r.script_off + 16384)]
    for m in pat.finditer(seg):
        c1[m.group(1) + "_" + m.group(2)] += 1
        c2[m.group(3)] += 1
print("\n语音 ID 前缀 (v_XXX)：", dict(c1.most_common(20)))
print("语音 ID 说话人：", dict(c2.most_common(30)))

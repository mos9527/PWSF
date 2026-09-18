"""Probe: 语音集分区（v_bri / v_fop）、语言分区边界、<R=...> 富文本标记。"""
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
KANA = re.compile(r"[぀-ヿ一-鿿]")


def detect(s: str) -> str:
    if KANA.search(s):
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
D = br.data
VOICE = re.compile(rb"\b([a-z])_([a-z]{3})_([a-z]{3,})_?(\d*)_?(\d*)_?(\d*)")

for r in br.records:
    r.lang = detect(" ".join(r.lines))
    seg = D[r.script_off:min(len(D), r.script_off + 16384)]
    vids = re.findall(rb"[a-z]_[a-z]{3}_[A-Za-z0-9_]{6,}", seg)
    r.vset = collections.Counter(v.decode().split("_")[1] for v in vids).most_common(1)
    r.vset = r.vset[0][0] if r.vset else "-"
    r.vids = [v.decode() for v in vids]

print(f"记录 {len(br.records)}  台词 {sum(r.n_lines for r in br.records)}")

print("\n=== 语音集 (v_XXX) 分区 ===")
prev, start = None, 0
for r in br.records:
    if r.vset != prev:
        if prev is not None:
            print(f"  扇区 {start:5}..{r.sector - 1:5}  v_{prev}")
        prev, start = r.vset, r.sector
print(f"  扇区 {start:5}..{br.records[-1].sector:5}  v_{prev}")

print("\n=== 语言分区（记录级，压缩游程，容 2 条噪声）===")
seq = []
for r in br.records:
    if not seq or seq[-1][0] != r.lang:
        seq.append([r.lang, r.sector, r.sector, 1])
    else:
        seq[-1][2] = r.sector
        seq[-1][3] += 1
merged = []
for lg, a, b, n in seq:
    if n <= 2 and merged:
        merged[-1][2] = b
        merged[-1][3] += n
    else:
        merged.append([lg, a, b, n])
for lg, a, b, n in merged:
    print(f"  扇区 {a:5}..{b:5}  {lg}   {n:5} 条")

print("\n=== 语言 × 记录数 / 台词数 ===")
c1, c2 = collections.Counter(), collections.Counter()
for r in br.records:
    c1[r.lang] += 1
    c2[r.lang] += r.n_lines
for lg in sorted(c1):
    print(f"  {lg}: {c1[lg]:5} 条  {c2[lg]:6} 行")

print("\n=== 富文本标记 <R=...> ===")
rm = collections.Counter()
for r in br.records:
    for s in r.lines:
        rm.update(re.findall(r"<R=([^>]*)>", s))
print(f"  不同取值 {len(rm)}，出现 {sum(rm.values())} 次")
for k, v in rm.most_common(25):
    print(f"   <R={k}>  x{v}")

print("\n=== 其它尖括号标记 ===")
oth = collections.Counter()
for r in br.records:
    for s in r.lines:
        oth.update(re.findall(r"<([A-Za-z]+)=?", s))
print("  ", dict(oth.most_common(20)))

print("\n=== 语音 ID 命名样本（按集）===")
by = collections.defaultdict(set)
for r in br.records:
    for v in r.vids[:3]:
        by[r.vset].add(v)
for k in sorted(by):
    print(f"  v_{k}: {sorted(by[k])[:6]}")

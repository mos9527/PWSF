"""_probe_bri53.py —— CODEC 回写：文本池「原地重写」的预算与往返一致性

前情（_probe_bri51.py，ANALYSIS/03 §9）
--------------------------------------
* 可译文本**只**在文本池里，脚本区 0/2049 条含台词 -> 回写不需要碰字节码；
* 记录尺寸不能变（``off3 == off0 - 4`` 恒成立，记录间空隙 0-15 B，且记录
  绝对偏移被编进 req 字、由另一个脚本文件的 TOPIC 表引用）；
* 故方案是「尺寸不变的原地重写」：重写文本池 + 重建 u32 偏移表，
  ``off0..off3`` 一个字节都不改（§9.3）。

本探针把该方案落成可测量的事实：

[A] 布局恒等式：``off3 == off0 - 4``、``off2 - off1 == 4 * n_lines``
    （即偏移表紧接头、池紧接表）
[B] **预算**：``budget = off3 - off2`` vs 当前用量 ``sum(len(utf8)+1)``，
    逐记录余量分布，en 块合计
[C] ``table[0] != 0`` 的记录有多少（决定重排时第一个串从哪开始写）
[D] 池末端到 ``off3`` 的尾巴是什么（是否全 NUL —— 决定能不能安全复用）
[E] **往返**：把**原文**按「紧凑重排」规则重写一遍，记录字节是否与原来
    逐字节相同（相同 = 重排规则与生成器一致，是 §9.3 的成立条件）
[F] 压力：每条记录能承受的字节放大倍率 ``budget / used`` 的分布
"""
import collections
import statistics
import sys

from pwsf_briefing import load
from pwsf import config

DAT = config.pristine(config.BRIEFING_DAT)


def hdr(rec, data):
    """(p1 偏移表, p2 文本池, budget) —— 全部相对 v10 的绝对文件偏移。"""
    v10 = rec.v10
    p1, p2 = v10 + rec.off1, v10 + rec.off2
    return p1, p2, rec.off3 - rec.off2


def main():
    br = load(DAT)
    data = br.data
    recs = br.records
    print(f"{DAT}\n  size={len(data):#x}  key={br.key:#010x}  "
          f"记录={len(recs)}")

    # ---------------------------------------------------------------- [A]
    ok_off3 = ok_tbl = ok_inc = 0
    for r in recs:
        if r.off3 == r.off0 - 4:
            ok_off3 += 1
        if r.off2 - r.off1 == 4 * len(r.table):
            ok_tbl += 1
        if all(r.table[i] < r.table[i + 1] for i in range(len(r.table) - 1)):
            ok_inc += 1
    print(f"\n[A] 布局恒等式")
    print(f"  off3 == off0 - 4        {ok_off3}/{len(recs)}")
    print(f"  off2 - off1 == 4*n      {ok_tbl}/{len(recs)}")
    print(f"  偏移表严格递增          {ok_inc}/{len(recs)}")

    # ---------------------------------------------------------------- [B]
    print(f"\n[B] 预算 = off3 - off2  vs  用量 = sum(len(utf8)+1)")
    per_lang = collections.defaultdict(lambda: dict(n=0, budget=0, used=0,
                                                    slacks=[]))
    for r in recs:
        p1, p2, budget = hdr(r, data)
        used = sum(len(s.encode("utf-8")) + 1 for s in r.lines)
        d = per_lang[(r.group, r.lang)]
        d["n"] += 1
        d["budget"] += budget
        d["used"] += used
        d["slacks"].append(budget - used)
    print(f"  {'组':>2} {'lang':>4} {'记录':>5} {'预算':>9} {'用量':>9} "
          f"{'余量%':>6} {'最小余量':>8} {'中位余量':>8}")
    for (g, lang) in sorted(per_lang):
        d = per_lang[(g, lang)]
        sl = sorted(d["slacks"])
        print(f"  {g:>2} {lang:>4} {d['n']:>5} {d['budget']:>9} "
              f"{d['used']:>9} {100*d['used']//max(1,d['budget']):>5}% "
              f"{sl[0]:>8} {statistics.median(sl):>8.0f}")

    # ---------------------------------------------------------------- [C]
    bad0 = [r for r in recs if r.table and r.table[0] != 0]
    print(f"\n[C] table[0] != 0 的记录：{len(bad0)}/{len(recs)}")
    for r in bad0[:5]:
        p1, p2, _b = hdr(r, data)
        print(f"  {r.off:#x} table[0]={r.table[0]}  "
              f"前导={bytes(data[p2:p2 + min(r.table[0], 16)])!r}")

    # ---------------------------------------------------------------- [D]
    tails = collections.Counter()
    for r in recs:
        p1, p2, budget = hdr(r, data)
        if not r.table:
            continue
        end = p2 + r.table[-1] + len(r.lines[-1].encode("utf-8")) + 1
        tail = bytes(data[end:p2 + budget])
        tails["NUL" if tail.strip(b"\x00") == b"" else "nonzero"] += 1
    print(f"\n[D] 池末端..off3 的尾巴：{dict(tails)}")

    # ---------------------------------------------------------------- [E]
    def repack(r, lines):
        """紧凑重排：串顺序写 + NUL，表 = 累积偏移，其余字节不动。

        返回 (新区间的字节, 需求字节数) 或 None（超预算）。
        """
        p1, p2, budget = hdr(r, data)
        blobs = [s.encode("utf-8") + b"\x00" for s in lines]
        need = sum(len(b) for b in blobs)
        if need > budget:
            return None, need
        body = bytearray()
        table = bytearray()
        for b in blobs:
            table += (len(body)).to_bytes(4, "little")
            body += b
        body += b"\x00" * (budget - len(body))
        return bytes(table) + bytes(body), need

    same = diff = over = 0
    for r in recs:
        p1, p2, budget = hdr(r, data)
        new, _need = repack(r, r.lines)
        if new is None:
            over += 1
            continue
        old = bytes(data[p1:p2 + budget])
        if new == old:
            same += 1
        else:
            diff += 1
            if diff <= 3:
                i = next(i for i in range(min(len(old), len(new)))
                         if old[i] != new[i])
                print(f"  差异 {r.off:#x} @+{i:#x}: "
                      f"{old[i:i+12].hex()} -> {new[i:i+12].hex()}")
    print(f"\n[E] 原文紧凑重排 vs 原字节：相同 {same}, 不同 {diff}, "
          f"超预算 {over}  (共 {len(recs)})")

    # [E2] 差异到底长什么样：尾部残留是什么
    print("\n[E2] 差异解剖（前 3 条）")
    shown = 0
    for r in recs:
        if shown >= 3:
            break
        p1, p2, budget = hdr(r, data)
        new, _ = repack(r, r.lines)
        if new is None or new == bytes(data[p1:p2 + budget]):
            continue
        shown += 1
        old = bytes(data[p1:p2 + budget])
        i = next(i for i in range(min(len(old), len(new)))
                 if old[i] != new[i])
        used = sum(len(s.encode("utf-8")) + 1 for s in r.lines)
        tbl_end = 4 * len(r.table)
        print(f"  -- {r.off:#x} 组{r.group} {r.lang} n={len(r.lines)} "
              f"budget={budget} used={used} 表={tbl_end}B")
        print(f"     首个差异在 +{i:#x}（表后 +{i - tbl_end}）")
        print(f"     old  {old[max(0, i - 16):i + 32].hex(' ')}")
        print(f"     new  {new[max(0, i - 16):i + 32].hex(' ')}")
        print(f"     old  {old[max(0, i - 16):i + 32]!r}")
        # 池里每条串的实际占位 vs 我们读到的
        for k in range(min(4, len(r.table))):
            j = tbl_end + r.table[k]
            nul = old.find(b"\x00", j)
            print(f"     line{k}: table={r.table[k]} 池内起 {j} "
                  f"NUL@{nul} 读到的串 {len(r.lines[k].encode())}B")

    # [E3] 若把「尾部残留」原样保留（而不是填 NUL），往返是否成立
    def repack_keep_tail(r, lines):
        p1, p2, budget = hdr(r, data)
        blobs = [s.encode("utf-8") + b"\x00" for s in lines]
        need = sum(len(b) for b in blobs)
        if need > budget:
            return None
        body = bytearray()
        table = bytearray()
        for b in blobs:
            table += len(body).to_bytes(4, "little")
            body += b
        tail = bytes(data[p2 + len(body):p2 + budget])
        return bytes(table) + bytes(body) + tail

    keep = 0
    for r in recs:
        p1, p2, budget = hdr(r, data)
        new = repack_keep_tail(r, r.lines)
        if new is not None and new == bytes(data[p1:p2 + budget]):
            keep += 1
    print(f"\n[E3] 保留尾部残留后逐字节还原：{keep}/{len(recs)}")

    # ---------------------------------------------------------------- [F]
    print(f"\n[F] 可承受倍率 budget/used 的分布")
    ratios = []
    for r in recs:
        p1, p2, budget = hdr(r, data)
        used = sum(len(s.encode("utf-8")) + 1 for s in r.lines)
        ratios.append((budget / used if used else 9.9, r))
    rs = sorted(x[0] for x in ratios)
    def q(p):
        return rs[min(len(rs) - 1, int(len(rs) * p))]
    print(f"  min={rs[0]:.3f}  p1={q(0.01):.3f}  p5={q(0.05):.3f}  "
          f"median={statistics.median(rs):.3f}  max={rs[-1]:.3f}")
    for k in (0.75, 1.0, 1.2, 1.5):
        n = sum(1 for x in ratios if x[0] < k)
        print(f"  倍率 {k}: 会超预算 {n}/{len(rs)} 条记录")
    # ---------------------------------------------------------------- [G]
    # pwsf/briefing_build.py 用 crypto.buffer_xor_decrypt 逐扇区，
    # pwsf/briefing.py 用 MT19937 手工生成的 keystream；两者必须一致
    from pwsf_briefing_build import crypt, key as bb_key, rewrite, pool_of
    raw = open(DAT, "rb").read()
    mine = bytes(crypt(raw))
    theirs = bytes(load(DAT).data)
    print(f"\n[G] briefing_build.crypt vs briefing.decrypt_sectors: "
          f"{'一致' if mine == theirs else '不一致'}  "
          f"(key={bb_key():#010x} vs {load(DAT).key:#010x})")
    print(f"    crypt(crypt(x)) == x : {bytes(crypt(bytearray(mine))) == raw}")

    # ---------------------------------------------------------------- [H]
    # 端到端：用**原文**走一遍 rewrite（保留尾部），重新加密后应逐字节还原
    data = bytearray(mine)
    n_ok = n_bad = 0
    for r in br.records:
        blob, _need = rewrite(data, r, r.lines)
        if blob is None:
            n_bad += 1
            continue
        p = pool_of(r)
        data[p.table:p.end] = blob
        n_ok += 1
    out = bytes(crypt(bytes(data)))
    print(f"\n[H] 全量 rewrite(原文) + 重新加密：重写 {n_ok}, 跳过 {n_bad}")
    print(f"    与磁盘原文件逐字节相同: {out == raw}")

    print("  最紧的 5 条：")
    for v, r in sorted(ratios, key=lambda x: x[0])[:5]:
        p1, p2, budget = hdr(r, data)
        used = sum(len(s.encode("utf-8")) + 1 for s in r.lines)
        print(f"    {r.off:#x} 组{r.group} {r.lang}  {used}/{budget} "
              f"({v:.3f})  {r.lines[0][:40]!r}")


if __name__ == "__main__":
    sys.exit(main())

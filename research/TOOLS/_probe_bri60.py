"""_probe_bri60.py —— 解密模型 R 落地后的复验（`ANALYSIS/03_codec.md` §11）

`_probe_bri59.py` 证明「密钥流按记录连续」是对的，本探针证明**实现**也是对的，
并把 §11.5 的预算数字换成 R 口径。

    python research\\TOOLS\\_probe_bri60.py

[A] 往返恒等：`decrypt_by_record` -> `crypt_by_record` == 磁盘原文件
[B] en 池预算（R 口径），与 §9.4 的旧口径（358 条 / 252,504 B / 剩 555）对比
[C] 写回正确性（§11.5 第 2 条那个 bug）：挑一条**文本池伸出记录首扇区**的 en
    记录，把译文写进去，分别用「按记录」和旧的「逐扇区」两种方式加密，再用
    游戏那套（按记录）解密读回 —— 前者拿到译文，后者拿到乱码
[D] 恒等变换：不改任何台词（`rebuild` 空译文）时产物与原文逐字节相同
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pwsf import briefing as B                    # noqa: E402
from pwsf import briefing_build as BB             # noqa: E402
from pwsf import config                           # noqa: E402

S = B.SECTOR


def main() -> int:
    config.require_game()
    src = BB.source_path()
    raw = src.read_bytes()
    key = BB.key()
    print(f"{src.name}  {len(raw):#x} B  key={key:#010x}")

    # ---- [A] 往返恒等 ----
    plain = B.decrypt_by_record(raw, key)
    offs = B.record_offsets(plain)
    back = bytes(B.crypt_by_record(plain, key, offs))
    print(f"\n[A] 记录 {len(offs)} 条；按记录重新加密 == 磁盘原文件: "
          f"{back == raw}")
    if back != raw:
        i = next(i for i in range(len(raw)) if back[i] != raw[i])
        print(f"    首个不同字节 {i:#x}: {raw[i]:#04x} -> {back[i]:#04x}")
        return 1
    # 旧逐扇区模型不是磁盘格式（只作自举第一步）
    print(f"    逐扇区重新加密 == 磁盘原文件: "
          f"{bytes(B.decrypt_sectors(plain, key)) == raw}  "
          f"（False 才对：那不是磁盘格式）")

    # ---- [B] en 池预算 ----
    recs = B.iter_records(plain)
    en = [r for r in recs if r.lang == "en"]
    budget = sum(BB.pool_of(r).budget for r in en)
    used = sum(BB.needed(r.lines) for r in en)
    ratios = sorted(BB.pool_of(r).budget / max(1, BB.needed(r.lines))
                    for r in en)
    med = ratios[len(ratios) // 2]
    print(f"\n[B] en 记录 {len(en)} 条（组1 "
          f"{sum(1 for r in en if r.group == 1)} / 组2 "
          f"{sum(1 for r in en if r.group == 2)}）")
    print(f"    池字节 {budget:,}，已用 {used:,}  ->  只剩 {budget - used:,} 字节")
    print(f"    可承受倍率 budget/used: min {ratios[0]:.3f}  中位 {med:.3f}  "
          f"max {ratios[-1]:.3f}")
    print(f"    §9.4 旧口径：358 条 / 252,504 B / 剩 555（旧解密，已作废）")

    # ---- [C] 写回正确性 ----
    cross = [r for r in en
             if (r.v10 + r.off3 - 1) // S != r.off // S and r.n_text > 0]
    print(f"\n[C] en 里文本池伸出记录首扇区的记录: {len(cross)} 条")
    if not cross:
        print("    没有可用于演示的记录")
        return 1
    # 要挑一条**改动字节落在记录首扇区之后**的行：改第 0 行没用，池首多半
    # 还在首扇区内（两个模型在那里给出同一段密钥流，§11.2 的 69.7%）
    pick = None
    for r in sorted(cross, key=lambda r: -(r.v10 + r.off3)):
        pp = BB.pool_of(r)
        nxt = (r.off // S + 1) * S
        for i in range(r.n_text):
            if pp.pool + r.table[i] >= nxt:
                pick = (r, pp, i)
                break
        if pick:
            break
    if pick is None:
        print("    没有可用于演示的记录")
        return 1
    rec, p, line_i = pick
    cn = "中文台词测试\n第二行"
    lines = BB.display_lines(list(rec.lines), rec.n_text)
    lines[line_i] = cn
    need = BB.needed(lines)
    nxt = (rec.off // S + 1) * S
    print(f"    取 {rec.off:#x}（扇区 {rec.sector}，池 {p.pool:#x}..{p.end:#x}，"
          f"跨 {(p.end - 1) // S - rec.off // S + 1} 个扇区）")
    print(f"    改第 {line_i} 行，该行在 {p.pool + rec.table[line_i]:#x} "
          f">= 扇区边界 {nxt:#x} —— 改动字节确实在记录首扇区之后")
    print(f"    预算 {p.budget} B，写入后需要 {need} B -> "
          f"{'装得下' if need <= p.budget else '装不下，换一条'}")
    if need > p.budget:
        return 1

    new = bytearray(plain)
    blob, need = BB.rewrite(plain, rec, lines)
    new[p.table:p.end] = blob

    # 两种加密方式各写一份，都用**游戏那套**（按记录）解密读回
    got = {}
    for tag, enc in (("按记录(R)", B.crypt_by_record(bytes(new), key, offs)),
                     ("逐扇区(旧)", B.decrypt_sectors(bytes(new), key))):
        dec = B.decrypt_by_record(bytes(enc), key)
        r2 = next((x for x in B.iter_records(dec) if x.off == rec.off), None)
        got[tag] = r2.lines[line_i] if r2 and line_i < len(r2.lines) else None
        print(f"    {tag}: 读回第 {line_i} 行 = {got[tag]!r}")

    ok = got["按记录(R)"] == cn and got["逐扇区(旧)"] != cn
    print(f"    -> 按记录写得对、逐扇区写坏: {ok}")

    # 除了这条记录的池窗口，整个文件必须逐字节不变
    same = bytes(new[:p.table]) == plain[:p.table] and \
        bytes(new[p.end:]) == plain[p.end:]
    print(f"    池窗口之外逐字节不变: {same}")

    # ---- [D] 恒等变换 ----
    path, st = BB.rebuild({}, config.LANG_EN, config.BUILD_DIR, verbose=False)
    print(f"\n[D] 空译文 rebuild: {st}")
    print(f"    产物 == 原文: {path.read_bytes() == raw}")
    print(f"    R 下带伪影记录 {st.artifacts} 条（应为 0，§11.4）")

    # ---- [E] R 之后新出现的 codec-budget 溢出 ----
    # 旧模型把 lines[n_text:] 清空成空串（1 字节），R 下那些行是真台词、按英文
    # 原长计费，于是少数记录的池装不下了。逐个列出旧/新口径，交给译者处理。
    from pwsf import po_lint                      # noqa: E402

    rep = po_lint.lint(check_font=False)
    over = BB.overflows(rep.translations)
    if not over:
        print("\n[E] 没有 codec-budget 溢出")
        return 0 if (back == raw and ok and same) else 1
    old_plain = bytes(B.decrypt_sectors(raw, key))       # 旧模型（非磁盘格式）
    old_recs = {r.off: r for r in B.iter_records(old_plain)}
    by_rec = BB.by_record(rep.translations)
    print(f"\n[E] R 下溢出 {len(over)} 条：")
    print(f"    {'记录':<10}{'预算':>7}{'R需要':>8}{'旧需要':>8}"
          f"{'旧伪影行':>9}{'差':>7}")
    for g, off, need, budget in over:
        o = old_recs.get(off)
        if o is None:
            print(f"    {off:#010x}  旧模型下没有这条记录")
            continue
        ol = list(o.lines)
        for line, text in by_rec.get((g, off), {}).items():
            if 0 <= line < len(ol):
                ol[line] = text
        old_need = BB.needed(BB.display_lines(ol, o.n_text))
        print(f"    {off:#010x}{budget:>7}{need:>8}{old_need:>8}"
              f"{o.artifacts:>9}{need - budget:>+7}")

    # 逐行账单：差值是「这条记录要再省出多少字节」，按 (译文-英文) 从大到小
    # 列出最值得动刀的几行 —— 英文部分动不了，只能缩短译文
    print("\n[F] 溢出记录逐行账单（bytes = UTF-8 长度，含 NUL）：")
    new_recs = {r.off: r for r in recs}
    for g, off, need, budget in over:
        r = new_recs.get(off)
        if r is None:
            continue
        by_line = by_rec.get((g, off), {})
        rows = []
        for i, en in enumerate(r.lines):
            cn = by_line.get(i, en)
            rows.append((len(cn.encode()) - len(en.encode()), i, cn, en))
        rows.sort(reverse=True)
        print(f"    codec/{g}/{off:#x}  还差 {need - budget} 字节  "
              f"（{r.n_text} 行，其中 {len(by_line)} 行有译文）")
        for d, i, cn, en in rows[:3]:
            tag = "译文" if i in by_line else "英文"
            print(f"      行 {i:>3} {tag} {d:+5d} B  {cn[:38]!r}")
    return 0 if (back == raw and ok and same) else 1


if __name__ == "__main__":
    raise SystemExit(main())

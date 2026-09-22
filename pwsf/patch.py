r"""Package a build as a redistributable patch, and apply it.

    BUILD/MANIFEST.tsv + BUILD/*  --build-->  BUILD/pwsf_patch/
                                                 files/<game-relative path>
                                                 MANIFEST.tsv
                                                 PATCH.txt, README.txt
                                                 install.bat / restore.bat
                                                 (no Python needed)
                                   then ->  PWSF-<ver>.zip  in the cwd

The payload is the whole replaced file, not a delta.  That is deliberate:

* every one of these files is encrypted (MT19937 XOR) or carries compressed
  payloads inside (SLOT.DAT records, the XPR2 texture), so a binary delta
  against the original is mostly noise -- `_probe_patch1.py` measured the
  real byte churn: SLOT.DAT 17.4% of 544 MB in 109 scattered regions, the
  font atlas 51% of 17 MB in 3,408 runs.  A delta would be neither small
  nor simple.
* "install" is then just `copy`, so a player with no Python can apply it
  from a .bat.

The shipped installer does NOT verify the game's original.  The player is
expected to confirm Steam has the latest clean build first (right-click ->
Properties -> Verify integrity of game files); the installer then backs up
each file (to `*.orig`, `config.BACKUP_SUFFIX`) only if no backup exists yet,
and overwrites.  The dev-side `pwsf.install` keeps the stricter hash gate
(`verify_game=True`) for when you are iterating from the repo.  `*.orig`
backups mean `pwsf.install --restore` and this module undo each other's work.

Usage:
    python -m pwsf.patch --build            # BUILD/ -> BUILD/pwsf_patch/ +
                                            #   PWSF-<ver>.zip in the cwd
    python -m pwsf.patch --install          # apply the package
    python -m pwsf.patch --restore          # put the *.orig backups back
"""

import argparse
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import config
from . import install as inst
from .po_import import MANIFEST, MANIFEST_HEADER

PACKAGE_NAME = "pwsf_patch"
PAYLOAD = "files"
INFO = "PATCH.txt"
README = "README.txt"
FILES_TSV = "files.tsv"           # comma list the static .bats parse

# no-Python path: the installers are static helpers, kept in the repo
# (tools/build/) and copied verbatim into the package.  They read FILES_TSV
# for the per-file dest / payload, so nothing about them is regenerated on
# each build.
BAT_DIR = config.REPO_ROOT / "tools" / "build"
INSTALL_BAT = "install.bat"
RESTORE_BAT = "restore.bat"


def git_describe() -> str:
    """`v<date>+g<short hash>[-dirty]`, or 'unknown' off a checkout."""
    try:
        r = subprocess.run(["git", "describe", "--always", "--dirty",
                            "--abbrev=8"],
                           cwd=str(config.REPO_ROOT), capture_output=True,
                           text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            h = r.stdout.strip()
            return f"{datetime.now(timezone.utc):%Y%m%d}+g{h}"
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def payload_path(dest_rel: str) -> str:
    return f"{PAYLOAD}/{dest_rel}"


# ------------------------------------------------------------------- build

def build(build_dir: Path, pkg_dir: Path, lang: str = "en",
          note: str = "") -> Path:
    items = inst.read_manifest(build_dir)          # validates hashes
    if pkg_dir.exists():
        shutil.rmtree(pkg_dir)
    (pkg_dir / PAYLOAD).mkdir(parents=True)

    rows, copied, total = [MANIFEST_HEADER], 0, 0
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR).as_posix()
        sub = payload_path(rel)
        dst = pkg_dir / sub
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(it.built, dst)
        assert inst.sha256(dst) == it.sha
        rows.append(f"{rel}\t{sub}\t{it.kind}\t{it.size}\t{it.sha}\t"
                    f"{it.orig_sha}")
        copied += 1
        total += it.size

    (pkg_dir / MANIFEST).write_text("\n".join(rows) + "\n", encoding="utf-8")
    version = git_describe()
    (pkg_dir / INFO).write_text(
        info_text(version, items, lang, note, total), encoding="utf-8")
    (pkg_dir / README).write_text(
        readme_text(version, items, lang, total), encoding="utf-8")
    write_files_tsv(pkg_dir / FILES_TSV, items)
    for bat in (INSTALL_BAT, RESTORE_BAT):
        src_bat = BAT_DIR / bat
        if not src_bat.is_file():
            raise SystemExit(f"missing helper {src_bat}; "
                             f"expected the static installers in tools/build/")
        shutil.copy2(src_bat, pkg_dir / bat)

    # 注入 DLL：只有 pwsf.asi 一种形态（伪装成 winmm.dll 会加载在 exe 解密之前，
    # sigscan 扫不到，2026-09-22 实测）。强制按 PWSF_DEBUG=OFF 重编一次，
    # 免得把 --debug-hook 那版发出去。
    inst.build_hook(debug=False)
    hook = inst.find_hook_artifact()
    if hook:
        shutil.copy2(hook, pkg_dir / inst.HOOK_ASI)
        print(f"  hook {hook.name} -> {pkg_dir / inst.HOOK_ASI}")
    else:
        print(f"  hook: {inst.HOOK_DLL} not built, shipping without the "
              f"injection DLL")
    # ASI loader：整包带着，install.bat 只在游戏目录没有 winmm.dll 时才放
    loader = inst.find_loader_artifact()
    if loader:
        shutil.copy2(loader, pkg_dir / inst.HOOK_WINMM)
        print(f"  loader {loader.name} -> {pkg_dir / inst.HOOK_WINMM}")
    else:
        print("  loader: repo carries no ASI loader, shipping without one")

    print(f"  {copied} file(s), {total:,} bytes -> {pkg_dir}")
    print(f"  version {version}")
    return pkg_dir


def write_files_tsv(path: Path, items: list) -> None:
    """Comma-separated `dest,payload` for the static bats.

    No hash columns: the shipped installer does not verify the game's original
    (the player confirms Steam is up to date); it only needs where each file
    goes and where its replacement sits.  Windows paths never contain a comma,
    so `delims=,` parses cleanly.
    """
    lines = ["dest,payload"]
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR).as_posix()
        lines.append(f"{rel},{payload_path(rel)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def zip_package(pkg_dir: Path, level: int = 6,
                out_dir: Path | None = None) -> Path:
    """Zip the package into ``out_dir`` (default: current working directory)
    as ``PWSF-<ver>.zip`` where ``<ver>`` is the git describe string.
    """
    out_dir = out_dir or Path.cwd()
    ver = git_describe()
    dst = out_dir / f"PWSF-{ver}.zip"
    if dst.exists():
        dst.unlink()
    files = sorted(p for p in pkg_dir.rglob("*") if p.is_file())
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED,
                         compresslevel=level) as z:
        for p in files:
            print(f"  + {p.relative_to(pkg_dir).as_posix()} "
                  f"({p.stat().st_size:,} B)")
            z.write(p, Path(pkg_dir.name) / p.relative_to(pkg_dir))
    print(f"  {dst}  {dst.stat().st_size:,} bytes "
          f"({100.0 * dst.stat().st_size / max(1, sum(p.stat().st_size for p in files)):.1f}% "
          f"of the payload)")
    return dst


# ------------------------------------------------------------------ texts

def info_text(version: str, items: list, lang: str, note: str,
              total: int) -> str:
    lines = [
        "PWSF — Peace Walker Sans Frontiers",
        f"patch version : {version}",
        f"built at      : {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}",
        f"language slot : {lang}",
        f"files         : {len(items)}   payload {total:,} bytes",
        f"toolchain     : python {sys.version.split()[0]}",
    ]
    if note:
        lines.append(f"note          : {note}")
    lines += ["", "contents (dest, kind, size, sha256 of the patched file, "
                   "sha256 of the original it was built from)", ""]
    for it in items:
        rel = it.dest.relative_to(config.GAME_DIR).as_posix()
        lines.append(f"  {rel}")
        lines.append(f"      {it.kind:8} {it.size:>12,}  {it.sha}")
        lines.append(f"      {'':8} {'original':>12}  {it.orig_sha}")
    lines += ["", "sha256 of this PATCH.txt is for manual spot-checks only; "
                   "the shipped installer does not verify the game original.",
              ""]
    return "\n".join(lines) + "\n"


def readme_text(version: str, items: list, lang: str, total: int) -> str:
    kinds = {}
    for it in items:
        kinds[it.kind] = kinds.get(it.kind, 0) + 1
    kinds_txt = ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items()))
    return "\n".join([
        "PWSF 汉化补丁 — 食用说明",
        "=" * 60,
        f"版本 {version}   语言槽 {lang}   {len(items)} 个文件（{kinds_txt}）"
        f"   共 {total:,} 字节",
        "",
        "【装之前】",
        "  1. 先确认游戏是最新原版：Steam 库里右键 MGS PW → 属性 →",
        "     「已安装的文件」→ 验证游戏文件的完整性。安装器不再帮你校验",
        "     原版哈希，版本对不上会把错的文件备份成 *.orig，后续还原/再提取",
        "     都会出错。",
        "  2. 每个被替换的文件都会在旁边留一份 *.orig。它是还原的唯一依据，",
        "     也是下次重新导出英文语料的来源，别删。",
        "  3. 不需要关 Steam；装完直接开游戏即可。",
        "",
        "【没有 Python 怎么装】",
        "  双击 install.bat，按提示把游戏目录（含 FONT 和 MLG 的 mgspw 文件夹）",
        "  粘贴进去回车就行。它会装 pwsf.asi（字体注入），并在游戏目录还没有",
        "  ASI loader 时补一个 winmm.dll —— 已经有的话原样保留，不动别的 mod。",
        "  它不自动找 Steam、也不读任何配置文件，每次都问你。",
        "",
        "【有 Python 怎么装】",
        "  在本仓库根目录：",
        "    python -m pwsf.patch --install",
        "",
        "【还原】",
        "  restore.bat（带 Python 就 python -m pwsf.patch --restore）",
        "  会把 *.orig 拷回去，并删掉装进去的注入 DLL。",
        "  想连备份一起清掉，手动删 *.orig。",
        "",
        "【游戏更新后】",
        "  先还原，再让 Steam 更新，然后重新打补丁：更新会覆盖原文件，",
        "  *.orig 不受影响，重装补丁即可。",
        "",
        "【这一包里有什么】",
        "  files\\  按游戏目录原样摆放的替换文件",
        "  pwsf.asi   字体注入 DLL（由 ASI loader 加载）",
        "  winmm.dll  自带的 ASI loader（仅当游戏目录没有时才装）",
        "  MANIFEST.tsv  每个文件的目标路径 / 补丁后哈希 / 原版哈希",
        "  PATCH.txt     版本、构建时间、逐文件哈希（人工核对用）",
        "",
        "注意：files\\ 里是【由游戏原始文件改出来的】数据，不是新增素材。",
        "",
    ]) + "\n"


# --------------------------------------------------------------- bat files
#
# The installers are static helpers in tools/build/ (see write_files_tsv for
# the FILES_TSV they consume); nothing here generates script text.

# ------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--build-dir", type=Path, default=config.BUILD_DIR)
    ap.add_argument("--pkg-dir", type=Path,
                    default=config.BUILD_DIR / PACKAGE_NAME)
    ap.add_argument("--build", action="store_true",
                    help="package the build and write PWSF-<ver>.zip into the "
                         "current working directory")
    ap.add_argument("--zip-level", type=int, default=6)
    ap.add_argument("--install", action="store_true")
    ap.add_argument("--restore", action="store_true")
    ap.add_argument("--lang", default="en",
                    help="language slot the build writes into; recorded in "
                         "PATCH.txt / README.txt only")
    ap.add_argument("--note", default="", help="free-form line in PATCH.txt")
    ap.add_argument("--hook", choices=inst.HOOK_MODES, default="asi",
                    help="with --install, deploy the package's pwsf.asi "
                         "(default), adding the bundled ASI loader only when "
                         "the game directory has none")
    args = ap.parse_args()

    if args.build:
        if not args.build_dir.is_dir():
            raise SystemExit(f"no build directory {args.build_dir}\n"
                             f"run: python -m pwsf.po_import")
        print(f"packaging {args.build_dir} -> {args.pkg_dir}")
        pkg = build(args.build_dir, args.pkg_dir, args.lang, args.note)
        zip_dst = zip_package(pkg, args.zip_level)
        print(f"  zip at {zip_dst}")
        return

    config.require_game()
    if args.install:
        # shipped installer: no game-original hash gate (player confirms Steam
        # is up to date); just back up + overwrite.
        inst.install(inst.read_manifest(args.pkg_dir), verify_game=False)
        inst.deploy_hook(args.hook, True)
        print("restore with: python -m pwsf.patch --restore")
    elif args.restore:
        inst.restore(inst.read_manifest(args.pkg_dir))
        inst.remove_hook()
    else:
        inst.status(inst.read_manifest(args.pkg_dir))
        print("\n--install to apply, --restore to undo")


if __name__ == "__main__":
    main()

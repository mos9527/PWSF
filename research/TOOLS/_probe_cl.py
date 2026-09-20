"""Is `cl` usable from Python, and can it build the launcher shim?

Steam runs `MGS_PW/launcher/launcher.exe` (a Unity IL2CPP front-end).  The plan
is to stand in for it with a tiny C program that starts the real game, so we
need a compiler at build time.  Evidence that
    cmd /c '"...VsDevCmd.bat" -no_logo -arch=x64 && cl ...'
works from a plain subprocess, i.e. that pwsf.launch can do it unattended.
"""

import os
import pathlib
import subprocess
import sys

CANDIDATES = [
    r"C:\Program Files\Microsoft Visual Studio\18\Community"
    r"\Common7\Tools\VsDevCmd.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community"
    r"\Common7\Tools\VsDevCmd.bat",
]

SRC = r"""
#include <windows.h>
int wmain(void) { return 0; }
"""


def main() -> None:
    tmp = pathlib.Path(os.environ.get("TEMP", ".")) / "pwsf_cl_probe"
    tmp.mkdir(exist_ok=True)
    (tmp / "t.c").write_text(SRC, encoding="ascii")

    bat = next((p for p in CANDIDATES if pathlib.Path(p).is_file()), None)
    print(f"VsDevCmd: {bat}")
    if not bat:
        print("no Visual Studio found")
        return

    # cmd /c mis-parses a quoted path followed by && (it strips the outer
    # quotes), so drive it through a generated .bat instead -- that is also
    # what pwsf.launch does.
    (tmp / "build.bat").write_text(
        f'@echo off\r\n'
        f'call "{bat}" -no_logo -arch=x64\r\n'
        f'cl /nologo /W3 /O2 /Fe:"{tmp / "t.exe"}" "{tmp / "t.c"}"\r\n',
        encoding="ascii")
    r = subprocess.run(["cmd", "/c", str(tmp / "build.bat")],
                       capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if line.strip():
            print("  |", line.rstrip())
    print(f"\nreturncode={r.returncode}  exe={(tmp / 't.exe').is_file()}")
    if (tmp / "t.exe").is_file():
        print("OK -- cl can be driven unattended")


if __name__ == "__main__":
    main()

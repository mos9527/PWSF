/* Stand-in for the Steam launcher of MGS_PW.
 *
 * Steam launches  <install>\launcher\launcher.exe  -- a Unity IL2CPP front
 * end that only ends up starting the real game.  This replaces it: read
 * pwsf_launch.ini next to ourselves, chdir to the game directory and start
 * the game, then wait for it so Steam still shows the game as running.
 *
 * The launcher itself is deliberately NOT reverse engineered; nothing here
 * depends on what it did, only on where the game lives.
 *
 * Built by `python -m pwsf.launch --install-shim`; see pwsf/launch.py.
 *
 * ini (all optional, defaults below):
 *     [launch]
 *     dir=..\mgspw                              ; relative to this .exe
 *     exe=METAL GEAR SOLID PEACE WALKER.exe
 *     args=-lan en -region eu -selfregion EU -ctrltype XS
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#define CCH 4096

static const wchar_t *DEF_DIR  = L"..\\mgspw";
static const wchar_t *DEF_EXE  = L"METAL GEAR SOLID PEACE WALKER.exe";
static const wchar_t *DEF_ARGS = L"-lan en -region eu -selfregion EU "
                                 L"-ctrltype XS";

/* not named logf: that is an intrinsic in math.h and cl rejects the shadow */
static void shim_log(const wchar_t *path, const wchar_t *fmt, ...)
{
    FILE *f = NULL;
    if (_wfopen_s(&f, path, L"a,ccs=UTF-8") == 0 && f) {
        va_list ap;
        va_start(ap, fmt);
        vfwprintf_s(f, fmt, ap);
        va_end(ap);
        fclose(f);
    }
}

/* /subsystem:windows: no console window should flash when Steam starts us */
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrev, PWSTR cmdline_in,
                    int show)
{
    wchar_t self[CCH], ini[CCH], reldir[CCH], exe[CCH], args[CCH];
    wchar_t combined[CCH], gamedir[CCH], cmdline[CCH], logpath[CCH];

    (void)hInst;
    (void)hPrev;
    (void)cmdline_in;
    (void)show;

    if (!GetModuleFileNameW(NULL, self, CCH))
        return 2;
    wchar_t *slash = wcsrchr(self, L'\\');
    if (slash)
        *slash = L'\0';

    swprintf_s(ini, CCH, L"%ls\\pwsf_launch.ini", self);
    swprintf_s(logpath, CCH, L"%ls\\pwsf_launch.log", self);

    GetPrivateProfileStringW(L"launch", L"dir", DEF_DIR, reldir, CCH, ini);
    GetPrivateProfileStringW(L"launch", L"exe", DEF_EXE, exe, CCH, ini);
    GetPrivateProfileStringW(L"launch", L"args", DEF_ARGS, args, CCH, ini);

    /* the working directory matters: the game looks its font up as ".".
       `dir` is normally relative to this .exe ("..\mgspw"); an absolute one
       is taken as-is so the ini stays usable by hand. */
    if (reldir[0] == L'\\' || (wcslen(reldir) > 1 && reldir[1] == L':')) {
        wcsncpy_s(gamedir, CCH, reldir, _TRUNCATE);
    } else {
        swprintf_s(combined, CCH, L"%ls\\%ls", self, reldir);
        if (!GetFullPathNameW(combined, CCH, gamedir, NULL)) {
            shim_log(logpath, L"bad dir: %ls\n", combined);
            return 2;
        }
    }
    swprintf_s(cmdline, CCH, L"\"%ls\\%ls\" %ls", gamedir, exe, args);

    SetCurrentDirectoryW(gamedir);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    shim_log(logpath, L"launching %ls\n", cmdline);
    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, gamedir,
                        &si, &pi)) {
        shim_log(logpath, L"CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    shim_log(logpath, L"exited with %lu\n", code);
    return (int)code;
}

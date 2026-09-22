// PWSF · 字体路线 A 注入 DLL
//
// 目标：让走小字体的界面（如 DATABASE 人员档案）也能出全字库汉字。
// 做法（两条一起）：
//   1. 数据侧：000ebbe8.xpr 被写成 0007ccd8.xpr 的字节副本（po_import 的
//      small-font mirror），小字体文件本身就是那张全字库图集；
//   2. 这里：detour font_load_xpr，只把 2048x1024 的加载尺寸改成 4096x4096，
//      资源名和其它参数一律不动 —— 改名字会撞上同名资源重入，2026-09-22 崩过。
// sigscan 实测命中 base+0x42E20（文档记的 0x140042C60 偏了 0x1C0，以实测为准）。
//
// 构建：产物恒为 pwsf.dll（winmm 导出被伪装转发到系统 winmm，ASI loader 也能扫到）。
// 部署：名字由安装侧决定 —— pwsf.install --hook winmm（默认，装成 winmm.dll）
//       或 --hook asi（装成 pwsf.asi），都落到游戏 exe 同目录（…\MGS_PW\mgspw\）。
//
// 诊断：-DPWSF_DEBUG=ON 会 AllocConsole 并 printf 每一步（默认关，发布包不弹
//       控制台；排查时重编加这个选项）。不写日志文件。
//
// 调用约定：font_load_xpr(font, name, w, h)  ->  RCX=font, RDX=name, R8=w, R9=h
//          返回 int（版本不符时返回 0）。

#define HOOKLIB_MODULE_NAME "METAL GEAR SOLID PEACE WALKER.exe"
// HOOKLIB_NO_DLL_SPOOFING 故意不定义：保留 winmm 伪装导出，不影响 loader。
#include <hooklib.hpp>
#include <cstring>
#include <cstdio>
#include <cwchar>

#ifdef PWSF_DEBUG
#define PWSF_LOG(fmt, ...) \
    do { printf("[pwsf] " fmt "\n", __VA_ARGS__); fflush(stdout); } while (0)
static void pwsfConsole()
{
    AllocConsole();
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
}
#else
#define PWSF_LOG(fmt, ...) ((void)0)
#endif

// 实测地址（2026-09-22 控制台日志）：模块基址 + 0x42E20。给 sigscan 当 hint：
// 命中就直接返回，不再依赖 GetModuleInformation。ASLR 重定位时这里不命中，
// 会自动退回全模块扫描（hooklib.hpp 的 _moduleInfo 越界已修，那条路也稳）。
static inline uintptr_t pwsfModuleBase()
{
    return reinterpret_cast<uintptr_t>(GetModuleHandleA(HOOKLIB_MODULE_NAME));
}
#define FONT_LOAD_XPR_HINT (pwsfModuleBase())

// ---- sigscan: font_load_xpr（现行构建实测 RVA 0x42E20）-------------------------
// 40 55 53 56 57 41 54 41 55 41 56 41 57   push rbp/rbx/rsi/rdi/r12-r15 (8 个)
// 48 8D 6C 24 ??                            lea  rbp,[rsp-XX]   (帧偏移通配)
// 48 81 EC C8 00 00 00                      sub  rsp,0C8h
// 48 8B 05 ?? ?? ?? ??                       mov  rax,[rip+disp]
// 通配字节为 lea 的 disp8（E1）。28 字节（含 1 通配）在整模块内唯一。
HOOKLIB_SIG_SCAN(fontLoadXpr, FONT_LOAD_XPR_HINT,
    "\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57"
    "\x48\x8D\x6C\x24\xE1"
    "\x48\x81\xEC\xC8\x00\x00\x00"
    "\x48\x8B\x05",
    "xxxxxxxxxxxxxxxxx?xxxxxxxxxx");

// ---- detour ----------------------------------------------------------------
HOOKLIB_HOOK(int, __fastcall, font_load_xpr, fontLoadXprAddr,
    void* font, const char* name, int w, int h)
{
    // 小字体图集：磁盘上 000ebbe8.xpr 已是 0007ccd8.xpr 的字节副本，这里只把
    // 2048x1024 的加载尺寸改成 4096x4096；名字和其它参数一个字节都不动。
    if (w == 2048 && h == 1024) {
        PWSF_LOG("font_load_xpr name=\"%s\" %dx%d -> %dx%d (size only)",
                 name ? name : "(null)", w, h, 4096, 4096);
        int r = originalfont_load_xpr(font, name, 4096, 4096);
        PWSF_LOG("  -> ret=%d", r);
        return r;
    }
    PWSF_LOG("font_load_xpr name=\"%s\" %dx%d (passthrough)",
             name ? name : "(null)", w, h);
    return originalfont_load_xpr(font, name, w, h);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
#ifdef PWSF_DEBUG
        pwsfConsole();
#endif
        PWSF_LOG("DLL_PROCESS_ATTACH, hModule=%p", (void*)hModule);

        wchar_t selfPath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(hModule, selfPath, MAX_PATH))
            PWSF_LOG("dll = %ls", selfPath);

        wchar_t base[MAX_PATH] = { 0 };
        if (!GetModuleBaseNameW(GetCurrentProcess(), NULL, base, MAX_PATH))
            wcscpy_s(base, L"<GetModuleBaseNameW failed>");
        PWSF_LOG("main module base name = \"%ls\"", base);

        if (wcscmp(base, L"METAL GEAR SOLID PEACE WALKER.exe") != 0) {
            PWSF_LOG("process name mismatch -> hook NOT installed");
            return TRUE;
        }

        HMODULE target = GetModuleHandleA(HOOKLIB_MODULE_NAME);
        void* addr = fontLoadXpr();          // cached scan; rescans if it was 0
        PWSF_LOG("target module \"%s\" = %p", HOOKLIB_MODULE_NAME, (void*)target);
        PWSF_LOG("sigscan font_load_xpr = %p (base + 0x%llX)",
                 addr, (unsigned long long)((char*)addr - (char*)target));

        if (addr) {
            // 静态初始化那时若没扫到，originalfont_load_xpr 会是 0，detour 前补上
            originalfont_load_xpr =
                reinterpret_cast<decltype(originalfont_load_xpr)>(addr);
            HOOKLIB_INSTALL_HOOK(font_load_xpr);
            PWSF_LOG("hook installed");
        } else {
            PWSF_LOG("sigscan FAILED -> hook NOT installed (deploy as "
                     "pwsf.asi: winmm.dll loads during import resolution, "
                     "before the exe is decrypted)");
        }
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        PWSF_LOG("DLL_PROCESS_DETACH");
    }
    return TRUE;
}

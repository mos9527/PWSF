// PWSF · 字体路线 A 注入 DLL
//
// 目标：让走小字体的界面（如 DATABASE 人员档案）也能出全字库汉字，且排版零变化。
// 做法：sigscan 到 font_load_xpr @ 0x140042C60，detour 它；当小字体（000ebbe8.xpr /
// 001cbbd1.xpr）被加载时，把资源名与图集尺寸重定向到大字体的全字库
// （0007ccd8.xpr / 00c7c9f9.xpr，4096x4096）。等价于改 exe 的三处补丁
// （ANALYSIS/05_font.md §13.7 / TOOLS/_probe_font_redirect.py），但不碰磁盘文件
// —— Steam 加密的 exe 在运行时已解密，内存里 patch 即可。
//
// 构建：默认产出 winmm.dll（winmm 导出被伪装转发到系统 winmm，ASI loader 也能扫到）；
//       cmake -DPWSF_ASI=ON 产出 pwsf.asi。
// 部署：把产物（winmm.dll 或 pwsf.asi）放到游戏 exe 同目录（…\MGS_PW\mgspw\）。
//
// 调用约定：font_load_xpr(font, name, w, h)  ->  RCX=font, RDX=name, R8=w, R9=h
//          返回 int（版本不符时返回 0）。

#define HOOKLIB_MODULE_NAME "METAL GEAR SOLID PEACE WALKER.exe"
// HOOKLIB_NO_DLL_SPOOFING 故意不定义：保留 winmm 伪装导出，不影响 loader。
#include <hooklib.hpp>
#include <cstring>

// ---- sigscan: font_load_xpr @ 0x140042C60 -------------------------------------
// 40 55 53 56 57 41 54 41 55 41 56 41 57   push rbp/rbx/rsi/rdi/r12-r15 (8 个)
// 48 8D 6C 24 ??                            lea  rbp,[rsp-XX]   (帧偏移通配)
// 48 81 EC C8 00 00 00                      sub  rsp,0C8h
// 48 8B 05 ?? ?? ?? ??                       mov  rax,[rip+disp]
// 通配字节为 lea 的 disp8（E1）。28 字节（含 1 通配）在整模块内唯一。
HOOKLIB_SIG_SCAN(fontLoadXpr, NULL,
    "\x40\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57"
    "\x48\x8D\x6C\x24\xE1"
    "\x48\x81\xEC\xC8\x00\x00\x00"
    "\x48\x8B\x05",
    "xxxxxxxxxxxxxxxxx?xxxxxxxxxx");

// ---- detour ----------------------------------------------------------------
HOOKLIB_HOOK(int, __fastcall, font_load_xpr, fontLoadXprAddr,
    void* font, const char* name, int w, int h)
{
    if (name) {
        // 小字体（默认 / 欧美）-> 大字体的全字库 atlas
        if (std::strstr(name, "000ebbe8")) {
            return originalfont_load_xpr(font, "0007ccd8.xpr", 4096, 4096);
        }
        // 小字体（日语）-> 大字体的 JP atlas（尽力；JP 文件未随包发布）
        if (std::strstr(name, "001cbbd1")) {
            return originalfont_load_xpr(font, "00c7c9f9.xpr", 4096, 4096);
        }
    }
    return originalfont_load_xpr(font, name, w, h);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    if (HOOKLIB_IS_PROCESS(L"METAL GEAR SOLID PEACE WALKER.exe")) {
        switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        {
#ifdef _DEBUG
            AllocConsole();
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
#endif
            if (fontLoadXprAddr) {
                HOOKLIB_INSTALL_HOOK(font_load_xpr);
            }
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
        }
    }
    return TRUE;
}

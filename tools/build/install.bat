@echo off
chcp 65001 >nul
setlocal EnableExtensions
rem PWSF — Peace Walker Sans Frontiers, 汉化补丁安装器（静态 helper）
rem 用法: 双击运行后按提示粘贴游戏目录（含 FONT 和 MLG 的 mgspw）回车，
rem       装 pwsf.asi；游戏目录没有 ASI loader 时才补一个 winmm.dll
rem 依赖同目录的 files.tsv（dest,payload）、files\ 目录、pwsf.asi 与 winmm.dll
rem 不校验游戏原版：装之前请自己确认 Steam 游戏是最新原版
set "SRC=%~dp0"

set /p GDIR=游戏目录（含 FONT 和 MLG 的 mgspw）: 
set "GDIR=%GDIR:"=%"
if "%GDIR:~-1%"=="\" set "GDIR=%GDIR:~0,-1%"
if not exist "%GDIR%\FONT\" echo 不是游戏目录: %GDIR% & exit /b 1
if not exist "%GDIR%\MLG\" echo 不是游戏目录: %GDIR% & exit /b 1

echo 游戏目录: %GDIR%
echo 正在安装 PWSF 补丁...
for /f "usebackq skip=1 tokens=1,2 delims=," %%a in ("%SRC%files.tsv") do call :apply "%%a" "%%b" || goto :fail
call :hook || goto :fail
echo.
echo 完成。不想要了就跑 restore.bat。
endlocal
exit /b 0

:fail
echo.
echo 安装中断：看上面带 [失败] 的那一行。
endlocal
exit /b 1

:apply
set "REL=%~1"
set "REL=%REL:/=\%"
set "PAY=%~2"
set "PAY=%PAY:/=\%"
set "LIVE=%GDIR%\%REL%"
set "BAK=%LIVE%.orig"
if not exist "%SRC%%PAY%" echo   [缺补丁文件] %PAY% & exit /b 1
for %%d in ("%LIVE%") do set "DSTDIR=%%~dpd"
if not exist "%DSTDIR%" mkdir "%DSTDIR%" >nul 2>nul
if not exist "%BAK%" if exist "%LIVE%" copy /y "%LIVE%" "%BAK%" >nul
if errorlevel 1 echo   [备份失败] %REL% & exit /b 1
copy /y "%SRC%%PAY%" "%LIVE%" >nul
if errorlevel 1 echo   [写入失败] %REL% & exit /b 1
echo   [已装] %REL%
exit /b 0

:hook
rem 注入 DLL：只出 pwsf.asi 一种 —— 伪装 winmm.dll 会加载在 exe 解密之前，扫不到
if not exist "%SRC%pwsf.asi" (echo 这一包没带注入 DLL（pwsf.asi），跳过字体 hook。 & exit /b 0)
copy /y "%SRC%pwsf.asi" "%GDIR%\pwsf.asi" >nul
if errorlevel 1 (echo   [注入失败] pwsf.asi & exit /b 1)
echo   [已装注入 DLL] pwsf.asi
rem ASI loader：只在游戏目录还没有 winmm.dll 时才放，免得抢别的 mod 的 loader
if exist "%GDIR%\winmm.dll" (echo   [保留] winmm.dll（已有 ASI loader，不动） & exit /b 0)
if not exist "%SRC%winmm.dll" (echo   [警告] 包里没有 ASI loader，pwsf.asi 不会被加载。 & exit /b 0)
copy /y "%SRC%winmm.dll" "%GDIR%\winmm.dll" >nul
if errorlevel 1 (echo   [loader 失败] winmm.dll & exit /b 1)
echo   [已装 ASI loader] winmm.dll
exit /b 0

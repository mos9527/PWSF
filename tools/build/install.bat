@echo off
chcp 65001 >nul
setlocal EnableExtensions
rem PWSF — Peace Walker Sans Frontiers, 汉化补丁安装器（静态 helper）
rem 用法: 双击运行后按提示粘贴游戏目录（含 FONT 和 MLG 的 mgspw）回车，
rem       再选注入 DLL 装成 winmm.dll（默认）/ pwsf.asi / none
rem 依赖同目录的 files.tsv（dest,payload）、files\ 目录和 pwsf.dll（可选）
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
rem 注入 DLL：包里只带一个 pwsf.dll，装成什么名字由用户选（默认 winmm.dll）
if not exist "%SRC%pwsf.dll" (echo 这一包没带注入 DLL（pwsf.dll），跳过字体 hook。 & exit /b 0)
set "HOOKMODE=winmm"
set /p "HOOKMODE=注入 DLL 装成 [winmm/asi/none]（回车=winmm）: "
if /i "%HOOKMODE%"=="none" (echo 跳过注入 DLL。 & exit /b 0)
if /i "%HOOKMODE%"=="asi" (set "HOOKNAME=pwsf.asi") else (set "HOOKNAME=winmm.dll")
if "%HOOKNAME%"=="pwsf.asi" (if exist "%GDIR%\winmm.dll" del /q "%GDIR%\winmm.dll" >nul) else (if exist "%GDIR%\pwsf.asi" del /q "%GDIR%\pwsf.asi" >nul)
copy /y "%SRC%pwsf.dll" "%GDIR%\%HOOKNAME%" >nul
if errorlevel 1 (echo   [注入失败] %HOOKNAME% & exit /b 1)
echo   [已装注入 DLL] %HOOKNAME%
exit /b 0

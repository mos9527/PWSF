@echo off
chcp 65001 >nul
setlocal EnableExtensions
rem PWSF — Peace Walker Sans Frontiers, 汉化补丁还原器（静态 helper）
rem 用法: 双击运行后按提示粘贴游戏目录（含 FONT 和 MLG 的 mgspw）回车
rem 把每个被替换文件的 *.orig 拷回游戏文件
set "SRC=%~dp0"

set /p GDIR=游戏目录（含 FONT 和 MLG 的 mgspw）: 
set "GDIR=%GDIR:"=%"
if "%GDIR:~-1%"=="\" set "GDIR=%GDIR:~0,-1%"
if not exist "%GDIR%\FONT\" echo 不是游戏目录: %GDIR% & exit /b 1
if not exist "%GDIR%\MLG\" echo 不是游戏目录: %GDIR% & exit /b 1

echo 游戏目录: %GDIR%
echo 正在还原原版（*.orig -^> 游戏文件）...
for /f "usebackq skip=1 tokens=1 delims=," %%a in ("%SRC%files.tsv") do call :undo "%%a" || goto :fail
echo.
echo 已还原。*.orig 备份保留着，确认没问题后可以手动删。
endlocal
exit /b 0

:fail
echo.
echo 还原中断：看上面带 [还原失败] 的那一行。
endlocal
exit /b 1

:undo
set "REL=%~1"
set "REL=%REL:/=\%"
set "LIVE=%GDIR%\%REL%"
set "BAK=%LIVE%.orig"
if not exist "%BAK%" echo   [没备份] %~1 本就是原版？ & exit /b 0
copy /y "%BAK%" "%LIVE%" >nul
if errorlevel 1 echo   [还原失败] %~1 & exit /b 1
echo   [已还原] %~1
exit /b 0

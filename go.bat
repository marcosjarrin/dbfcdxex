@echo off
rem -----------------------------------------------------------------------
rem  go.bat  -  Build dbfcdxex.lib (static library)
rem
rem  Output: dbfcdxex.lib  (place it in your Harbour lib folder or link
rem          it directly with -ldbfcdxex in your project .hbp)
rem
rem  Requires:
rem    - Harbour installed at c:\harbour
rem    - Visual Studio 2022 Community (or any MSVC 64-bit toolchain)
rem -----------------------------------------------------------------------
cd /d "%~dp0"
set "VSINSTALLER=C:\Program Files (x86)\Microsoft Visual Studio\Installer"
set "PATH=%VSINSTALLER%;%PATH%"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64

set "hbdir=c:\harbour"
set "include=%include%;%hbdir%\include"
set "lib=%lib%;%hbdir%\lib"

c:\harbour\bin\hbmk2.exe dbfcdxex.hbp -comp=msvc64
echo EXITCODE=%ERRORLEVEL%
if errorlevel 1 pause

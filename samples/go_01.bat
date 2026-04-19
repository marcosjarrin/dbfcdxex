@echo off
cd /d "%~dp0"
set "VSINSTALLER=C:\Program Files (x86)\Microsoft Visual Studio\Installer"
set "PATH=%VSINSTALLER%;%PATH%"
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64
set "hbdir=c:\harbour"
set "include=%include%;%hbdir%\include"
set "lib=%lib%;%hbdir%\lib"
c:\harbour\bin\hbmk2.exe sample01.hbp -comp=msvc64
if errorlevel 1 ( echo BUILD FAILED & pause & goto :eof )
sample01.exe

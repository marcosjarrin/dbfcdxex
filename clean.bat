@echo off
rem -----------------------------------------------------------------------
rem  clean.bat  -  Remove all generated files
rem
rem  Removes:
rem    - dbfcdxex.lib          (root, built by go.bat)
rem    - samples\*.exe         (built by go_xx.bat)
rem    - samples\*.dbf         (created at runtime by samples)
rem    - samples\*.cdx         (created at runtime by samples)
rem    - samples\*.fpt         (created at runtime by samples)
rem    - samples\.hbmk\        (hbmk2 incremental build cache)
rem
rem  Does NOT touch:
rem    - src\                  (source files)
rem    - data\                 (test data)
rem    - samples\*.prg         (source files)
rem    - samples\*.hbp         (project files)
rem    - samples\*.bat         (build scripts)
rem    - samples\*.md          (documentation)
rem -----------------------------------------------------------------------
cd /d "%~dp0"

echo Cleaning root...
if exist dbfcdxex.lib   del /q dbfcdxex.lib

echo Cleaning samples\...
if exist samples\*.exe  del /q samples\*.exe
if exist samples\*.dbf  del /q samples\*.dbf
if exist samples\*.cdx  del /q samples\*.cdx
if exist samples\*.fpt  del /q samples\*.fpt
if exist samples\*.txt  del /q samples\*.txt
if exist samples\*.log  del /q samples\*.log
if exist samples\.hbmk  rd  /s /q samples\.hbmk

echo Done.

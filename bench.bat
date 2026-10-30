@echo off
REM ============================================================================
REM  How fast is the forensics engine on this machine? One command, one report.
REM  Measures the digests, E01 reading and every parser; writes the numbers to
REM  logs\bench\bench_<date>.txt in this folder. Scratch files go in bench_tmp\
REM  here and are deleted at the end. Nothing is written to C:\ or the profile.
REM  Takes about a minute. Hand the report to Claude to decide what (if
REM  anything) is worth a C accelerator.
REM ============================================================================
setlocal
cd /d "%~dp0"
set "PY="
if exist "..\ATK\envs\atk_core\Scripts\python.exe" set "PY=..\ATK\envs\atk_core\Scripts\python.exe"
if not defined PY if exist "..\ATK\.python\python.exe" set "PY=..\ATK\.python\python.exe"
if not defined PY (
    where py >nul 2>&1 && set "PY=py -3"
)
if not defined PY set "PY=python"
set "PYTHONDONTWRITEBYTECODE=1"
%PY% tools\bench.py
if errorlevel 1 (
    echo.
    echo [ERR] The benchmark stopped - the lines above say where.
    pause
    exit /b 1
)
echo.
pause
endlocal

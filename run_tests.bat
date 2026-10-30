@echo off
REM ============================================================================
REM  Every forensics test in one go: the engine's whole suite, then ATK's
REM  Digital Forensics tests (with ATK's own Python), then - with /all - the
REM  rest of ATK's suite too. One line per part and a TOTAL at the bottom;
REM  everything else goes to logs\tests\tests_<date>.txt in this folder.
REM
REM    run_tests.bat         engine + ATK's forensics tests (a few minutes)
REM    run_tests.bat /all    ... and the whole ATK suite (much longer)
REM
REM  The tests' scratch files go in test_tmp\ here and are deleted at the
REM  end: nothing is written to C:\ or your profile. Hand the log to
REM  Claude if anything fails.
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
%PY% tools\run_tests.py %*
set "RC=%ERRORLEVEL%"
echo.
pause
endlocal & exit /b %RC%

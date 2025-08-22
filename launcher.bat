@echo off
REM BLRCS Launcher

echo BLRCS
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found
    pause
    exit /b 1
)

if not exist ".venv" (
    python -m venv .venv
)

call .venv\Scripts\activate.bat
pip install -q -r requirements.txt 2>nul

echo 1. Desktop App
echo 2. Web Server
echo 3. Test
echo 4. Exit
echo.

set /p choice="Select: "

if "%choice%"=="1" python desktop.py
if "%choice%"=="2" python main.py
if "%choice%"=="3" python -m pytest test.py -v
if "%choice%"=="4" exit

deactivate
pause

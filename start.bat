@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
title 威胁情报分析平台

echo ========================================
echo   威胁情报自动化提取与分析平台
echo ========================================
echo.
echo [Working Dir] %cd%
echo.

:: ====== Python ======
set PY=
python3 --version >nul 2>&1 && set PY=python3
if "%PY%"=="" python --version >nul 2>&1 && set PY=python
if "%PY%"=="" (
    echo [ERROR] Python 3.10+ not found
    pause & exit /b 1
)
echo [OK] %PY%

:: ====== Node ======
node --version >nul 2>&1 || (
    echo [ERROR] Node.js 20+ not found
    pause & exit /b 1
)
echo [OK] Node
echo.

:: ====== .env ======
if not exist "backend\.env" (
    echo [Setup] Creating backend\.env ...
    copy "backend\.env.example" "backend\.env" >nul
    echo [Setup] Done. Edit backend\.env to set DEEPSEEK_API_KEY
    echo.
)

:: ====== pip install ======
%PY% -c "import fastapi" >nul 2>&1 || (
    echo [Install] Python dependencies...
    %PY% -m pip install -r "backend\requirements.txt" -q || (
        echo [ERROR] pip install failed
        pause & exit /b 1
    )
    echo [OK] Python deps installed
)

:: ====== npm install ======
if not exist "frontend\node_modules" (
    echo [Install] npm dependencies...
    pushd frontend
    call npm install || (
        popd
        echo [ERROR] npm install failed
        pause & exit /b 1
    )
    popd
    echo [OK] npm deps installed
)

echo.
echo ========================================
echo   Starting services...
echo   Backend  : http://localhost:8000
echo   Frontend : http://localhost:5173
echo   API Docs : http://localhost:8000/docs
echo ========================================
echo.

:: Kill old processes on target ports
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8000.*LISTENING" 2^>nul') do taskkill /PID %%a /F >nul 2>&1
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5173.*LISTENING" 2^>nul') do taskkill /PID %%a /F >nul 2>&1

start "ThreatIntel-Backend" /D "%~dp0backend" cmd /k "%PY% main.py"
ping -n 3 127.0.0.1 >nul
start "ThreatIntel-Frontend" /D "%~dp0frontend" cmd /k "npm run dev"

echo All services launched. You may close this window.
pause >nul

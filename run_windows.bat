@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  Exodus BIP39 Recovery Tool - instalacion local
echo ============================================================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo ERROR: No se encontro Python.
    echo Instala Python 3.11 o 3.12 desde https://www.python.org/
    echo Durante la instalacion marca "Add Python to PATH".
    pause
    exit /b 1
)

echo [1/2] Instalando dependencias...
py -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR al instalar dependencias.
    pause
    exit /b 1
)

echo.
echo [2/2] Iniciando la aplicacion...
py exodus_recovery_tool.py
pause

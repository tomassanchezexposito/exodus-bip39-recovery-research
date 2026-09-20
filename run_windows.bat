@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  Exodus BIP39 Recovery Tool - instalacion local
echo  Version mejorada - soporte 24 palabras
ECHO ============================================================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo ERROR: No se encontro Python Launcher ^(py^).
    echo Instala Python 3.11 o superior desde https://www.python.org/
    echo Durante la instalacion marca "Add Python to PATH".
    pause
    exit /b 1
)

echo [1/2] Instalando/verificando dependencias...
py -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR al instalar dependencias.
    pause
    exit /b 1
)

echo.
echo [2/2] Iniciando la aplicacion...
py src\exodus_recovery_tool.py
if errorlevel 1 (
    echo.
    echo La aplicacion termino con un error.
)

echo.
pause

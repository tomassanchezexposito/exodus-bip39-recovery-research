@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo  Exodus BIP39 Research Recovery Tool - v0.3.0
echo  Registro forense automatico: .log + .jsonl
echo ============================================================
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
echo Los logs se guardaran en la carpeta configurada en la interfaz.
py src\exodus_recovery_tool.py
if errorlevel 1 (
    echo.
    echo La aplicacion termino con un error.
)

echo.
pause

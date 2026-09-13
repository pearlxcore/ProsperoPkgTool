@echo off
rem Simple launcher for the ProsperoPkgTool GUI (Release).
rem Double-click this file, or use the Desktop shortcut.
setlocal
set "GUI=%~dp0ProsperoPkgTool.Gui\bin\Release\net10.0-windows\ProsperoPkgTool.Gui.exe"
if not exist "%GUI%" (
    echo GUI not built yet. Building Release...
    dotnet build "%~dp0ProsperoPkgTool.Gui\ProsperoPkgTool.Gui.csproj" -c Release --nologo
    if errorlevel 1 (
        echo Build failed.
        pause
        exit /b 1
    )
)
start "" "%GUI%"
endlocal

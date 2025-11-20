@echo off
REM Result: .\dist\SQLMonitor.exe

python -m PyInstaller ^
  --onefile ^
  --windowed ^
  --name SQLMonitor ^
  program.py

echo.
echo Done

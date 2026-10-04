@echo off
cd /d "%~dp0"
python -c "import flask, requests" >nul 2>&1
if errorlevel 1 (
  echo Chua cai thu vien can thiet. Chay lenh sau truoc:
  echo python -m pip install -r requirements.txt
  pause
  exit /b 1
)
echo Mo http://127.0.0.1:8000 trong trinh duyet.
echo Nhan Ctrl+C de dung ung dung.
python app.py
pause

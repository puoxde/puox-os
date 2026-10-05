@echo off
rem PUOX-OS starten (laufwerksbuchstaben-los: Pfade relativ zu dieser Datei).
rem Standard ist https://os.example.com auf Port 443; Port 80 leitet nur auf https weiter.
rem Anderer HTTPS-Port bei Bedarf:  set PORT=8443  vor dem Aufruf.
rem Nur lokal statt im Netz:  set HOST=127.0.0.1
cd /d "%~dp0"
python server.py
pause

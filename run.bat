@echo off
rem Opens the Password Strength Analyzer window. Needs Python 3.10 or newer.
cd /d "%~dp0"
start "" pythonw -m password_analyzer

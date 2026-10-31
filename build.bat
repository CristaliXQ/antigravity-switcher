@echo off
chcp 65001 >nul
echo [Antigravity Switcher Builder]
set CSC="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist %CSC% (
    echo [ERROR] csc.exe not found!
    pause
    exit /b 1
)

echo Compiling to Desktop...
%CSC% /nologo /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll /win32icon:"%~dp0app.ico" /target:winexe /out:"%USERPROFILE%\Desktop\Antigravity Switcher.exe" "%~dp0Program.cs"

if %ERRORLEVEL% EQU 0 (
    echo [OK] Successfully compiled to Desktop: "%USERPROFILE%\Desktop\Antigravity Switcher.exe"
    copy /Y "%USERPROFILE%\Desktop\Antigravity Switcher.exe" "%~dp0AntigravitySwitcher.exe" >nul
) else (
    echo [ERROR] Compilation failed.
)
pause

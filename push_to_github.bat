@echo off
echo ===================================================
echo   Pushing Project 2 to GitHub
echo ===================================================
cd /d "%~dp0"
git remote set-url origin https://github.com/jainpragti8-ops/project2_spam_msz_detect.git
git push -u origin main
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [NOTE] If you got 'Repository not found', please make sure
    echo you have created the empty repository on GitHub first at:
    echo https://github.com/new with name 'project2_spam_msz_detect'
)
echo.
pause

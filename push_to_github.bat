@echo off
echo ===================================================
echo   Pushing Project 2 to GitHub
echo ===================================================
cd /d "%~dp0"
git remote set-url origin https://github.com/jainpragti8-ops/project2-_spam_msz_detect.git
git add .
git commit -m "Update project files"
git push -u origin main
echo.
pause

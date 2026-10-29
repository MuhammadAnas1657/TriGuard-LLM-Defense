@echo off
REM =====================================================================
REM TriGuard v2: Automated GitHub Push Helper
REM =====================================================================
echo =====================================================================
echo  TriGuard v2: Push Repository to GitHub
echo =====================================================================
echo.
set /p REPO_URL="Enter your GitHub Repository URL (e.g., https://github.com/username/triguard-v2.git): "
if "%REPO_URL%"=="" (
    echo [ERROR] No URL provided. Aborting.
    pause
    exit /b 1
)

echo.
echo [*] Configuring remote origin: %REPO_URL%
git remote remove origin 2>nul
git remote add origin %REPO_URL%

echo [*] Pushing 'main' branch to remote...
git branch -M main
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Repository successfully pushed to GitHub!
) else (
    echo.
    echo [ERROR] Push failed. Please check your GitHub permissions or authentication.
)
echo.
pause

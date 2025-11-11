@echo off
REM Quick JIRA Integration Test Script
REM Run this to test if your JIRA credentials work

echo.
echo ========================================
echo   JIRA Integration Test
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    exit /b 1
)

REM Check for environment variables
if "%JIRA_URL%"=="" (
    echo ERROR: JIRA_URL environment variable not set
    echo.
    echo Please set your JIRA credentials:
    echo   set JIRA_URL=https://secure-transaction.atlassian.net
    echo   set JIRA_USERNAME=darshsundar007@gmail.com
    echo   set JIRA_API_TOKEN=your-token-here
    echo   set JIRA_PROJECT_KEY=KAN
    echo.
    exit /b 1
)

if "%JIRA_USERNAME%"=="" (
    echo ERROR: JIRA_USERNAME not set
    exit /b 1
)

if "%JIRA_API_TOKEN%"=="" (
    echo ERROR: JIRA_API_TOKEN not set
    exit /b 1
)

if "%JIRA_PROJECT_KEY%"=="" (
    set JIRA_PROJECT_KEY=KAN
)

echo Testing JIRA connection...
echo   URL: %JIRA_URL%
echo   User: %JIRA_USERNAME%
echo   Project: %JIRA_PROJECT_KEY%
echo.

cd scripts\python

REM Install dependencies if needed
echo Checking Python dependencies...
python -c "import requests" 2>nul
if %errorlevel% neq 0 (
    echo Installing requests...
    pip install requests
)

echo.
echo Running test...
python test_jira_integration.py

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo   SUCCESS! JIRA integration works!
    echo ========================================
) else (
    echo.
    echo ========================================
    echo   FAILED! Check your credentials
    echo ========================================
)

cd ..\..

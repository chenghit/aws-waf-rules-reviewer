@echo off
setlocal

set SKILL_NAME=aws-waf-rules-reviewer
set SCRIPT_DIR=%~dp0
set SKILL_DIR=%USERPROFILE%\.kiro\skills\%SKILL_NAME%
set AGENT_DIR=%USERPROFILE%\.kiro\agents
set AGENT_FILE=%AGENT_DIR%\%SKILL_NAME%.json

:: Verify source files exist
for %%f in (SKILL.md references\checklist.md references\waf-knowledge.md %SKILL_NAME%.json) do (
    if not exist "%SCRIPT_DIR%%%f" (
        echo Error: %%f not found in %SCRIPT_DIR% >&2
        exit /b 1
    )
)

:: Uninstall existing
if exist "%SKILL_DIR%" (
    echo Found existing installation, removing...
    rmdir /s /q "%SKILL_DIR%"
    echo Removed skill directory.
)
if exist "%AGENT_FILE%" (
    echo Found existing agent config, removing...
    del /q "%AGENT_FILE%"
    echo Removed agent config.
)

:: Install skill
if not exist "%SKILL_DIR%" mkdir "%SKILL_DIR%"
copy "%SCRIPT_DIR%SKILL.md" "%SKILL_DIR%\" >nul
xcopy "%SCRIPT_DIR%references" "%SKILL_DIR%\references\" /e /i /q >nul

:: Install agent config
if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
copy "%SCRIPT_DIR%%SKILL_NAME%.json" "%AGENT_FILE%" >nul

:: Verify installation
for %%f in ("%SKILL_DIR%\SKILL.md" "%SKILL_DIR%\references\checklist.md" "%SKILL_DIR%\references\waf-knowledge.md" "%AGENT_FILE%") do (
    if not exist %%f (
        echo Error: installation verification failed — %%f not found >&2
        exit /b 1
    )
)

echo Installed skill to %SKILL_DIR%
echo Installed agent config to %AGENT_FILE%
echo.
echo Done. Installation successful.

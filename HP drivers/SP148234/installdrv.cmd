REM ========================================================
REM   Driver deliverable installation
REM 
REM   Template Version: V1.04f
REM ========================================================

REM %Description of deliverable%
@ECHO OFF
if defined FCC_LOG_FOLDER (SET "APP_LOG_FOLDER=%FCC_LOG_FOLDER%") else (SET "APP_LOG_FOLDER=%~d0\programdata\hp\logs")
SET "APP_LOG=%APP_LOG_FOLDER%\%~n0.log"
if not exist "%APP_LOG_FOLDER%" md "%APP_LOG_FOLDER%"

ECHO ############################################################# >> %APP_LOG%
ECHO  [%DATE%]                                                     >> %APP_LOG%
ECHO  [%TIME%] Beginning of the %~nx0                              >> %APP_LOG%
ECHO ############################################################# >> %APP_LOG%

set "ExtensionGuid={e2f84ce7-8efa-411c-aa69-97454ca4cb57}"
set "SoftwareComponenGuid={5c4c3332-344d-483c-8739-259e934c9cc8}"

REM ------------------- Script Entry ------------------------
:DCH_Driver
echo [%TIME%] Search DCH driver >> %APP_LOG%
dir /ad "%~dp0dchu_*" >nul 2>>&1
if errorlevel 1 echo [%TIME%] No DCH driver found. >> %APP_LOG% & goto IHV_Driver

for /f "delims=" %%a in ('dir /ad /b "%~dp0dchu_*"') do (
	echo [%TIME%] Search BASE driver in "%~dp0%%~a\*.inf" >> %APP_LOG%
	if not exist "%~dp0%%~a\*.inf" echo [%TIME%] No .inf found. >> %APP_LOG% & goto RESULTFAILED
	for /f "delims=" %%i in ('dir /a-d /b "%~dp0%%~a\*.inf"') do (
		echo [%TIME%] Check "%~dp0%%~a\%%~i" driver category. >> %APP_LOG%
		call:ChkDrvClassGuid "%~dp0%%~a\%%~i" "%ExtensionGuid% %SoftwareComponenGuid%"
		if errorlevel 1 (
			echo [%TIME%] Driver category match, install it. >> %APP_LOG%
			call:DrvInst "%~dp0%%~a\%%~i"
			if errorlevel 1 echo [%TIME%] %%~i driver install failed. >> %APP_LOG% & goto RESULTFAILED
			echo [%TIME%] %%~i driver install success. >> %APP_LOG%
		) else (
			echo [%TIME%] Driver category mismatch. >> %APP_LOG%
		)
	)

	echo. >> %APP_LOG%
	echo [%TIME%] Search EXTENSION driver in "%~dp0%%~a\*.inf" >> %APP_LOG%
	for /f "delims=" %%i in ('dir /a-d /b "%~dp0%%~a\*.inf"') do (
		echo [%TIME%] Check "%~dp0%%~a\%%~i" driver category. >> %APP_LOG%
		call:ChkDrvClassGuid "%~dp0%%~a\%%~i" "%ExtensionGuid%"
		if not errorlevel 1 (
			echo [%TIME%] Driver category match, install it. >> %APP_LOG%
			call:DrvInst "%~dp0%%~a\%%~i"
			if errorlevel 1 echo [%TIME%] %%~i driver install failed. >> %APP_LOG% & goto RESULTFAILED
			echo [%TIME%] %%~i driver install success. >> %APP_LOG%
		) else (
			echo [%TIME%] Driver category mismatch. >> %APP_LOG%
		)
	)

	echo. >> %APP_LOG%
	echo [%TIME%] Search COMPONENT driver in "%~dp0%%~a\*.inf" >> %APP_LOG%
	if not exist "%~dp0%%~a\*.inf" echo [%TIME%] No COMPONENT .inf found. >> %APP_LOG%
	for /f "delims=" %%i in ('dir /a-d /b "%~dp0%%~a\*.inf"') do (
		echo [%TIME%] Check "%~dp0%%~a\%%~i" driver category. >> %APP_LOG%
		call:ChkDrvClassGuid "%~dp0%%~a\%%~i" "%SoftwareComponenGuid%"
		if not errorlevel 1 (
			echo [%TIME%] Driver category match, install it. >> %APP_LOG%
			call:DrvInst "%~dp0%%~a\%%~i"
			if errorlevel 1 echo [%TIME%] %%~i driver install failed. >> %APP_LOG% & goto RESULTFAILED
			echo [%TIME%] %%~i driver install success. >> %APP_LOG%
		) else (
			echo [%TIME%] Driver category mismatch. >> %APP_LOG%
		)
	)
)

:IHV_Driver
echo [%TIME%] Search IHV special driver order >> %APP_LOG%
dir /ad "%~dp0ihv_*" >nul 2>>&1
if errorlevel 1 echo [%TIME%] No IHV driver found. >> %APP_LOG% & goto Other_Driver

for /f "delims=" %%a in ('dir /ad /b "%~dp0ihv_*"') do (
    echo [%TIME%] Checking "%~dp0%%~a" folder. >> %APP_LOG%
	if exist "%~dp0%%~a\drvorder.txt" (
		echo [%TIME%] Install driver by drvorder.txt >> %APP_LOG%
		for /f "delims=" %%i in ('type "%~dp0%%~a\drvorder.txt"') do (
			echo [%TIME%] Check "%~dp0%%~a\%%~i" >> %APP_LOG%
			if not exist "%~dp0%%~a\%%~i" echo could not found the inf file. >> %APP_LOG% & goto RESULTFAILED
			echo [%TIME%] Install "%~dp0%%~a\%%~i" >> %APP_LOG%
			call:DrvInst "%~dp0%%~a\%%~i"
			if errorlevel 1 echo [%TIME%] %%~i driver install failed. >> %APP_LOG% & goto RESULTFAILED
			echo [%TIME%] Driver install success. >> %APP_LOG%
		)
	) else (
		echo [%TIME%] No drvorder.txt found >> %APP_LOG% & goto RESULTFAILED
	)
)

:Other_Driver
rem Please add addition IHV command below.

if not exist "%~dp0hpup.exe" if not exist "%~dp0..\hpup.exe" GOTO END
echo [%TIME%] Softpaq flow >> %APP_LOG%
if not exist "%~dp0uwp\appxinst.cmd" GOTO END
echo [%TIME%] Call "%~dp0uwp\appxinst.cmd" >> %APP_LOG%
call "%~dp0uwp\appxinst.cmd" >> %APP_LOG%
if not [%errorlevel%] == [0] echo [%TIME%] appxinst.cmd failed >> %APP_LOG% & goto RESULTFAILED
echo [%TIME%] appxinst.cmd success >> %APP_LOG%
GOTO END

:DrvInst
echo %windir%\system32\Pnputil.exe /add-driver "%~1" /install >> %APP_LOG%
%windir%\system32\Pnputil.exe /add-driver "%~1" /install >> %APP_LOG%
echo Result=%errorlevel% >> %APP_LOG%
if /i [%errorlevel%] == [0] exit /b 0
if /i [%errorlevel%] == [259] exit /b 0
if /i [%errorlevel%] == [3010] exit /b 0
exit /b 1
GOTO:EOF

:ChkDrvClassGuid
if exist c:\system.sav\util\rwini.exe (
    for /f "delims=" %%i in ('c:\system.sav\util\rwini.exe read /file:"%~1" /section:"version" key:"ClassGuid"') do (
        echo ClassGuid=%%~i >> %APP_LOG%.
		for %%x in (%~2) do (if /i [ClassGuid^=%%~i] == [ClassGuid^=%%~x] exit /b 0 )
    )
    exit /b 1
)
for /f "eol=; tokens=1,2 delims== " %%i in ('findstr.exe /i /r /c:"^ClassGuid" "%~1"') do (
    echo ClassGuid=%%~j >> %APP_LOG%
    for %%x in (%~2) do (if /i [%%~i^=%%~j] == [ClassGuid^=%%~x]  exit /b 0)
)
exit /b 1
GOTO:EOF

:RESULTFAILED
ECHO ERRRORLEVEL=%ERRORLEVEL% >> %APP_LOG%
EXIT /B 1
GOTO END

:END
EXIT /B 0


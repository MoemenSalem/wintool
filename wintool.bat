@echo off
title Wintool
set "params=%*"
cd /d "%~dp0" && ( if exist "%temp%\getadmin.vbs" del "%temp%\getadmin.vbs" ) && fsutil dirty query %systemdrive% 1>nul 2>nul || (  echo Set UAC = CreateObject^("Shell.Application"^) : UAC.ShellExecute "cmd.exe", "/c cd ""%~sdp0"" && %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" && "%temp%\getadmin.vbs" && exit /B )






:menu
color 05
cls
echo ##################################################
echo #               Made by Moemen_N7                #
echo #          https://github.com/Moemen-N7/         #
echo ##################################################
echo Thanks For Using My tool  :)
echo ############################
echo Please choose an option:
echo 1. Lock,Unlock
echo 2. Windows Tools
echo 3. About
echo 4. Temp cleaner
echo 5. San system
echo 6. Force Delete
echo 7. Task Manger (Enable,disable)
echo 0. Exit

set /p choice=Enter choice:

if "%choice%"=="1" goto option1
if "%choice%"=="2" goto option2
if "%choice%"=="3" goto option3
if "%choice%"=="4" goto option4
if "%choice%"=="5" goto option5
if "%choice%"=="6" goto option6
if "%choice%"=="7" goto option7
if "%choice%"=="8" goto option8
if "%choice%"=="9" goto option9
if "%choice%"=="10" goto option10
if "%choice%"=="0" goto end
cls
echo Invalid choice. Please try again.
pause
goto menu

:option1
color %color%
title Lock folder
:lockfo
cls
echo =====================================
echo         Lock Main Menu          
echo =====================================
echo [1] Lock the folder
echo [2] Unlock the folder
echo [0] Go to Main menu
echo =====================================
set /p choice=Enter your choice:

if "%choice%"=="1" goto lock
if "%choice%"=="2" goto unlock
if "%choice%"=="0" goto main
cls
echo Invalid choice. Please try again.
pause
goto menu
:lock
setlocal EnableDelayedExpansion

set "psCommand="(new-object -COM 'Shell.Application').BrowseForFolder(0, 'Select a folder', 0, 0).self.path""
for /f "usebackq delims=" %%I in (`powershell %psCommand%`) do set "folder=%%I"

if not defined folder (
  echo No folder selected
  pause
  exit /b
)
attrib +h +s "%folder%"
icacls "%folder%" /deny Everyone:M
icacls "%folder%" /deny "%username%":R 
cls
echo =====================================
echo Locking the folder, please wait...
echo =====================================
cls
echo =====================================
echo Locked complete
echo =====================================
pause
goto lockfo

:unlock
set /p folder=Enter folder nu (Path:D:\move\): 
icacls "%folder%" /grant Everyone:M
icacls "%folder%" /grant "%username%":R
attrib -h -s "%folder%"
cls
echo =====================================
echo Unlocking the folder, please wait...
echo =====================================
cls
echo =====================================
echo Unlocked complete
echo =====================================

pause
goto lockfo

:main
goto menu

pause
goto lockfo




:option2
color %color%
title Windows Tools
:windowstools
cls
echo =====================================
echo         Windows Main Menu          
echo =====================================
echo [1] Net fix
echo [2] Windows update fix
echo [3] Delete all bloatware
echo [4] Disable Windows updates
echo [5] Enable Windows updates
echo [6] disable Windows search online
echo [7] Create the GodMode folder
echo [8] Create the power option ultimate performance
echo [9] admin user enable
echo [10] Usb Permissions fix
echo [11] Add ownership ot the user
echo [12] Computer Performance
echo [13] Enable Group Policy Editor (Home,earlier versions)
echo [13] Enable Windows Sandbox (Home,earlier versions)
echo [0] Go to Main menu
echo =====================================
set /p choice=Enter your choice:

if "%choice%"=="1" goto w_option1
if "%choice%"=="2" goto w_option2
if "%choice%"=="3" goto w_option3
if "%choice%"=="4" goto w_option4
if "%choice%"=="5" goto w_option5
if "%choice%"=="6" goto w_option6
if "%choice%"=="7" goto w_option7
if "%choice%"=="8" goto w_option8
if "%choice%"=="9" goto w_option9
if "%choice%"=="10" goto w_option10
if "%choice%"=="11" goto w_option11
if "%choice%"=="12" goto w_option12
if "%choice%"=="13" goto w_option13
if "%choice%"=="14" goto w_option14
if "%choice%"=="0" goto main
cls
echo Invalid choice. Please try again.
pause
goto menu

:w_option1
cls
ipconfig /release
ipconfig /renew
arp -d *
nbtstat -R
nbtstat -RR
netsh advfirewall reset
netsh winsock reset
netsh int tcp reset
netsh int ip reset
ipconfig /flushdns
ipconfig /registerdns
pause
goto windowstools

:w_option2
cls
net stop bits
net stop wuauserv
net stop appidsvc
net stop cryptsvc
Del "%ALLUSERSPROFILE%\Application Data\Microsoft\Network\Downloader\*.*"
rmdir %systemroot%\SoftwareDistribution /S /Q
rmdir %systemroot%\system32\catroot2 /S /Q
sc.exe sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
sc.exe sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)
cd /d %windir%\system32
regsvr32.exe /s atl.dll
regsvr32.exe /s urlmon.dll
regsvr32.exe /s mshtml.dll
regsvr32.exe /s shdocvw.dll
regsvr32.exe /s browseui.dll
regsvr32.exe /s jscript.dll
regsvr32.exe /s vbscript.dll
regsvr32.exe /s scrrun.dll
regsvr32.exe /s msxml.dll
regsvr32.exe /s msxml3.dll
regsvr32.exe /s msxml6.dll
regsvr32.exe /s actxprxy.dll
regsvr32.exe /s softpub.dll
regsvr32.exe /s wintrust.dll
regsvr32.exe /s dssenh.dll
regsvr32.exe /s rsaenh.dll
regsvr32.exe /s gpkcsp.dll
regsvr32.exe /s sccbase.dll
regsvr32.exe /s slbcsp.dll
regsvr32.exe /s cryptdlg.dll
regsvr32.exe /s oleaut32.dll
regsvr32.exe /s ole32.dll
regsvr32.exe /s shell32.dll
regsvr32.exe /s initpki.dll
regsvr32.exe /s wuapi.dll
regsvr32.exe /s wuaueng.dll
regsvr32.exe /s wuaueng1.dll
regsvr32.exe /s wucltui.dll
regsvr32.exe /s wups.dll
regsvr32.exe /s wups2.dll
regsvr32.exe /s wuweb.dll
regsvr32.exe /s qmgr.dll
regsvr32.exe /s qmgrprxy.dll
regsvr32.exe /s wucltux.dll
regsvr32.exe /s muweb.dll
regsvr32.exe /s wuwebv.dll
netsh winsock reset
netsh winsock reset proxy
net start bits
net start wuauserv
net start appidsvc
net start cryptsvc
pause
goto windowstools

:w_option3
cls
echo Uninstalling bloatware...
echo This may take some time. Please be patient.
echo.

::Uninstalling 3D Builder
echo Uninstalling 3D Builder...
start /wait PowerShell -Command "Get-AppxPackage *3dbuilder* | Remove-AppxPackage"
echo.


::Uninstalling XboxApp
echo Uninstalling XboxApp...
start /wait PowerShell.exe -ExecutionPolicy Bypass -Command "Get-AppxPackage *XboxApp* | Remove-AppxPackage"
echo.


::Uninstalling Alarms & Clock
echo Uninstalling Alarms & Clock...
start /wait PowerShell -Command "Get-AppxPackage *windowsalarms* | Remove-AppxPackage"
echo.

::Uninstalling Calendar & Mail
echo Uninstalling Calendar & Mail...
start /wait PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
echo.

::Uninstalling Camera
echo Uninstalling Camera...
start /wait PowerShell -Command "Get-AppxPackage *windowscamera* | Remove-AppxPackage"
echo.

::Uninstalling Get Help
echo Uninstalling Get Help...
start /wait PowerShell -Command "Get-AppxPackage *gethelp* | Remove-AppxPackage"
echo.

::Uninstalling Get Office
echo Uninstalling Get Office...
start /wait PowerShell -Command "Get-AppxPackage *officehub* | Remove-AppxPackage"
echo.

::Uninstalling Groove Music
echo Uninstalling Groove Music...
start /wait PowerShell -Command "Get-AppxPackage *zunemusic* | Remove-AppxPackage"
echo.

::Uninstalling Maps
echo Uninstalling Maps...
start /wait PowerShell -Command "Get-AppxPackage *windowsmaps* | Remove-AppxPackage"
echo.

::Uninstalling Microsoft News
echo Uninstalling Microsoft News...
start /wait PowerShell -Command "Get-AppxPackage *bingnews* | Remove-AppxPackage"
echo.

::Uninstalling Microsoft Solitaire Collection
echo Uninstalling Microsoft Solitaire Collection...
start /wait PowerShell -Command "Get-AppxPackage *solitairecollection* | Remove-AppxPackage"
echo.

::Uninstalling Movies & TV
echo Uninstalling Movies & TV...
start /wait PowerShell -Command "Get-AppxPackage *zunevideo* | Remove-AppxPackage"
echo.

::Uninstalling OneNote
echo Uninstalling OneNote...
start /wait PowerShell -Command "Get-AppxPackage *onenote* | Remove-AppxPackage"
echo.

::Uninstalling Paint 3D
echo Uninstalling Paint 3D...
start /wait PowerShell -Command "Get-AppxPackage *mspaint* | Remove-AppxPackage"
echo.

::Uninstalling Skype
echo Uninstalling Skype...
start /wait PowerShell -Command "Get-AppxPackage *skypeapp* | Remove-AppxPackage"
echo.

::Uninstalling Snip & Sketch
echo Uninstalling Snip & Sketch...
start /wait PowerShell -Command "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
echo.

echo Bloatware removed.
pause
goto windowstools

:w_option4
cls
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows" /v "WindowsUpdate" /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "AUOptions" /t REG_DWORD /d "2" /f
net stop wuauserv
net stop bits
sc stop wuauserv
sc config wuauserv start= disabled
cls
echo Windows Update has been fully disabled.
pause
goto windowstools

:w_option5
cls
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
sc config wuauserv start= auto
sc start wuauserv
cls
echo Windows Update has been fully enabled.
pause
goto windowstools

:w_option6
cls
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
cls
echo Windows Search has been fully disabled.
pause
goto windowstools

:w_option7
cls
set folderName="GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
md %folderName%
cls
echo GodMode folder created.
pause
goto windowstools

:w_option8
cls
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
cls
echo Power option ultimate performance has been fully created.
pause
goto windowstools

:w_option9
cls
net user administrator /active:yes
cls
echo Admin user has been fully enabled.
pause
goto windowstools

:w_option10
cls
set /p drive=Enter drive letter of USB drive (ex: E): 
echo Fixing permissions for %drive%:\ ...
takeown /r /d y /f %drive%:\ >nul
icacls %drive%:\ /grant administrators:F /T >nul
echo Permissions have been fixed for %drive%:\
pause
echo Removing registry entries for %drive%:\
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\%drive%" /f >nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "%drive%.*" /f >nul
echo Registry entries have been removed for %drive%:\
pause
goto windowstools

:w_option11
cls
takeown /f "C:\path\to\file_or_folder" /r /d y
icacls "C:\path\to\file_or_folder" /grant "%USERNAME%":F /t
pause
goto windowstools



:w_option12
cls
echo System Performance:
systeminfo | findstr /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Total Physical Memory" /C:"Available Physical Memory" /C:"Domain"
echo.
echo CPU Information:
wmic cpu get Name, MaxClockSpeed, NumberOfCores
echo.
echo Memory Information:
wmic memorychip get BankLabel, Capacity, MemoryType, Speed
echo.
echo GPU Information:
wmic path win32_VideoController get name, AdapterRAM, VideoProcessor, DriverVersion
echo.
echo Battery Information:
WMIC Path Win32_Battery Get EstimatedChargeRemaining, BatteryStatus, BatteryRechargeTime
echo.
echo Disk Information:
wmic diskdrive get Model, InterfaceType, Size, MediaType
pause
goto windowstools


:w_option13

FOR %%F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%%F")
FOR %%F IN ("%SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%%F")
cls
echo Group Policy Editor has been fully enabled.
pause
goto windowstools



:w_option14

@echo off

echo Checking for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

echo Permission check result: %errorlevel%

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
echo Requesting administrative privileges...
goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

echo Running created temporary "%temp%\getadmin.vbs"
timeout /T 2
"%temp%\getadmin.vbs"
exit /B

:gotAdmin
if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
pushd "%CD%"
CD /D "%~dp0" 

echo Batch was successfully started with admin privileges
echo .
cls
Title Sandbox Installer

pushd "%~dp0"

dir /b %SystemRoot%\servicing\Packages\*Containers*.mum >sandbox.txt

for /f %%i in ('findstr /i . sandbox.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i"

del sandbox.txt

Dism /online /enable-feature /featurename:Containers-DisposableClientVM /LimitAccess /ALL

pause 

pause
goto windowstools




:w_option15



pause
goto windowstools






:main
goto menu

pause
goto windowstools


pause
goto menu





:option3
cls
color %color%
echo ##################################################
echo #               Made by Moemen_N7                #
echo #          https://github.com/Moemen-N7/         #
echo ##################################################
echo Thanks For Using My tool  :)
echo ############################
start /max https://moemen.ga


pause
goto menu




:option4
echo Deleting temporary files...
echo Please wait...
cleanmgr /sageset:1
cleanmgr /sagerun:1
RD /S /Q "%temp%"
md "%temp%"
del /f /q "%temp%\*.*"
RD /S /Q "C:\Windows\Prefetch"
md "C:\Windows\Prefetch"
del /f /q "C:\Windows\Temp\*.*"
md "C:\Windows\Temp"
del /f /q "C:\Windows\Spool\Printers\*.*"
md "C:\Windows\Spool\Printers"
del /f /q "C:\Windows\Recent\*.*"
md "C:\Windows\Recent"
del /f /q "C:\Windows\Tmp\*.*"
md "C:\Windows\Tmp"
echo Temporary files deleted.
pause
goto menu



:option5
color %color%
title Antivirus
:antmenu
cls
echo =====================================
echo         Antivirus Main Menu          
echo =====================================
echo [1] Scan computer
echo [2] View scan results
echo [0] Go to Main menu
echo =====================================
set /p choice=Enter your choice:

if "%choice%"=="1" goto scan
if "%choice%"=="2" goto view_results
if "%choice%"=="0" goto main
cls
echo Invalid choice. Please try again.
pause
goto antmenu

:scan
echo Scanning, please wait...
echo =====================================

rem Scan for viruses
set result=No viruses found
for /r C:\ %%f in (*.exe, *.bat, *.vbs) do (
    findstr /m /c:"virus" "%%f" >nul
    if not errorlevel 1 (
        set result=Infected: %%f
        echo Infected: %%f
    )
)

rem Save scan results to a file
echo %result% > scan_result.txt

echo =====================================
echo Scan complete
pause
goto antmenu

:view_results
echo =====================================
echo           Scan Results              
echo =====================================
type scan_result.txt
echo =====================================
pause
goto antmenu

:main
goto menu

pause
goto antmenu





:option6

setlocal EnableDelayedExpansion

set "psCommand="(new-object -COM 'Shell.Application').BrowseForFolder(0, 'Select a folder', 0, 0).self.path""
for /f "usebackq delims=" %%I in (`powershell %psCommand%`) do set "folder=%%I"

if not defined folder (
  echo No folder selected
  pause
  exit /b
)

if exist "%folder%" (
    echo Attempting to delete "%folder%"...
    attrib -r -a -s -h "%folder%" >nul 2>&1
    takeown /f "%folder%" /r /d y >nul 2>&1
    icacls "%folder%" /grant administrators:F /t >nul 2>&1
    rd /s /q "%folder%" >nul 2>&1 || del /f /q "%folder%" >nul 2>&1 || (
        echo Unable to delete "%folder%". Giving ownership to current user and trying again...
        takeown /f "%folder%" /r /d y >nul 2>&1
        icacls "%folder%" /grant administrators:F /t >nul 2>&1
        rd /s /q "%folder%" >nul 2>&1 || del /f /q "%folder%" >nul 2>&1 || (
            echo Unable to delete "%folder%". Moving to recycle bin...
            move "%folder%" "%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files"
        )
    )
    if exist "%file%" (
        echo You don't have sufficient permissions to delete "%file%". Please take ownership of the file or folder and try again.
    )
) else (
    echo File or folder "%file%" does not exist.
)

pause
goto menu










:option7

color %color%
title Task Manger folder
:Task
cls
echo =====================================
echo         Task Manger Main Menu          
echo =====================================
echo [1] Enable Task Manger
echo [2] Disable Task Manger
echo [0] Go to Main menu
echo =====================================
set /p choice=Enter your choice:

if "%choice%"=="1" goto Enable
if "%choice%"=="2" goto Disable
if "%choice%"=="0" goto main
cls
echo Invalid choice. Please try again.
pause
goto menu
:Enable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v DisableRegistryTools /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v DisableTaskMgr /t REG_DWORD /d 0 /f
echo =====================================
echo Task Manger has been Enable
echo =====================================
pause
goto Task
:Disable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /f /v DisableTaskMgr /t REG_DWORD /d 1 /f
cls
echo =====================================
echo Task Manger has been Disable
echo =====================================

pause
goto Task

:main
goto menu

pause
goto Task




:end
cls
color %color%
echo ##################################################
echo #               Made by Moemen_N7                #
echo #          https://github.com/Moemen-N7/         #
echo ##################################################
echo Thanks For Using My tool  :)
echo ############################
echo Exiting...
pause

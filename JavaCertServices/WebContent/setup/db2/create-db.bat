@echo off

if "%2"=="" goto usage

set DB2_USER=%1
set DB2_PASSWD=%2

goto start

:usage

echo usage: create-db2-db.bat db2admin password
goto end

:start

db2cmd.exe -i -w gsi-db2.bat %DB2_USER% %DB2_PASSWD%

:end

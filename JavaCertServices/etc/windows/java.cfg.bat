@echo off

set LOCALCLASSPATH=
for %%i in ("%JCS_ROOT%\lib\*.jar") do call "%JCS_ROOT%\etc\lcp.bat" %%i
set LOCALCLASSPATH=%JCS_ROOT%\etc;%LOCALCLASSPATH%

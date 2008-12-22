@echo off

set DB2_USER=%1
set DB2_PASSWD=%2

echo Attaching to instance %DB2INSTANCE% as user %DB2_USER%...
db2 ATTACH TO %DB2INSTANCE% user %DB2_USER% using %DB2_PASSWD%

echo Dropping existing database...
db2 DROP DATABASE OGSA

echo Creating database...
db2 CREATE DATABASE OGSA

echo Connecting to database as user "%DB2_USER%"...
db2 CONNECT TO OGSA user "%DB2_USER%" using "%DB2_PASSWD%"

echo Setting up database schema...
db2 -t -f"gsi.ddl"

echo Disconnecting from database...
db2 DISCONNECT CURRENT

exit

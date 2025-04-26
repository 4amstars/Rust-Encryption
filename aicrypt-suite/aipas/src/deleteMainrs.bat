@echo off 
 
REM Get the directory of the batch file 
set "batch_dir=%~dp0" 
 
REM Navigate to the src directory 
cd "%batch_dir%" 
 
REM Delete main.rs if it exists 
if exist main.rs del main.rs 
 
REM Create a new blank main.rs file 
type nul > main.rs 
 
REM Indicate completion 
echo main.rs deleted and recreated as a blank file. 

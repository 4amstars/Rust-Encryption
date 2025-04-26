@echo off

:menu
cls
echo 0. cargo clean [Clean the project]
echo 1. cargo new [Create a new Rust project]
echo 2. cargo build [Clean and build the project]
echo 3. cargo build --release [Clean and build the project in release mode]
echo 4. cargo run [Clean and run the project]
echo 5. cargo test [Clean and test the project]
echo 6. cargo check [Check the project for errors]
echo 7. cargo fmt [Format the project's code]
echo 8. Custom Command [Run a custom cargo or rustc command]
echo 9. Exit [Exit the script]

set /p choice=Enter a command:

if "%choice%"=="0" goto cargo_clean
if "%choice%"=="1" goto cargo_new
if "%choice%"=="2" goto cargo_build
if "%choice%"=="3" goto cargo_build_release
if "%choice%"=="4" goto cargo_run
if "%choice%"=="5" goto cargo_test
if "%choice%"=="6" goto cargo_check
if "%choice%"=="7" goto cargo_fmt
if "%choice%"=="8" goto custom_command
if "%choice%"=="9" goto exit

echo Invalid choice. Press any key to return to the menu.
pause >nul
goto menu

:cargo_clean
cls
echo Cleaning the project...
cargo clean
goto return_to_menu

:cargo_new
cls
set /p project_name=Enter a project name:
echo Running cargo new...
cargo new %project_name%
echo Copying batch file to the new project directory...
copy "%~f0" ".\%project_name%\"
echo Creating deleteMainrs.bat in the src directory...
echo @echo off > .\%project_name%\src\deleteMainrs.bat
echo. >> .\%project_name%\src\deleteMainrs.bat
echo REM Get the directory of the batch file >> .\%project_name%\src\deleteMainrs.bat
echo set "batch_dir=%%~dp0" >> .\%project_name%\src\deleteMainrs.bat
echo. >> .\%project_name%\src\deleteMainrs.bat
echo REM Navigate to the src directory >> .\%project_name%\src\deleteMainrs.bat
echo cd "%%batch_dir%%" >> .\%project_name%\src\deleteMainrs.bat
echo. >> .\%project_name%\src\deleteMainrs.bat
echo REM Delete main.rs if it exists >> .\%project_name%\src\deleteMainrs.bat
echo if exist main.rs del main.rs >> .\%project_name%\src\deleteMainrs.bat
echo. >> .\%project_name%\src\deleteMainrs.bat
echo REM Create a new blank main.rs file >> .\%project_name%\src\deleteMainrs.bat
echo type nul ^> main.rs >> .\%project_name%\src\deleteMainrs.bat
echo. >> .\%project_name%\src\deleteMainrs.bat
echo REM Indicate completion >> .\%project_name%\src\deleteMainrs.bat
echo echo main.rs deleted and recreated as a blank file. >> .\%project_name%\src\deleteMainrs.bat
goto return_to_menu

:cargo_build
cls
echo Cleaning and building the project...
cargo clean
cargo build
goto return_to_menu

:cargo_build_release
cls
echo Cleaning and building the project in release mode...
cargo clean
cargo build --release
goto return_to_menu

:cargo_run
cls
echo Cleaning and running the project...
cargo clean
cargo run
goto return_to_menu

:cargo_test
cls
echo Cleaning and testing the project...
cargo clean
cargo test
goto return_to_menu

:cargo_check
cls
echo Checking the project for errors...
cargo check
goto return_to_menu

:cargo_fmt
cls
echo Formatting the project's code...
cargo fmt
goto return_to_menu

:custom_command
cls
set /p custom_command=Enter a custom cargo or rustc command:
echo Running %custom_command%...
%custom_command%
goto return_to_menu

:return_to_menu
pause
goto menu

:exit
exit
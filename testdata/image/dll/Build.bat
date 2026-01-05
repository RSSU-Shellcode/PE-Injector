@echo off

echo ========== initialize Visual Studio environment ==========
if "%VisualStudio%" == "" (
    echo environment variable "VisualStudio" is not set
    exit /b 1
)
call "%VisualStudio%\VC\Auxiliary\Build\vcvars64.bat"

echo ==================== clean old files =====================
rd /S /Q "TestDLL"
rd /S /Q "Release"
rd /S /Q "x64"

echo =================== generate test dll ====================
MSBuild.exe TestDLL.sln /t:TestDLL /p:Configuration=Release /p:Platform=x86
MSBuild.exe TestDLL.sln /t:TestDLL /p:Configuration=Release /p:Platform=x64
copy Release\TestDLL.dll     ..\..\image_dll_x86.dat
copy x64\Release\TestDLL.dll ..\..\image_dll_x64.dat

echo =================== clean output files ===================
rd /S /Q "TestDLL"
rd /S /Q "Release"
rd /S /Q "x64"

echo ==========================================================
echo                build test dll successfully!
echo ==========================================================

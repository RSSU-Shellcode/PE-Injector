set GOARCH=386
go test -v
set GOARCH=amd64
go test -v

taskkill /IM calc.exe /F
taskkill /IM win32calc.exe /F
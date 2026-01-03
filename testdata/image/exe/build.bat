set GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o ../../image_exe_x86.dat
set GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o ../../image_exe_x64.dat
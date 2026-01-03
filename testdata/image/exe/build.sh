export GOOS=windows
export GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o ../../image_exe_x86.dat
export GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o ../../image_exe_x64.dat
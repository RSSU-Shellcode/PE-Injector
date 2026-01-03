set GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o image_x86.dat
set GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o image_x64.dat
move image_x86.dat ../
move image_x64.dat ../
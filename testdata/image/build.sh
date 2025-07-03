export GOOS=windows
export GOARCH=386
go build -v -trimpath -ldflags "-s -w" -o image_x86.dat
export GOARCH=amd64
go build -v -trimpath -ldflags "-s -w" -o image_x64.dat
mv image_x86.dat ../
mv image_x64.dat ../
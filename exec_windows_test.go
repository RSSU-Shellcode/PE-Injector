//go:build windows

package injector

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testExecuteEXE(t *testing.T, path string, image []byte, args ...string) {
	err := os.WriteFile(path, image, 0600)
	require.NoError(t, err)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	cmd := exec.Command(path, args...)
	cmd.Stdout = w
	cmd.Stderr = w
	err = cmd.Start()
	require.NoError(t, err)
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	go func() {
		time.Sleep(5 * time.Second)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = r.Close()
		_ = w.Close()
	}()

	for {
		buf := make([]byte, 1024)
		n, err := r.Read(buf)
		out := string(buf[:n])
		if strings.Contains(out, "Hello World!") {
			return
		}
		fmt.Println(out)
		if err != nil {
			break
		}
	}

	// when failed to test, backup output image for debug
	path = strings.ReplaceAll(path, ".exe", ".exe.bak")
	err = os.WriteFile(path, image, 0600)
	require.NoError(t, err)
	t.FailNow()
}

func testExecuteDLL(t *testing.T, path string, image []byte) {
	err := os.WriteFile(path, image, 0600)
	require.NoError(t, err)

	dll, err := syscall.LoadDLL(path)
	require.NoError(t, err)
	defer func() {
		err = dll.Release()
		require.NoError(t, err)
	}()

	proc := dll.MustFindProc("Add")
	ret, _, err := proc.Call(1, 2)
	if ret == 3 {
		return
	}
	fmt.Println(err)

	// when failed to test, backup output image for debug
	path = strings.ReplaceAll(path, ".dll", ".dll.bak")
	err = os.WriteFile(path, image, 0600)
	require.NoError(t, err)
	t.FailNow()
}

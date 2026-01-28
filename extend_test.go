package injector

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtendTextSection(t *testing.T) {
	injector := NewInjector()

	t.Run("exe", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_exe_x86.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			output, err := injector.extendTextSection(1427)
			require.NoError(t, err)

			testExecuteEXE(t, "testdata/extended_x86.exe", output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_exe_x64.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			output, err := injector.extendTextSection(7433)
			require.NoError(t, err)

			testExecuteEXE(t, "testdata/extended_x64.exe", output)
		})
	})

	t.Run("dll", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_dll_x86.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			output, err := injector.extendTextSection(1427)
			require.NoError(t, err)

			if runtime.GOARCH != "386" {
				return
			}
			testExecuteDLL(t, "testdata/extended_x86.dll", output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_dll_x64.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			output, err := injector.extendTextSection(7433)
			require.NoError(t, err)

			if runtime.GOARCH != "amd64" {
				return
			}
			testExecuteDLL(t, "testdata/extended_x64.dll", output)
		})
	})

	err := injector.Close()
	require.NoError(t, err)
}

package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtendTextSection_EXE(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(1427)
		require.NoError(t, err)

		testExecuteEXE(t, "testdata/extended_x86.exe", output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(7433)
		require.NoError(t, err)

		testExecuteEXE(t, "testdata/extended_x64.exe", output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestExtendTextSection_DLL(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/kernel32_x86.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(1427)
		require.NoError(t, err)

		err = os.WriteFile("testdata/extended_x86.dll", output, 0600)
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/kernel32_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(7433)
		require.NoError(t, err)

		err = os.WriteFile("testdata/extended_x64.dll", output, 0600)
		require.NoError(t, err)
	})

	err := injector.Close()
	require.NoError(t, err)
}

package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInjector(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		output, err := injector.Inject(shellcode, image, nil)
		require.NoError(t, err)
		require.NotEmpty(t, output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)

		output, err := injector.Inject(shellcode, image, nil)
		require.NoError(t, err)
		require.NotEmpty(t, output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

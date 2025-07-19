package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelocateInstructionSegment(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		RandSeed:       1234,
		NotSaveContext: true,
	}

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)
		loader, err := os.ReadFile("testdata/relocate_x86.asm")
		require.NoError(t, err)
		opts.LoaderX86 = string(loader)

		output, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.NotEmpty(t, output)

		testExecuteImage(t, "testdata/injected_x86.exe", output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)
		loader, err := os.ReadFile("testdata/relocate_x64.asm")
		require.NoError(t, err)
		opts.LoaderX64 = string(loader)

		output, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.NotEmpty(t, output)

		testExecuteImage(t, "testdata/injected_x64.exe", output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

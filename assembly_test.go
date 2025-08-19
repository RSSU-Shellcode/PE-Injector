package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRelocateInstructionSegment(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		NotSaveContext: true,
		RandSeed:       1234,
	}

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)
		loader, err := os.ReadFile("testdata/relocate_x86.asm")
		require.NoError(t, err)
		opts.LoaderX86 = string(loader)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, ModeExtendSection, ctx.Mode)

		testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)
		loader, err := os.ReadFile("testdata/relocate_x64.asm")
		require.NoError(t, err)
		opts.LoaderX64 = string(loader)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, ModeCodeCave, ctx.Mode)

		testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGarbage(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		ForceCreateSection: true,
	}

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)

		testExecuteEXE(t, "testdata/injected_x86.exe", ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)

		testExecuteEXE(t, "testdata/injected_x64.exe", ctx.Output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestGarbageTemplateFuzz(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "386"
		injector.opts = new(Options)
		err := injector.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := injector.garbageTemplate()
			require.NotEmpty(t, data)
		}

		err = injector.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "amd64"
		injector.opts = new(Options)
		err := injector.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := injector.garbageTemplate()
			require.NotEmpty(t, data)
		}

		err = injector.Close()
		require.NoError(t, err)
	})
}

package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJunkCode(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		ForceCreateText: true,
	}

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_exe_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)

		testExecuteEXE(t, "testdata/injected_x86.exe", ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_exe_x64.dat")
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

func TestJunkTemplate(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		testJunkTemplate(t, 10, false)
	})

	t.Run("short", func(t *testing.T) {
		testJunkTemplate(t, 10, true)
	})
}

func TestJunkTemplateFuzz(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		testJunkTemplate(t, 1000, false)
	})

	t.Run("short", func(t *testing.T) {
		testJunkTemplate(t, 1000, true)
	})
}

func testJunkTemplate(t *testing.T, times int, short bool) {
	t.Run("x86", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "386"
		injector.opts = new(Options)
		injector.ctx = new(Context)
		err := injector.initAssembler()
		require.NoError(t, err)

		for i := 0; i < times; i++ {
			data := injector.junkTemplate(short)
			require.NotEmpty(t, data)
		}

		err = injector.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "amd64"
		injector.opts = new(Options)
		injector.ctx = new(Context)
		err := injector.initAssembler()
		require.NoError(t, err)

		for i := 0; i < times; i++ {
			data := injector.junkTemplate(short)
			require.NotEmpty(t, data)
		}

		err = injector.Close()
		require.NoError(t, err)
	})
}

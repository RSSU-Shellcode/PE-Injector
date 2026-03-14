package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGarbage(t *testing.T) {
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

func TestGarbageTemplate(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		testGarbageTemplate(t, false)
	})

	t.Run("common", func(t *testing.T) {
		testGarbageTemplate(t, true)
	})
}

func testGarbageTemplate(t *testing.T, short bool) {
	t.Run("x86", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "386"
		injector.opts = new(Options)
		injector.ctx = new(Context)
		err := injector.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			data := injector.garbageTemplate(short)
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

		for i := 0; i < 10; i++ {
			data := injector.garbageTemplate(short)
			require.NotEmpty(t, data)
		}

		err = injector.Close()
		require.NoError(t, err)
	})
}

func TestGarbageTemplateFuzz(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		testGarbageTemplateFuzz(t, false)
	})

	t.Run("common", func(t *testing.T) {
		testGarbageTemplateFuzz(t, true)
	})
}

func testGarbageTemplateFuzz(t *testing.T, short bool) {
	t.Run("x86", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "386"
		injector.opts = new(Options)
		injector.ctx = new(Context)
		err := injector.initAssembler()
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			data := injector.garbageTemplate(short)
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

		for i := 0; i < 1000; i++ {
			data := injector.garbageTemplate(short)
			require.NotEmpty(t, data)
		}

		err = injector.Close()
		require.NoError(t, err)
	})
}

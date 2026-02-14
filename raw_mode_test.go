package injector

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRawMode(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		NotSaveContext: true,
		NoGarbageInst:  true,
		RandSeed:       1234,
	}

	t.Run("auto", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendText = false
		opts.ForceCreateText = false
		testRawMode(t, injector, opts, "auto")
	})

	t.Run("code cave", func(t *testing.T) {
		opts.ForceCodeCave = true
		opts.ForceExtendText = false
		opts.ForceCreateText = false
		testRawMode(t, injector, opts, ModeCodeCave)
	})

	t.Run("extend text section", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendText = true
		opts.ForceCreateText = false
		testRawMode(t, injector, opts, ModeExtendText)
	})

	t.Run("create text section", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendText = false
		opts.ForceCreateText = true
		testRawMode(t, injector, opts, ModeCreateText)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testRawMode(t *testing.T, injector *Injector, opts *Options, mode string) {
	t.Run("x86", func(t *testing.T) {
		expected := mode
		if expected == "auto" {
			expected = ModeCodeCave
		}

		image, err := os.ReadFile("testdata/image_exe_x86.dat")
		require.NoError(t, err)
		shellcode := []byte{
			0x90,
			0x66, 0x90,
		}

		ctx, err := injector.InjectRaw(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, expected, ctx.Mode)
		fmt.Println(ctx.LoaderHex)
		fmt.Println(ctx.LoaderInst)

		testExecuteEXE(t, "testdata/injected_x86.exe", ctx.Output)
		testCheckOutputImage(t, image, ctx.Output, ctx.Mode)
	})

	t.Run("x64", func(t *testing.T) {
		expected := mode
		if expected == "auto" {
			expected = ModeCodeCave
		}

		image, err := os.ReadFile("testdata/image_exe_x64.dat")
		require.NoError(t, err)
		shellcode := []byte{
			0x90,
			0x66, 0x90,
		}

		ctx, err := injector.InjectRaw(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, expected, ctx.Mode)
		fmt.Println(ctx.LoaderHex)
		fmt.Println(ctx.LoaderInst)

		testExecuteEXE(t, "testdata/injected_x64.exe", ctx.Output)
		testCheckOutputImage(t, image, ctx.Output, ctx.Mode)
	})
}

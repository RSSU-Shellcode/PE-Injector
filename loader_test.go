package injector

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoader(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		NotSaveContext: true,
		NoGarbageInst:  true,
		RandSeed:       1234,
	}

	t.Run("auto", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCodeCaveNS = false
		opts.ForceExtendText = false
		opts.ForceExtendTextNS = false
		opts.ForceCreateText = false
		testLoader(t, injector, opts, "auto")
	})

	t.Run("code cave", func(t *testing.T) {
		opts.ForceCodeCave = true
		opts.ForceCodeCaveNS = false
		opts.ForceExtendText = false
		opts.ForceExtendTextNS = false
		opts.ForceCreateText = false
		testLoader(t, injector, opts, ModeCodeCave)
	})

	t.Run("code cave with new section", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCodeCaveNS = true
		opts.ForceExtendText = false
		opts.ForceExtendTextNS = false
		opts.ForceCreateText = false
		testLoader(t, injector, opts, ModeCodeCaveNS)
	})

	t.Run("extend text section", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCodeCaveNS = false
		opts.ForceExtendText = true
		opts.ForceExtendTextNS = false
		opts.ForceCreateText = false
		testLoader(t, injector, opts, ModeExtendText)
	})

	t.Run("extend text with new section", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCodeCaveNS = false
		opts.ForceExtendText = false
		opts.ForceExtendTextNS = true
		opts.ForceCreateText = false
		testLoader(t, injector, opts, ModeExtendTextNS)
	})

	t.Run("create text section", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCodeCaveNS = false
		opts.ForceExtendText = false
		opts.ForceExtendTextNS = false
		opts.ForceCreateText = true
		testLoader(t, injector, opts, ModeCreateText)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testLoader(t *testing.T, injector *Injector, opts *Options, mode string) {
	t.Run("x86", func(t *testing.T) {
		if opts.ForceCodeCave {
			return
		}

		expected := mode
		if expected == "auto" {
			expected = ModeCodeCaveNS
		}

		image, err := os.ReadFile("testdata/image_exe_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
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
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, expected, ctx.Mode)
		fmt.Println(ctx.LoaderHex)
		fmt.Println(ctx.LoaderInst)

		testExecuteEXE(t, "testdata/injected_x64.exe", ctx.Output)
		testCheckOutputImage(t, image, ctx.Output, ctx.Mode)
	})
}

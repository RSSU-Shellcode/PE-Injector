package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoader(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		RandSeed:       1234,
		NotSaveContext: true,
	}

	t.Run("auto mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendSection = false
		opts.ForceCreateSection = false
		testLoader(t, injector, opts, "auto")
	})

	t.Run("code cave mode", func(t *testing.T) {
		opts.ForceCodeCave = true
		opts.ForceExtendSection = false
		opts.ForceCreateSection = false
		testLoader(t, injector, opts, ModeCodeCave)
	})

	t.Run("extend section mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendSection = true
		opts.ForceCreateSection = false
		testLoader(t, injector, opts, ModeExtendSection)
	})

	t.Run("create section mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendSection = false
		opts.ForceCreateSection = true
		testLoader(t, injector, opts, ModeCreateSection)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testLoader(t *testing.T, injector *Injector, opts *Options, mode string) {
	t.Run("x86", func(t *testing.T) {
		if opts.ForceCodeCave || opts.ForceExtendSection {
			return
		}
		mode := mode
		if mode == "auto" {
			mode = ModeCreateSection
		}

		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, mode, ctx.Mode)

		testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		mode := mode
		if mode == "auto" {
			mode = ModeCodeCave
		}

		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, mode, ctx.Mode)

		testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
	})
}

func TestToDB(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		data := []byte{1, 2, 3, 4}
		output := toDB(data)

		expected := ".byte 0x01, 0x02, 0x03, 0x04, "
		require.Equal(t, expected, output)
	})

	t.Run("empty bytes", func(t *testing.T) {
		output := toDB(nil)
		require.Empty(t, output)
	})
}

func TestToHex(t *testing.T) {
	output := toHex(15)
	require.Equal(t, "0xF", output)
}

func TestToRegDWORD(t *testing.T) {
	for _, item := range []*struct {
		input  string
		output string
	}{
		{"rax", "eax"},
		{"rbx", "ebx"},
		{"rcx", "ecx"},
		{"rdx", "edx"},
		{"rdi", "edi"},
		{"rsi", "esi"},
		{"rsp", "esp"},
		{"r8", "r8d"},
		{"r9", "r9d"},
		{"r10", "r10d"},
		{"r11", "r11d"},
		{"r12", "r12d"},
		{"r13", "r13d"},
		{"r14", "r14d"},
		{"r15", "r15d"},
	} {
		output := toRegDWORD(item.input)
		require.Equal(t, item.output, output)
	}
}

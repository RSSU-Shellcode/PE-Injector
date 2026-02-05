package injector

import (
	"bytes"
	"debug/pe"
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
			expected = ModeExtendText
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
		testCheckOutput(t, image, ctx.Output, ctx.Mode)
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
		testCheckOutput(t, image, ctx.Output, ctx.Mode)
	})
}

func testCheckOutput(t *testing.T, origin, output []byte, mode string) {
	ori, err := pe.NewFile(bytes.NewReader(origin))
	require.NoError(t, err)
	out, err := pe.NewFile(bytes.NewReader(output))
	require.NoError(t, err)
	switch mode {
	case ModeCodeCave:
		require.Equal(t, ori, out)
	case ModeCodeCaveNS:
		require.Equal(t, ori.Sections[0].VirtualSize, out.Sections[0].VirtualSize)
		require.Equal(t, ori.Sections[0].Size, out.Sections[0].Size)
		require.Equal(t, len(ori.Sections)+1, len(out.Sections))
	case ModeExtendText:
		require.Less(t, ori.Sections[0].VirtualSize, out.Sections[0].VirtualSize)
		require.Less(t, ori.Sections[0].Size, out.Sections[0].Size)
		require.Equal(t, len(ori.Sections), len(out.Sections))
	case ModeExtendTextNS:
		require.Less(t, ori.Sections[0].VirtualSize, out.Sections[0].VirtualSize)
		require.Less(t, ori.Sections[0].Size, out.Sections[0].Size)
		require.Equal(t, len(ori.Sections)+1, len(out.Sections))
	case ModeCreateText:
		require.Equal(t, ori.Sections[0].VirtualSize, out.Sections[0].VirtualSize)
		require.Equal(t, ori.Sections[0].Size, out.Sections[0].Size)
		require.Equal(t, len(ori.Sections)+1, len(out.Sections))
	}
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

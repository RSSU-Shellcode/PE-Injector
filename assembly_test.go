package injector

import (
	"fmt"
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
		image, err := os.ReadFile("testdata/image_exe_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)
		loader, err := os.ReadFile("testdata/relocate_x86.asm")
		require.NoError(t, err)
		opts.LoaderX86 = string(loader)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, ModeCodeCaveNS, ctx.Mode)

		testExecuteEXE(t, "testdata/injected_x86.exe", ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_exe_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)
		loader, err := os.ReadFile("testdata/relocate_x64.asm")
		require.NoError(t, err)
		opts.LoaderX64 = string(loader)

		ctx, err := injector.Inject(image, shellcode, opts)
		require.NoError(t, err)
		require.Equal(t, ModeCodeCave, ctx.Mode)

		testExecuteEXE(t, "testdata/injected_x64.exe", ctx.Output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestPrintInstructions(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		binHex, insts, err := printInstructions(testAddX86, 32)
		require.NoError(t, err)
		fmt.Println(binHex)
		fmt.Println(insts)
	})

	t.Run("x64", func(t *testing.T) {
		binHex, insts, err := printInstructions(testAddX64, 64)
		require.NoError(t, err)
		fmt.Println(binHex)
		fmt.Println(insts)
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

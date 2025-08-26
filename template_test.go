package injector

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplate(t *testing.T) {
	loaderX86 := `
.code32

entry:
  // check Integer
  mov {{.Reg.ecx}}, {{hex .CIEnc.Const_1}}
  xor {{.Reg.ecx}}, {{hex .CIKey.Const_1}}
  cmp {{.Reg.ecx}}, 123
  jne panic

  mov {{.Reg.ecx}}, {{hex .CIEnc.Const_2}}
  xor {{.Reg.ecx}}, {{hex .CIKey.Const_2}}
  cmp {{.Reg.ecx}}, 456
  jne panic

  // check ANSI
  mov {{.Reg.eax}}, {{index .CAEnc.ANSI_1 0}}
  mov {{.Reg.ecx}}, {{index .CAKey.ANSI_1 0}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}
  mov {{.Reg.eax}}, {{index .CAEnc.ANSI_1 1}}
  mov {{.Reg.ecx}}, {{index .CAKey.ANSI_1 1}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}

  // "ansi"
  push 0x69736E61

  // compare string
  mov esi, esp
  lea edi, [esp+4]
  mov ecx, 4
  cld
  repe cmpsb
  jnz panic

  // check UTF-16
  mov {{.Reg.eax}}, {{index .CWEnc.UTF16_1 0}}
  mov {{.Reg.ecx}}, {{index .CWKey.UTF16_1 0}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}
  mov {{.Reg.eax}}, {{index .CWEnc.UTF16_1 1}}
  mov {{.Reg.ecx}}, {{index .CWKey.UTF16_1 1}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}
  mov {{.Reg.eax}}, {{index .CWEnc.UTF16_1 2}}
  mov {{.Reg.ecx}}, {{index .CWKey.UTF16_1 2}}
  xor {{.Reg.eax}}, {{.Reg.ecx}}
  push {{.Reg.eax}}

  // "utf16"
  push 0x00000036
  push 0x00310066
  push 0x00740075

  // compare string
  mov esi, esp
  lea edi, [esp+3*4]
  mov ecx, 10
  cld
  repe cmpsb
  jnz panic

  // check Arguments
  mov {{.Reg.ecx}}, {{.Args.Arg_1}}
  cmp {{.Reg.ecx}}, 123
  jne panic
  mov {{.Reg.ecx}}, {{.Args.Arg_2}}
  cmp {{.Reg.ecx}}, 456
  jne panic

  // check Switches
  {{if .Switches.Switch_1}}
    jmp panic
  {{end}}

  {{if not .Switches.Switch_2}}
    jmp panic
  {{end}}

  add esp, 9*4

  // mark the end of loader
  {{db .EndOfLoader}}

panic:
  int3
`
	loaderX64 := `
.code64

`
	tpl := &Template{
		LoaderX86:     loaderX86,
		LoaderX64:     loaderX64,
		MaxNumInstX86: 150,
		MaxNumInstX64: 100,

		Integer: map[string]uint32{
			"Const_1": 123,
			"Const_2": 456,
		},

		ANSI: map[string]string{
			"ANSI_1": "ansi",
		},

		UTF16: map[string]string{
			"UTF16_1": "utf16",
		},

		Arguments: map[string]any{
			"Arg_1": uint16(123),
			"Arg_2": uint32(456),
		},

		Switches: map[string]bool{
			"Switch_1": false,
			"Switch_2": true,
		},
	}

	injector := NewInjector()

	opts := &Options{
		Template: tpl,
	}

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		payload := []byte("payload_x86")

		ctx, err := injector.Inject(image, payload, opts)
		require.NoError(t, err)
		require.Equal(t, ModeCodeCave, ctx.Mode)
		fmt.Println(ctx.Loader[0])
		fmt.Println(ctx.Loader[1])

		testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		payload := []byte("payload_x64")

		ctx, err := injector.Inject(image, payload, opts)
		require.NoError(t, err)
		require.Equal(t, ModeCodeCave, ctx.Mode)
		fmt.Println(ctx.Loader[0])
		fmt.Println(ctx.Loader[1])

		testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestTemplate_Check(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		tpl := Template{
			LoaderX86:     ".code32",
			LoaderX64:     ".code64",
			MaxNumInstX86: 86,
			MaxNumInstX64: 64,
		}

		err := tpl.Check()
		require.NoError(t, err)
	})

	t.Run("empty loader", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			tpl := Template{}

			err := tpl.Check()
			errStr := "empty loader template for x86"
			require.EqualError(t, err, errStr)
		})

		t.Run("x64", func(t *testing.T) {
			tpl := Template{
				LoaderX86: ".code32",
			}

			err := tpl.Check()
			errStr := "empty loader template for x64"
			require.EqualError(t, err, errStr)
		})
	})

	t.Run("invalid num inst", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			tpl := Template{
				LoaderX86:     ".code32",
				LoaderX64:     ".code64",
				MaxNumInstX86: 0,
			}

			err := tpl.Check()
			errStr := "invalid maximum number of loader instructions for x86"
			require.EqualError(t, err, errStr)
		})

		t.Run("x64", func(t *testing.T) {
			tpl := Template{
				LoaderX86:     ".code32",
				LoaderX64:     ".code64",
				MaxNumInstX86: 86,
				MaxNumInstX64: 0,
			}

			err := tpl.Check()
			errStr := "invalid maximum number of loader instructions for x64"
			require.EqualError(t, err, errStr)
		})
	})
}

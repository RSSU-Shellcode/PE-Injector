package injector

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplate(t *testing.T) {
	injector := NewInjector()

	loaderX86, err := os.ReadFile("testdata/template_x86.asm")
	require.NoError(t, err)
	loaderX64, err := os.ReadFile("testdata/template_x64.asm")
	require.NoError(t, err)
	tpl := &Template{
		LoaderX86:     string(loaderX86),
		LoaderX64:     string(loaderX64),
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

	err = injector.Close()
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

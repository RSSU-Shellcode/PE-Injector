package injector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplate(t *testing.T) {

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

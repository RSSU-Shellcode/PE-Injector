package injector

import (
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestAnalyze(t *testing.T) {
	t.Run("exe", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_exe_x86.dat")
			require.NoError(t, err)

			info, err := Analyze(image)
			require.NoError(t, err)

			spew.Dump(info)

			require.Equal(t, "x86", info.ImageArch)
			require.Equal(t, imageTypeEXE, info.ImageType)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_exe_x64.dat")
			require.NoError(t, err)

			info, err := Analyze(image)
			require.NoError(t, err)

			spew.Dump(info)

			require.Equal(t, "x64", info.ImageArch)
			require.Equal(t, imageTypeEXE, info.ImageType)
		})
	})

	t.Run("dll", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_dll_x86.dat")
			require.NoError(t, err)

			info, err := Analyze(image)
			require.NoError(t, err)

			spew.Dump(info)

			require.Equal(t, "x86", info.ImageArch)
			require.Equal(t, imageTypeDLL, info.ImageType)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_dll_x64.dat")
			require.NoError(t, err)

			info, err := Analyze(image)
			require.NoError(t, err)

			spew.Dump(info)

			require.Equal(t, "x64", info.ImageArch)
			require.Equal(t, imageTypeDLL, info.ImageType)
		})
	})

	t.Run("with signature", func(t *testing.T) {
		image, err := os.ReadFile("testdata/putty.dat")
		require.NoError(t, err)

		info, err := Analyze(image)
		require.NoError(t, err)

		spew.Dump(info)

		require.True(t, info.HasSignature)
	})
}

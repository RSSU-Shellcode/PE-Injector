package injector

import (
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestAnalyze(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)

		info, err := Analyze(image)
		require.NoError(t, err)

		spew.Dump(info)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)

		info, err := Analyze(image)
		require.NoError(t, err)

		spew.Dump(info)
	})

	t.Run("with signature", func(t *testing.T) {
		image, err := os.ReadFile("testdata/putty.dat")
		require.NoError(t, err)

		info, err := Analyze(image)
		require.NoError(t, err)

		spew.Dump(info)
	})
}

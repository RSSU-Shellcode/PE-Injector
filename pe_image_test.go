package injector

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadImage(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		peFile, err := pe.NewFile(bytes.NewReader(image))
		require.NoError(t, err)
		injector.img = peFile
		injector.arch = "386"
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		injector.loadImage(image)
		for _, iat := range injector.iat {
			fmt.Println(iat.dll, iat.proc, iat.addr)
		}
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		peFile, err := pe.NewFile(bytes.NewReader(image))
		require.NoError(t, err)
		injector.img = peFile
		injector.arch = "amd64"
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		injector.loadImage(image)
		for _, iat := range injector.iat {
			fmt.Println(iat.dll, iat.proc, iat.addr)
		}
	})

	err := injector.Close()
	require.NoError(t, err)
}

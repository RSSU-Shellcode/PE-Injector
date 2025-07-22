package injector

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanCodeCave(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		peFile, err := pe.NewFile(bytes.NewReader(image))
		require.NoError(t, err)
		injector.img = peFile
		injector.arch = "386"

		caves, err := injector.scanCodeCave()
		require.NoError(t, err)

		fmt.Println(len(caves))
		for _, cave := range caves {
			fmt.Println(cave.virtualAddr, cave.pointerToRaw, cave.size)
		}

		require.Equal(t, 200, len(caves))
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		peFile, err := pe.NewFile(bytes.NewReader(image))
		require.NoError(t, err)
		injector.img = peFile
		injector.arch = "amd64"

		caves, err := injector.scanCodeCave()
		require.NoError(t, err)

		fmt.Println(len(caves))
		for _, cave := range caves {
			fmt.Println(cave.virtualAddr, cave.pointerToRaw, cave.size)
		}

		require.Equal(t, 749, len(caves))
	})

	err := injector.Close()
	require.NoError(t, err)
}

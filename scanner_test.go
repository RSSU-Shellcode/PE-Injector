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

		err = injector.scanCodeCave()
		require.NoError(t, err)

		fmt.Println(len(injector.caves))
		for _, cave := range injector.caves {
			fmt.Println(cave.virtualAddr, cave.pointerToRaw, cave.size)
		}
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		peFile, err := pe.NewFile(bytes.NewReader(image))
		require.NoError(t, err)
		injector.img = peFile
		injector.arch = "amd64"

		err = injector.scanCodeCave()
		require.NoError(t, err)

		fmt.Println(len(injector.caves))
		for _, cave := range injector.caves {
			fmt.Println(cave.virtualAddr, cave.pointerToRaw, cave.size)
		}
	})

	err := injector.Close()
	require.NoError(t, err)
}

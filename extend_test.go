package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtendTextSection(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(1024)
		require.NoError(t, err)

		os.WriteFile("F:\\output.exe", output, 0644)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(1024)
		require.NoError(t, err)

		os.WriteFile("F:\\output.exe", output, 0644)
	})

	err := injector.Close()
	require.NoError(t, err)
}

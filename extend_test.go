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

		output, err := injector.extendTextSection(1427)
		require.NoError(t, err)

		testExecuteImage(t, "testdata/extended_x86.exe", output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		output, err := injector.extendTextSection(7433)
		require.NoError(t, err)

		testExecuteImage(t, "testdata/extended_x64.exe", output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

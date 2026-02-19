//go:build !windows

package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func testExecuteEXE(t *testing.T, path string, image []byte, _ ...string) {
	err := os.WriteFile(path, image, 0600)
	require.NoError(t, err)
}

func testExecuteDLL(t *testing.T, path string, image []byte) {
	err := os.WriteFile(path, image, 0600)
	require.NoError(t, err)
}

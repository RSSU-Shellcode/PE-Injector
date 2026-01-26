package injector

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScan(t *testing.T) {
	t.Run("common", func(t *testing.T) {
		results, err := Scan("testdata", nil)
		require.NoError(t, err)

		for _, result := range results {
			fmt.Println(result.Path)
		}
	})

	t.Run("no signature", func(t *testing.T) {
		opts := &ScanOptions{
			NoSignature: true,
		}

		results, err := Scan("testdata", opts)
		require.NoError(t, err)

		for _, result := range results {
			fmt.Println(result.Path)
		}
	})

	t.Run("no load config", func(t *testing.T) {
		opts := &ScanOptions{
			NoLoadConfig: true,
		}

		results, err := Scan("testdata", opts)
		require.NoError(t, err)

		for _, result := range results {
			fmt.Println(result.Path)
		}
	})

	t.Run("ignore rank", func(t *testing.T) {
		opts := &ScanOptions{
			IgnoreRank: true,
		}

		results, err := Scan("testdata", opts)
		require.NoError(t, err)

		for _, result := range results {
			fmt.Println(result.Path)
		}
	})
}

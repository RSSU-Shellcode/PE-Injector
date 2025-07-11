package injector

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInjector(t *testing.T) {
	injector := NewInjector()

	t.Run("common", func(t *testing.T) {
		testInjector(t, injector, nil)
	})

	t.Run("set address", func(t *testing.T) {
		opts := Options{
			Address: 0x469D20,
		}
		testInjector(t, injector, &opts)
	})

	t.Run("not save context", func(t *testing.T) {
		opts := Options{
			NotSaveContext: true,
		}
		testInjector(t, injector, &opts)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testInjector(t *testing.T, injector *Injector, opts *Options) {
	t.Run("loader", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x86.exe", output, 0600)
			require.NoError(t, err)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x64.exe", output, 0600)
			require.NoError(t, err)
		})
	})

	t.Run("raw", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x86.exe", output, 0600)
			require.NoError(t, err)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x64.exe", output, 0600)
			require.NoError(t, err)
		})
	})
}

// TODO add more tests
func TestSpecificSeed(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		Address:  0x469D20,
		RandSeed: 1234,
	}

	t.Run("loader", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x86.exe", output, 0600)
			require.NoError(t, err)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x64.exe", output, 0600)
			require.NoError(t, err)
		})
	})

	t.Run("raw", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x86.exe", output, 0600)
			require.NoError(t, err)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			err = os.WriteFile("testdata/injected_x64.exe", output, 0600)
			require.NoError(t, err)
		})
	})

	err := injector.Close()
	require.NoError(t, err)
}

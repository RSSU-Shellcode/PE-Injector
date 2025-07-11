package injector

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInjector(t *testing.T) {
	injector := NewInjector()

	t.Run("common", func(t *testing.T) {
		testInjector(t, injector, nil)
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

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x64.exe", output)
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

			testExecuteImage(t, "testdata/injected_x86.exe", output)
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

			testExecuteImage(t, "testdata/injected_x64.exe", output)
		})
	})
}

func TestSpecificAddress(t *testing.T) {
	injector := NewInjector()

	t.Run("loader", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			opts := &Options{
				Address: 0x46A590,
			}

			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})

		t.Run("x64", func(t *testing.T) {
			opts := &Options{
				Address: 0x469D20,
			}

			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x64.exe", output)
		})
	})

	t.Run("raw", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			opts := &Options{
				Address: 0x46A590,
			}

			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})

		t.Run("x64", func(t *testing.T) {
			opts := &Options{
				Address: 0x469D20,
			}

			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x64.exe", output)
		})
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestSpecificSeed(t *testing.T) {
	injector := NewInjector()

	opts := &Options{
		RandSeed: 1234,
	}

	t.Run("loader", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
			require.NoError(t, err)

			output1, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output1)
			output2, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output2)
			require.Equal(t, output1, output2)

			testExecuteImage(t, "testdata/injected_x86.exe", output1)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			output1, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output1)
			output2, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output2)
			require.Equal(t, output1, output2)

			testExecuteImage(t, "testdata/injected_x64.exe", output1)
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

			output1, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output1)
			output2, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output2)
			require.Equal(t, output1, output2)

			testExecuteImage(t, "testdata/injected_x86.exe", output1)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			output1, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output1)
			output2, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output2)
			require.Equal(t, output1, output2)

			testExecuteImage(t, "testdata/injected_x64.exe", output1)
		})
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testExecuteImage(t *testing.T, path string, image []byte) {
	err := os.WriteFile(path, image, 0600)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	cmd := exec.Command(path)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	require.NoError(t, err)

	time.Sleep(time.Second)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	require.Contains(t, buf.String(), "Hello World!")
}

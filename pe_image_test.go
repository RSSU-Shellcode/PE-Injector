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

func TestExtendSection(t *testing.T) {
	injector := NewInjector()

	t.Run("reuse", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			peFile, err := pe.NewFile(bytes.NewReader(image))
			require.NoError(t, err)
			injector.img = peFile
			injector.arch = "386"
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			data := []byte("Hello Injector!")
			rva := injector.extendSection(data)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup

			peFile, err = pe.NewFile(bytes.NewReader(output))
			require.NoError(t, err)
			last := peFile.Sections[len(peFile.Sections)-1]
			require.Less(t, last.VirtualSize, uint32(512))
			require.Equal(t, last.Size, uint32(512))

			testExecuteImage(t, "testdata/injected_x86.exe", output)
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

			data := []byte("Hello Injector!")
			rva := injector.extendSection(data)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup

			peFile, err = pe.NewFile(bytes.NewReader(output))
			require.NoError(t, err)
			last := peFile.Sections[len(peFile.Sections)-1]
			require.Less(t, last.VirtualSize, uint32(512))
			require.Equal(t, last.Size, uint32(512))

			testExecuteImage(t, "testdata/injected_x64.exe", output)
		})
	})

	t.Run("extend", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			peFile, err := pe.NewFile(bytes.NewReader(image))
			require.NoError(t, err)
			injector.img = peFile
			injector.arch = "386"
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			data := bytes.Repeat([]byte("Hello Injector!"), 1024)
			rva := injector.extendSection(data)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup

			peFile, err = pe.NewFile(bytes.NewReader(output))
			require.NoError(t, err)
			last := peFile.Sections[len(peFile.Sections)-1]
			require.Greater(t, last.VirtualSize, uint32(len(data)))
			require.Greater(t, last.Size, uint32(len(data)))

			testExecuteImage(t, "testdata/injected_x86.exe", output)
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

			data := bytes.Repeat([]byte("Hello Injector!"), 1024)
			rva := injector.extendSection(data)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup

			peFile, err = pe.NewFile(bytes.NewReader(output))
			require.NoError(t, err)
			last := peFile.Sections[len(peFile.Sections)-1]
			require.Greater(t, last.VirtualSize, uint32(len(data)))
			require.Greater(t, last.Size, uint32(len(data)))

			testExecuteImage(t, "testdata/injected_x64.exe", output)
		})
	})

	err := injector.Close()
	require.NoError(t, err)
}

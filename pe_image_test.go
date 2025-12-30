package injector

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestProcessEAT(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/kernel32_x86.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		injector.loadImage(image)
		for _, eat := range injector.eat {
			fmt.Printf("%s 0x%X\n", eat.proc, eat.rva)
		}
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/kernel32_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		injector.loadImage(image)
		for _, eat := range injector.eat {
			fmt.Printf("%s 0x%X\n", eat.proc, eat.rva)
		}
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestProcessIAT(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		injector.loadImage(image)
		for _, iat := range injector.iat {
			fmt.Printf("%s %s 0x%X\n", iat.dll, iat.proc, iat.rva)
		}
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		injector.loadImage(image)
		for _, iat := range injector.iat {
			fmt.Printf("%s %s 0x%X\n", iat.dll, iat.proc, iat.rva)
		}
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestRemoveSignature(t *testing.T) {
	image, err := os.ReadFile("testdata/putty.dat")
	require.NoError(t, err)
	peFile, err := pe.NewFile(bytes.NewReader(image))
	require.NoError(t, err)
	hdr := peFile.OptionalHeader.(*pe.OptionalHeader64)
	dd := hdr.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
	require.NotZero(t, dd.VirtualAddress)
	require.NotZero(t, dd.Size)

	injector := NewInjector()
	err = injector.preprocess(image, nil)
	require.NoError(t, err)
	check := func() {
		peOut, err := pe.NewFile(bytes.NewReader(injector.dup))
		require.NoError(t, err)
		hdr = peOut.OptionalHeader.(*pe.OptionalHeader64)
		dd = hdr.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		require.Zero(t, dd.VirtualAddress)
		require.Zero(t, dd.Size)
	}

	t.Run("code cave", func(t *testing.T) {
		check()
	})

	t.Run("extend section", func(t *testing.T) {
		_, err = injector.extendSection(bytes.Repeat([]byte{0x10}, 4096))
		require.NoError(t, err)

		check()
	})

	t.Run("create section", func(t *testing.T) {
		_, err = injector.createSection(".test", 4096)
		require.NoError(t, err)

		check()
	})

	err = injector.Close()
	require.NoError(t, err)
}

func TestRemoveLoadConfig(t *testing.T) {
	image, err := os.ReadFile("testdata/putty.dat")
	require.NoError(t, err)
	peFile, err := pe.NewFile(bytes.NewReader(image))
	require.NoError(t, err)
	hdr := peFile.OptionalHeader.(*pe.OptionalHeader64)
	dd := hdr.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
	require.NotZero(t, dd.VirtualAddress)
	require.NotZero(t, dd.Size)

	injector := NewInjector()
	err = injector.preprocess(image, nil)
	require.NoError(t, err)
	check := func() {
		peOut, err := pe.NewFile(bytes.NewReader(injector.dup))
		require.NoError(t, err)
		hdr = peOut.OptionalHeader.(*pe.OptionalHeader64)
		dd = hdr.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
		require.Zero(t, dd.VirtualAddress)
		require.Zero(t, dd.Size)
	}

	t.Run("code cave", func(t *testing.T) {
		check()
	})

	t.Run("extend section", func(t *testing.T) {
		_, err = injector.extendSection(bytes.Repeat([]byte{0x10}, 4096))
		require.NoError(t, err)

		check()
	})

	t.Run("create section", func(t *testing.T) {
		_, err = injector.createSection(".test", 4096)
		require.NoError(t, err)

		check()
	})

	err = injector.Close()
	require.NoError(t, err)
}

func TestCalculateChecksum(t *testing.T) {
	image, err := os.ReadFile("testdata/putty.dat")
	require.NoError(t, err)
	peFile, err := pe.NewFile(bytes.NewReader(image))
	require.NoError(t, err)
	hdr := peFile.OptionalHeader.(*pe.OptionalHeader64)

	checksum := calculateChecksum(image)
	require.Equal(t, hdr.CheckSum, checksum)
}

func TestExtendSection(t *testing.T) {
	injector := NewInjector()

	t.Run("reuse", func(t *testing.T) {
		t.Run("x86", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			data := []byte("Hello Injector!")
			rva, err := injector.extendSection(data)
			require.NoError(t, err)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup
			peFile, err := pe.NewFile(bytes.NewReader(output))
			require.NoError(t, err)
			last := peFile.Sections[len(peFile.Sections)-1]
			require.Less(t, last.VirtualSize, uint32(512))
			require.Equal(t, last.Size, uint32(512))

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			data := []byte("Hello Injector!")
			rva, err := injector.extendSection(data)
			require.NoError(t, err)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup
			peFile, err := pe.NewFile(bytes.NewReader(output))
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
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			data := bytes.Repeat([]byte("Hello Injector!"), 1024)
			rva, err := injector.extendSection(data)
			require.NoError(t, err)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup
			peFile, err := pe.NewFile(bytes.NewReader(output))
			require.NoError(t, err)
			last := peFile.Sections[len(peFile.Sections)-1]
			require.Greater(t, last.VirtualSize, uint32(len(data)))
			require.Greater(t, last.Size, uint32(len(data)))

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			err = injector.preprocess(image, nil)
			require.NoError(t, err)

			data := bytes.Repeat([]byte("Hello Injector!"), 1024)
			rva, err := injector.extendSection(data)
			require.NoError(t, err)
			fmt.Printf("rva: 0x%X\n", rva)

			output := injector.dup
			peFile, err := pe.NewFile(bytes.NewReader(output))
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

func TestCreateSection(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		sh, err := injector.createSection(".patch", 666)
		require.NoError(t, err)
		spew.Dump(sh)

		data := bytes.Repeat([]byte("Hello Injector!"), 4)
		copy(injector.dup[sh.Offset:], data)

		output := injector.dup
		peFile, err := pe.NewFile(bytes.NewReader(output))
		require.NoError(t, err)
		require.Greater(t, peFile.NumberOfSections, injector.img.NumberOfSections)

		testExecuteImage(t, "testdata/injected_x86.exe", output)
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		err = injector.preprocess(image, nil)
		require.NoError(t, err)

		sh, err := injector.createSection(".patch", 666)
		require.NoError(t, err)
		spew.Dump(sh)

		data := bytes.Repeat([]byte("Hello Injector!"), 4)
		copy(injector.dup[sh.Offset:], data)

		output := injector.dup
		peFile, err := pe.NewFile(bytes.NewReader(output))
		require.NoError(t, err)
		require.Greater(t, peFile.NumberOfSections, injector.img.NumberOfSections)

		testExecuteImage(t, "testdata/injected_x64.exe", output)
	})

	err := injector.Close()
	require.NoError(t, err)
}

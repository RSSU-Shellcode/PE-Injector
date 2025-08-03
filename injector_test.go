package injector

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	code := m.Run()
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/IM", "calc.exe", "/F").Run()
		_ = exec.Command("taskkill", "/IM", "win32calc.exe", "/F").Run()
	}
	os.Exit(code)
}

func TestInjector_Inject(t *testing.T) {
	injector := NewInjector()
	fmt.Println("seed:", injector.Seed())

	t.Run("common", func(t *testing.T) {
		opts := new(Options)

		testInjectorInject(t, injector, opts)
	})

	t.Run("not save context", func(t *testing.T) {
		opts := Options{
			NotSaveContext: true,
		}

		testInjectorInject(t, injector, &opts)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testInjectorInject(t *testing.T, injector *Injector, opts *Options) {
	t.Run("auto mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendSection = false
		opts.ForceCreateSection = false
		testInjectorInjectWithOpts(t, injector, opts)
	})

	t.Run("code cave mode", func(t *testing.T) {
		opts.ForceCodeCave = true
		opts.ForceExtendSection = false
		opts.ForceCreateSection = false
		testInjectorInjectWithOpts(t, injector, opts)
	})

	t.Run("extend section mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendSection = true
		opts.ForceCreateSection = false
		testInjectorInjectWithOpts(t, injector, opts)
	})

	t.Run("create section mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceExtendSection = false
		opts.ForceCreateSection = true
		testInjectorInjectWithOpts(t, injector, opts)
	})
}

func testInjectorInjectWithOpts(t *testing.T, injector *Injector, opts *Options) {
	t.Run("x86", func(t *testing.T) {
		if opts.ForceCodeCave || opts.ForceExtendSection {
			return
		}

		t.Run("entry point", func(t *testing.T) {
			opts.Address = 0

			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})

		t.Run("custom address", func(t *testing.T) {
			if opts.NotSaveContext {
				return
			}
			opts.Address = 0x46A6F1

			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x86.exe", output)
		})
	})

	t.Run("x64", func(t *testing.T) {
		t.Run("entry point", func(t *testing.T) {
			opts.Address = 0

			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			output, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImage(t, "testdata/injected_x64.exe", output)
		})

		t.Run("custom address", func(t *testing.T) {
			if opts.NotSaveContext {
				return
			}
			opts.Address = 0x469E4F

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
}

func TestInjector_InjectRaw(t *testing.T) {
	injector := NewInjector()
	fmt.Println("seed:", injector.Seed())

	t.Run("common", func(t *testing.T) {
		opts := new(Options)

		testInjectorInjectRaw(t, injector, opts)
	})

	t.Run("not save context", func(t *testing.T) {
		opts := Options{
			NotSaveContext: true,
		}
		testInjectorInjectRaw(t, injector, &opts)
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testInjectorInjectRaw(t *testing.T, injector *Injector, opts *Options) {
	t.Run("auto mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCreateSection = false
		testInjectorInjectRawWithOpts(t, injector, opts)
	})

	t.Run("code cave mode", func(t *testing.T) {
		opts.ForceCodeCave = true
		opts.ForceCreateSection = false
		testInjectorInjectRawWithOpts(t, injector, opts)
	})

	t.Run("create section mode", func(t *testing.T) {
		opts.ForceCodeCave = false
		opts.ForceCreateSection = true
		testInjectorInjectRawWithOpts(t, injector, opts)
	})
}

func testInjectorInjectRawWithOpts(t *testing.T, injector *Injector, opts *Options) {
	t.Run("x86", func(t *testing.T) {
		t.Run("entry point", func(t *testing.T) {
			opts.Address = 0

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

		t.Run("custom address", func(t *testing.T) {
			opts.Address = 0x46A6F1

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
	})

	t.Run("x64", func(t *testing.T) {
		t.Run("entry point", func(t *testing.T) {
			opts.Address = 0

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

		t.Run("custom address", func(t *testing.T) {
			opts.Address = 0x469E4F

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
				Address: 0x46A6F1,
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
				Address: 0x469E4F,
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
				Address: 0x46A6F1,
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
				Address: 0x469E4F,
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

func TestInjectorFuzz(t *testing.T) {
	injector := NewInjector()
	fmt.Println("seed:", injector.Seed())

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		for i := 0; i < 100; i++ {
			output, err := injector.Inject(image, shellcode, nil)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImageFast(t, "testdata/injected_x86.exe", output)
		}
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)

		for i := 0; i < 100; i++ {
			output, err := injector.Inject(image, shellcode, nil)
			require.NoError(t, err)
			require.NotEmpty(t, output)

			testExecuteImageFast(t, "testdata/injected_x64.exe", output)
		}
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testExecuteImage(t *testing.T, path string, image []byte) {
	testExecuteImageWait(t, path, image, 500*time.Millisecond)
}

func testExecuteImageFast(t *testing.T, path string, image []byte) {
	testExecuteImageWait(t, path, image, 250*time.Millisecond)
}

func testExecuteImageWait(t *testing.T, path string, image []byte, wait time.Duration) {
	err := os.WriteFile(path, image, 0600)
	require.NoError(t, err)

	buf := bytes.NewBuffer(nil)
	cmd := exec.Command(path)
	cmd.Stdout = buf
	cmd.Stderr = buf

	err = cmd.Start()
	require.NoError(t, err)

	time.Sleep(wait)
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	require.Contains(t, buf.String(), "Hello World!")
}

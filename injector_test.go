package injector

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			fmt.Println("seed:", ctx.Seed)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
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

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
		})
	})

	t.Run("x64", func(t *testing.T) {
		t.Run("entry point", func(t *testing.T) {
			opts.Address = 0

			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
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

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
		})
	})
}

func TestInjector_InjectRaw(t *testing.T) {
	injector := NewInjector()

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

			ctx, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
		})

		t.Run("custom address", func(t *testing.T) {
			opts.Address = 0x46A6F1

			image, err := os.ReadFile("testdata/image_x86.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			ctx, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
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

			ctx, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
		})

		t.Run("custom address", func(t *testing.T) {
			opts.Address = 0x469E4F

			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			ctx, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
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

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
		})

		t.Run("x64", func(t *testing.T) {
			opts := &Options{
				Address: 0x469E4F,
			}

			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
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

			ctx, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx.Output)
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

			ctx, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx.Output)
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

			ctx1, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			ctx2, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ctx1, ctx2)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx1.Output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
			require.NoError(t, err)

			ctx1, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			ctx2, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ctx1, ctx2)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx1.Output)
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

			ctx1, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			ctx2, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ctx1, ctx2)

			testExecuteImage(t, "testdata/injected_x86.exe", ctx1.Output)
		})

		t.Run("x64", func(t *testing.T) {
			image, err := os.ReadFile("testdata/image_x64.dat")
			require.NoError(t, err)
			shellcode := []byte{
				0x90,
				0x66, 0x90,
			}

			ctx1, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			ctx2, err := injector.InjectRaw(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ctx1, ctx2)

			testExecuteImage(t, "testdata/injected_x64.exe", ctx1.Output)
		})
	})

	err := injector.Close()
	require.NoError(t, err)
}

func TestInjectorFuzz(t *testing.T) {
	injector := NewInjector()

	t.Run("x86", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x86.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x86.dat")
		require.NoError(t, err)

		for i := 0; i < 30; i++ {
			ctx, err := injector.Inject(image, shellcode, nil)
			require.NoError(t, err)
			require.Equal(t, ModeCreateSection, ctx.Mode)

			testExecuteImageFast(t, "testdata/injected_x86.exe", ctx.Output)
		}
	})

	t.Run("x64", func(t *testing.T) {
		image, err := os.ReadFile("testdata/image_x64.dat")
		require.NoError(t, err)
		shellcode, err := os.ReadFile("testdata/shellcode_x64.dat")
		require.NoError(t, err)

		opts := new(Options)
		for i := 0; i < 30; i++ {
			opts.ForceCodeCave = true
			opts.ForceExtendSection = false
			opts.ForceCreateSection = false

			ctx, err := injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ModeCodeCave, ctx.Mode)

			testExecuteImageFast(t, "testdata/injected_x64.exe", ctx.Output)

			opts.ForceCodeCave = false
			opts.ForceExtendSection = true
			opts.ForceCreateSection = false

			ctx, err = injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ModeExtendSection, ctx.Mode)

			testExecuteImageFast(t, "testdata/injected_x64.exe", ctx.Output)

			opts.ForceCodeCave = false
			opts.ForceExtendSection = false
			opts.ForceCreateSection = true

			ctx, err = injector.Inject(image, shellcode, opts)
			require.NoError(t, err)
			require.Equal(t, ModeCreateSection, ctx.Mode)

			testExecuteImageFast(t, "testdata/injected_x64.exe", ctx.Output)
		}
	})

	err := injector.Close()
	require.NoError(t, err)
}

func testExecuteImage(t *testing.T, path string, image []byte) {
	testExecuteImageWait(t, path, image, 750*time.Millisecond)
}

func testExecuteImageFast(t *testing.T, path string, image []byte) {
	testExecuteImageWait(t, path, image, 500*time.Millisecond)
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

	if assert.Contains(t, buf.String(), "Hello World!") {
		return
	}

	// when failed to test, backup output image for debug
	path = strings.ReplaceAll(path, ".exe", ".bak")
	err = os.WriteFile(path, image, 0600)
	require.NoError(t, err)
	t.FailNow()
}

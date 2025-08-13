package injector

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestInspectLoaderTemplate(t *testing.T) {
	var opts []*InspectOptions
	opt := InspectOptions{}
	for i := 0; i < 3; i++ {
		opt.CodeCaveMode = i == 0
		opt.ExtendSectionMode = i == 1
		opt.CreateSectionMode = i == 2

		for i1 := 0; i1 < 2; i1++ {
			opt.HasVirtualAlloc = i1 == 0
			for i2 := 0; i2 < 2; i2++ {
				opt.HasVirtualFree = i2 == 0
				for i3 := 0; i3 < 2; i3++ {
					opt.HasVirtualProtect = i3 == 0
					for i4 := 0; i4 < 2; i4++ {
						opt.HasCreateThread = i4 == 0
						for i5 := 0; i5 < 2; i5++ {
							opt.HasWaitForSingleObject = i5 == 0
							for i6 := 0; i6 < 2; i6++ {
								opt.HasLoadLibraryA = i6 == 0
								cp := opt
								opts = append(opts, &cp)
							}
						}
					}
				}
			}
		}
	}

	t.Run("x86", func(t *testing.T) {
		for _, opt := range opts {
			asm, inst, err := InspectLoaderTemplate("386", defaultLoaderX86, opt)
			require.NoError(t, err, asm)
			insts, err := disassemble(inst, 32)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, opt := range opts {
			asm, inst, err := InspectLoaderTemplate("amd64", defaultLoaderX64, opt)
			require.NoError(t, err, asm)
			insts, err := disassemble(inst, 64)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
		}
	})
}

func TestInspectJunkCodeTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, src := range defaultJunkCodeX86 {
			asm, inst, err := InspectJunkCodeTemplate("386", src)
			require.NoError(t, err, asm)
			insts, err := disassemble(inst, 32)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, src := range defaultJunkCodeX64 {
			asm, inst, err := InspectJunkCodeTemplate("amd64", src)
			require.NoError(t, err, asm)
			insts, err := disassemble(inst, 64)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
		}
	})
}

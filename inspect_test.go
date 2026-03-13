package injector

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestInspectLoaderTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		err := InspectLoaderTemplate("x86", defaultLoaderX86)
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		err := InspectLoaderTemplate("x64", defaultLoaderX64)
		require.NoError(t, err)
	})
}

func TestInspectLoaderTemplateWithConfig(t *testing.T) {
	configs := buildPossibleConfigs()
	t.Run("x86", func(t *testing.T) {
		for _, cfg := range configs {
			asm, inst, err := InspectLoaderTemplateWithConfig("386", defaultLoaderX86, cfg)
			require.NoError(t, err, asm)
			insts, err := disassemble(inst, 32)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, cfg := range configs {
			asm, inst, err := InspectLoaderTemplateWithConfig("amd64", defaultLoaderX64, cfg)
			require.NoError(t, err, asm)
			insts, err := disassemble(inst, 64)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
		}
	})

	t.Run("invalid arch", func(t *testing.T) {
		cfg := InspectConfig{}
		asm, inst, err := InspectLoaderTemplateWithConfig("test", "", &cfg)
		require.EqualError(t, err, "unsupported architecture: test")
		require.Nil(t, inst)
		require.Zero(t, asm)
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

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate("test", "")
		require.EqualError(t, err, "unsupported architecture: test")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})
}

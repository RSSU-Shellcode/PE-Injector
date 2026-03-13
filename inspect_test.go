package injector

import (
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestInspectLoaderTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		cfg, err := InspectLoaderTemplate("386", defaultLoaderX86)
		require.NoError(t, err)
		require.Nil(t, cfg)
	})

	t.Run("x64", func(t *testing.T) {
		cfg, err := InspectLoaderTemplate("amd64", defaultLoaderX64)
		require.NoError(t, err)
		require.Nil(t, cfg)
	})

	t.Run("invalid arch", func(t *testing.T) {
		cfg, err := InspectLoaderTemplate("invalid", "")
		require.EqualError(t, err, "unsupported architecture: invalid")
		require.NotNil(t, cfg)
		spew.Dump(cfg)
	})

	t.Run("invalid template", func(t *testing.T) {
		cfg, err := InspectLoaderTemplate("amd64", "invalid")
		errStr := "failed to assemble loader: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.EqualError(t, err, errStr)
		require.NotNil(t, cfg)
		spew.Dump(cfg)
	})
}

func TestInspectLoaderTemplateWithConfig(t *testing.T) {
	configs := buildPossibleConfigs()

	t.Run("x86", func(t *testing.T) {
		for _, cfg := range configs {
			asm, inst, err := InspectLoaderTemplateWithConfig("386", defaultLoaderX86, cfg)
			require.NoError(t, err)
			insts, err := disassemble(inst, 32)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
			fmt.Println(asm)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, cfg := range configs {
			asm, inst, err := InspectLoaderTemplateWithConfig("amd64", defaultLoaderX64, cfg)
			require.NoError(t, err)
			insts, err := disassemble(inst, 64)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
			fmt.Println(asm)
		}
	})

	t.Run("invalid arch", func(t *testing.T) {
		cfg := InspectConfig{}
		asm, inst, err := InspectLoaderTemplateWithConfig("invalid", "", &cfg)
		require.EqualError(t, err, "unsupported architecture: invalid")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid template", func(t *testing.T) {
		cfg := InspectConfig{}
		asm, inst, err := InspectLoaderTemplateWithConfig("amd64", "invalid", &cfg)
		require.EqualError(t, err, "proc LoadLibrary is not exist in IAT")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})
}

func TestInspectJunkCodeTemplate(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		for _, src := range defaultJunkCodeX86 {
			asm, inst, err := InspectJunkCodeTemplate("386", src)
			require.NoError(t, err)
			insts, err := disassemble(inst, 32)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
			fmt.Println(asm)
		}
	})

	t.Run("x64", func(t *testing.T) {
		for _, src := range defaultJunkCodeX64 {
			asm, inst, err := InspectJunkCodeTemplate("amd64", src)
			require.NoError(t, err)
			insts, err := disassemble(inst, 64)
			require.NoError(t, err, inst)

			fmt.Println("num of instructions:", len(insts))
			spew.Dump(inst)
			fmt.Println(asm)
		}
	})

	t.Run("invalid arch", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate("invalid", "")
		require.EqualError(t, err, "unsupported architecture: invalid")
		require.Nil(t, inst)
		require.Zero(t, asm)
	})

	t.Run("invalid template", func(t *testing.T) {
		asm, inst, err := InspectJunkCodeTemplate("amd64", "invalid")
		errStr := "failed to assemble junk code: failed to assemble: "
		errStr += "Invalid mnemonic (KS_ERR_ASM_MNEMONICFAIL)"
		require.EqualError(t, err, errStr)
		require.Nil(t, inst)
		require.Zero(t, asm)
	})
}

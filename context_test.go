package injector

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestSaveContext(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "386"
		injector.opts = new(Options)
		injector.ctx = &Context{
			Mode: ModeCreateSection,
		}
		err := injector.initAssembler()
		require.NoError(t, err)

		inst := injector.saveContext()
		spew.Dump(inst)

		err = injector.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "amd64"
		injector.opts = new(Options)
		injector.ctx = &Context{
			Mode: ModeCreateSection,
		}
		err := injector.initAssembler()
		require.NoError(t, err)

		inst := injector.saveContext()
		spew.Dump(inst)

		err = injector.Close()
		require.NoError(t, err)
	})
}

func TestRestoreContext(t *testing.T) {
	t.Run("x86", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "386"
		injector.opts = new(Options)
		injector.ctx = &Context{
			Mode: ModeCreateSection,
		}
		err := injector.initAssembler()
		require.NoError(t, err)
		injector.saveContext()

		inst := injector.restoreContext()
		spew.Dump(inst)

		err = injector.Close()
		require.NoError(t, err)
	})

	t.Run("x64", func(t *testing.T) {
		injector := NewInjector()
		injector.arch = "amd64"
		injector.opts = new(Options)
		injector.ctx = &Context{
			Mode: ModeCreateSection,
		}
		err := injector.initAssembler()
		require.NoError(t, err)
		injector.saveContext()

		inst := injector.restoreContext()
		spew.Dump(inst)

		err = injector.Close()
		require.NoError(t, err)
	})
}

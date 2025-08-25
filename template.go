package injector

import (
	"errors"
)

// Template is used to build highly customizable loader.
type Template struct {
	// specify the x86 loader template.
	LoaderX86 string `toml:"loader_x86" json:"loader_x86"`

	// specify the x64 loader template.
	LoaderX64 string `toml:"loader_x64" json:"loader_x64"`

	// maximum number of loader instructions on x86.
	MaxNumInstX86 int `toml:"max_num_inst_x86" json:"max_num_inst_x86"`

	// maximum number of loader instructions on x64.
	MaxNumInstX64 int `toml:"max_num_inst_x64" json:"max_num_inst_x64"`

	// append custom integer that will be encrypted.
	Integer []uint64 `toml:"integer" json:"integer"`

	// append custom ANSI string that will be encrypted.
	ANSI []string `toml:"ansi" json:"ansi"`

	// append custom UTF16 string that will be encrypted.
	UTF16 []string `toml:"utf16" json:"utf16"`

	// append custom plain-text argument for loader template.
	Arguments map[string]any `toml:"arguments" json:"arguments"`

	// append custom switch for if statements in template.
	Switches map[string]bool `toml:"switches" json:"switches"`
}

// Check is used to check template configuration.
func (tpl *Template) Check() error {
	if tpl.LoaderX86 == "" {
		return errors.New("empty loader template for x86")
	}
	if tpl.LoaderX64 == "" {
		return errors.New("empty loader template for x64")
	}
	if tpl.MaxNumInstX86 < 1 {
		return errors.New("invalid maximum number of loader instructions for x86")
	}
	if tpl.MaxNumInstX64 < 1 {
		return errors.New("invalid maximum number of loader instructions for x64")
	}
	return nil
}

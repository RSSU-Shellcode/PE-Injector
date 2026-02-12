package injector

import (
	"errors"
)

func (inj *Injector) selectInjectRawMode() error {
	if inj.opts.ForceCodeCaveNS {
		return errors.New("code cave with new section mode is not support")
	}
	if inj.opts.ForceExtendTextNS {
		return errors.New("extend text with new section mode is not support")
	}
	var counter int
	for _, sw := range []bool{
		inj.opts.ForceCodeCave,
		inj.opts.ForceExtendText,
		inj.opts.ForceCreateText,
	} {
		if sw {
			counter++
		}
	}
	if counter > 1 {
		return errors.New("set too many force mode in options")
	}
	if counter == 1 {
		return inj.useForceRawMode()
	}
	// try to use these modes in the following order
	// 1. CodeCave
	// 2. ExtendText
	// 3. CreateText
	err := inj.useCodeCaveRawMode()
	if err == nil {
		return nil
	}
	err = inj.useExtendTextRawMode()
	if err == nil {
		return nil
	}
	err = inj.useCreateTextRawMode()
	if err == nil {
		return nil
	}
	return errors.New("unable to select any mode for inject raw")
}

func (inj *Injector) useForceRawMode() error {
	switch {
	case inj.opts.ForceCodeCave:
		return inj.useCodeCaveRawMode()
	case inj.opts.ForceExtendText:
		return inj.useExtendTextRawMode()
	case inj.opts.ForceCreateText:
		return inj.useCreateTextRawMode()
	default:
		panic("unreachable code")
	}
}

func (inj *Injector) useCodeCaveRawMode() error {
	return nil
}

func (inj *Injector) useExtendTextRawMode() error {
	return nil
}

func (inj *Injector) useCreateTextRawMode() error {
	return nil
}

//go:build !linux

package exec

import "errors"

func ValidateInheritedDescriptors(preserve []int) error {
	if len(preserve) == 0 {
		return nil
	}
	return errors.New("inherited descriptor isolation is only supported on Linux")
}

func PrepareInheritedDescriptors(_ []int) error {
	return errors.New("inherited descriptor isolation is only supported on Linux")
}

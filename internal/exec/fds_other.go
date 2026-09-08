//go:build !linux

package exec

import "errors"

func PrepareInheritedDescriptors(_ []int) error {
	return errors.New("inherited descriptor isolation is only supported on Linux")
}

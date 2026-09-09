//go:build linux

package exec

import (
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

const firstNonStandardFD = 3

// ValidateInheritedDescriptors checks the caller's preserve list before the
// launcher opens any of its own descriptors. This prevents a closed requested
// number from being accidentally satisfied by launcher setup.
func ValidateInheritedDescriptors(preserve []int) error {
	_, err := validatePreservedDescriptors(preserve)
	return err
}

// PrepareInheritedDescriptors marks every descriptor above stderr close-on-exec,
// then explicitly preserves the validated descriptors requested by the user.
// It must run immediately before exec so descriptors opened by launcher setup
// cannot accidentally leak into the target process.
func PrepareInheritedDescriptors(preserve []int) error {
	fds, err := validatePreservedDescriptors(preserve)
	if err != nil {
		return err
	}

	if err := unix.CloseRange(firstNonStandardFD, uint(^uint32(0)), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("mark inherited descriptors close-on-exec: %w", err)
	}

	for _, fd := range fds {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			return fmt.Errorf("inspect preserved descriptor %d: %w", fd, err)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
			return fmt.Errorf("preserve descriptor %d: %w", fd, err)
		}
	}

	return nil
}

func validatePreservedDescriptors(preserve []int) ([]int, error) {
	unique := make(map[int]struct{}, len(preserve))
	for _, fd := range preserve {
		if fd < firstNonStandardFD {
			return nil, fmt.Errorf("preserved descriptor must be 3 or greater: %d", fd)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			return nil, fmt.Errorf("preserved descriptor %d is not open: %w", fd, err)
		}
		unique[fd] = struct{}{}
	}

	fds := make([]int, 0, len(unique))
	for fd := range unique {
		fds = append(fds, fd)
	}
	sort.Ints(fds)
	return fds, nil
}

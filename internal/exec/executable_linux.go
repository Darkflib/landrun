//go:build linux

package exec

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenExecutable opens the resolved target without following a later path
// replacement. The O_PATH descriptor is retained until RunFile executes it.
func OpenExecutable(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open executable %q: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// RunFile replaces the current process by executing the already-open target
// descriptor. execveat(2) with AT_EMPTY_PATH avoids resolving the target path
// again after policy construction.
func RunFile(file *os.File, args, env []string) error {
	if file == nil {
		return fmt.Errorf("executable descriptor is nil")
	}
	if len(args) == 0 {
		return fmt.Errorf("executable argument vector is empty")
	}
	path, err := syscall.BytePtrFromString("")
	if err != nil {
		return err
	}
	argv, err := syscall.SlicePtrFromStrings(args)
	if err != nil {
		return err
	}
	envp, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return err
	}
	errno := execveat(file, argv, envp, path)
	if errno == syscall.ENOENT {
		return fmt.Errorf("execute opened target: %w; direct shebang scripts are unsupported, invoke the interpreter explicitly", errno)
	}
	if errno != 0 {
		return errno
	}
	return nil
}

func execveat(file *os.File, argv, envp []*byte, path *byte) syscall.Errno {
	_, _, errno := syscall.RawSyscall6(
		unix.SYS_EXECVEAT,
		file.Fd(),
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])),
		unix.AT_EMPTY_PATH,
		0,
	)
	return errno
}

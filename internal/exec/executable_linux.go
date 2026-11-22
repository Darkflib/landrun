//go:build linux

package exec

import (
	"fmt"
	"io"
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

// RunFile replaces the current process with the already-open target.
//
// An ELF target whose path still names the same file (same device and inode)
// is executed by that path. Anything else is executed through the descriptor
// with execveat(2) and AT_EMPTY_PATH: a path replaced after policy
// construction never runs, and a shebang script still fails closed, because
// its interpreter path isn't pinned.
//
// Executing by path when nothing has changed matters for multi-call binaries
// (uutils coreutils, busybox). They choose the tool from the name the kernel
// records for the exec (AT_EXECFN). After an AT_EMPTY_PATH exec that name is
// "/dev/fd/N", so the binary refuses to run. Ubuntu 26.04's cat is one of these.
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
	if isELF(file) && samePath(file) {
		errno := execve(file.Name(), argv, envp)
		if errno != 0 && errno != syscall.ENOENT {
			return errno
		}
		// ENOENT: gone between the check and the exec. Use the descriptor.
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

// isELF reports whether the open file starts with the ELF magic. The O_PATH
// descriptor can't be read, so it is reopened through /proc; if that fails
// (no /proc, no read access), the answer is no and the descriptor is used.
func isELF(file *os.File) bool {
	f, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", file.Fd()), os.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic == [4]byte{0x7f, 'E', 'L', 'F'}
}

// samePath reports whether file's path still resolves to the open file.
func samePath(file *os.File) bool {
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
		return false
	}
	if err := unix.Stat(file.Name(), &named); err != nil {
		return false
	}
	return opened.Dev == named.Dev && opened.Ino == named.Ino
}

func execve(name string, argv, envp []*byte) syscall.Errno {
	path, err := syscall.BytePtrFromString(name)
	if err != nil {
		return syscall.EINVAL
	}
	_, _, errno := syscall.RawSyscall(
		unix.SYS_EXECVE,
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])),
	)
	return errno
}

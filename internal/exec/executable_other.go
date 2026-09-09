//go:build !linux

package exec

import "os"

func OpenExecutable(path string) (*os.File, error) {
	return os.Open(path)
}

func RunFile(file *os.File, args, env []string) error {
	return Run(file.Name(), args, env)
}

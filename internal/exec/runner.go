package exec

import (
	"syscall"

	"github.com/zouuup/landrun/internal/log"
)

// Run replaces the current process with the already-resolved binary. Command
// lookup belongs before sandbox setup; repeating it here would let PATH select
// a different executable after the policy has been constructed.
func Run(binary string, args []string, env []string) error {
	log.Info("Executing: %v", args)

	// Only pass the explicitly specified environment variables
	// If env is empty, no environment variables will be passed
	return syscall.Exec(binary, args, env)
}

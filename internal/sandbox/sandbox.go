package sandbox

import (
	"fmt"
	"os"
	"sort"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/syscall"
	"github.com/zouuup/landrun/internal/log"
)

type Config struct {
	ReadOnlyPaths            []string
	ReadWritePaths           []string
	ReadOnlyExecutablePaths  []string
	ReadWriteExecutablePaths []string
	UnixSocketPaths          []string
	BindTCPPorts             []int
	ConnectTCPPorts          []int
	BestEffort               bool
	UnrestrictedFilesystem   bool
	UnrestrictedNetwork      bool
	UnrestrictedScoped       bool
	IgnoreMissingPaths       bool
	// Audit logging configuration (Landlock ABI V7+).
	DisableLogOriginating bool
	EnableLogSubprocesses bool
	DisableLogSubdomains  bool
}

// Probe returns the highest Landlock ABI supported by the running kernel.
func Probe() (int, error) {
	return syscall.LandlockGetABIVersion()
}

// RequiredABI returns the minimum ABI needed for explicitly requested policy
// controls. An empty policy has no explicit feature requirement.
func RequiredABI(cfg Config) int {
	required := 0
	if len(cfg.ReadOnlyPaths)+len(cfg.ReadOnlyExecutablePaths) > 0 {
		required = max(required, 1)
	}
	if len(cfg.ReadWritePaths)+len(cfg.ReadWriteExecutablePaths) > 0 {
		required = max(required, 3)
	}
	if len(cfg.BindTCPPorts)+len(cfg.ConnectTCPPorts) > 0 {
		required = max(required, 4)
	}
	if len(cfg.UnixSocketPaths) > 0 {
		required = max(required, 9)
	}
	if cfg.DisableLogOriginating || cfg.EnableLogSubprocesses || cfg.DisableLogSubdomains {
		required = max(required, 7)
	}
	return required
}

const maxTCPPort = 65535

// ValidateConfig validates and normalizes a sandbox policy before it is used.
// Path strings are intentionally not cleaned or made absolute: doing so can
// change their meaning when symlinks are involved.
func ValidateConfig(cfg Config) (Config, error) {
	if cfg.UnrestrictedFilesystem && hasAny(cfg.ReadOnlyPaths, cfg.ReadWritePaths, cfg.ReadOnlyExecutablePaths, cfg.ReadWriteExecutablePaths, cfg.UnixSocketPaths) {
		return Config{}, fmt.Errorf("--unrestricted-filesystem cannot be combined with filesystem or UNIX socket rules")
	}
	if cfg.UnrestrictedNetwork && len(cfg.BindTCPPorts)+len(cfg.ConnectTCPPorts) > 0 {
		return Config{}, fmt.Errorf("--unrestricted-network cannot be combined with TCP port rules")
	}

	var err error

	cfg.ReadOnlyPaths, err = normalizePaths("--ro", cfg.ReadOnlyPaths)
	if err != nil {
		return Config{}, err
	}
	cfg.ReadWritePaths, err = normalizePaths("--rw", cfg.ReadWritePaths)
	if err != nil {
		return Config{}, err
	}
	cfg.ReadOnlyExecutablePaths, err = normalizePaths("--rox", cfg.ReadOnlyExecutablePaths)
	if err != nil {
		return Config{}, err
	}
	cfg.ReadWriteExecutablePaths, err = normalizePaths("--rwx", cfg.ReadWriteExecutablePaths)
	if err != nil {
		return Config{}, err
	}
	cfg.UnixSocketPaths, err = normalizePaths("--unix", cfg.UnixSocketPaths)
	if err != nil {
		return Config{}, err
	}

	// Binding port zero has defined Linux semantics: the kernel chooses an
	// ephemeral port. Connecting to port zero has no corresponding ephemeral
	// behavior, so reject it as an ambiguous policy request.
	cfg.BindTCPPorts, err = normalizePorts("--bind-tcp", cfg.BindTCPPorts, 0)
	if err != nil {
		return Config{}, err
	}
	cfg.ConnectTCPPorts, err = normalizePorts("--connect-tcp", cfg.ConnectTCPPorts, 1)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// hasAny reports whether any policy field contains at least one entry.
func hasAny(groups ...[]string) bool {
	for _, group := range groups {
		if len(group) > 0 {
			return true
		}
	}
	return false
}

// normalizePaths rejects empty entries and returns sorted unique path strings.
func normalizePaths(flag string, paths []string) ([]string, error) {
	unique := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			return nil, fmt.Errorf("%s path must not be empty", flag)
		}
		unique[path] = struct{}{}
	}

	normalized := make([]string, 0, len(unique))
	for path := range unique {
		normalized = append(normalized, path)
	}
	sort.Strings(normalized)
	return normalized, nil
}

// normalizePorts validates the flag-specific range and returns sorted unique ports.
func normalizePorts(flag string, ports []int, minimum int) ([]int, error) {
	unique := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < minimum || port > maxTCPPort {
			return nil, fmt.Errorf("%s port must be between %d and %d: %d", flag, minimum, maxTCPPort, port)
		}
		unique[port] = struct{}{}
	}

	normalized := make([]int, 0, len(unique))
	for port := range unique {
		normalized = append(normalized, port)
	}
	sort.Ints(normalized)
	return normalized, nil
}

// fullFSAccess is the union of every filesystem access right supported by
// Landlock V9. It is used as the Config's handled access set so that every
// per-path rule we build stays within its bounds.
const fullFSAccess = landlock.AccessFSSet(
	syscall.AccessFSExecute |
		syscall.AccessFSWriteFile |
		syscall.AccessFSReadFile |
		syscall.AccessFSReadDir |
		syscall.AccessFSRemoveDir |
		syscall.AccessFSRemoveFile |
		syscall.AccessFSMakeChar |
		syscall.AccessFSMakeDir |
		syscall.AccessFSMakeReg |
		syscall.AccessFSMakeSock |
		syscall.AccessFSMakeFifo |
		syscall.AccessFSMakeBlock |
		syscall.AccessFSMakeSym |
		syscall.AccessFSRefer |
		syscall.AccessFSTruncate |
		syscall.AccessFSIoctlDev |
		syscall.AccessFSResolveUnix,
)

// fullNetAccess intentionally includes only the classic TCP rights. The
// go-landlock V10 dependency knows about UDP rights, but landrun does not
// expose UDP policy flags yet and must not enable them implicitly.
const fullNetAccess = landlock.AccessNetSet(
	syscall.AccessNetBindTCP | syscall.AccessNetConnectTCP,
)

// fullScoped is the union of every IPC scope supported by Landlock V9
// (available since V6).
const fullScoped = landlock.ScopedSet(
	syscall.ScopeAbstractUnixSocket | syscall.ScopeSignal,
)

// getReadWriteExecutableRights returns a full set of permissions including execution
func getReadWriteExecutableRights(dir bool) landlock.AccessFSSet {
	accessRights := landlock.AccessFSSet(0)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSExecute)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSReadFile)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSWriteFile)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSTruncate)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSIoctlDev)

	if dir {
		accessRights |= landlock.AccessFSSet(syscall.AccessFSReadDir)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSRemoveDir)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSRemoveFile)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeChar)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeDir)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeReg)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeSock)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeFifo)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeBlock)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeSym)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSRefer)
	}

	return accessRights
}

func getReadOnlyExecutableRights(dir bool) landlock.AccessFSSet {
	accessRights := landlock.AccessFSSet(0)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSExecute)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSReadFile)
	if dir {
		accessRights |= landlock.AccessFSSet(syscall.AccessFSReadDir)
	}
	return accessRights
}

// getReadOnlyRights returns permissions for read-only access
func getReadOnlyRights(dir bool) landlock.AccessFSSet {
	accessRights := landlock.AccessFSSet(0)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSReadFile)
	if dir {
		accessRights |= landlock.AccessFSSet(syscall.AccessFSReadDir)
	}
	return accessRights
}

// getReadWriteRights returns permissions for read-write access
func getReadWriteRights(dir bool) landlock.AccessFSSet {
	accessRights := landlock.AccessFSSet(0)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSReadFile)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSWriteFile)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSTruncate)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSIoctlDev)
	if dir {
		accessRights |= landlock.AccessFSSet(syscall.AccessFSReadDir)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSRemoveDir)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSRemoveFile)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeChar)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeDir)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeReg)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeSock)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeFifo)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeBlock)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSMakeSym)
		accessRights |= landlock.AccessFSSet(syscall.AccessFSRefer)
	}

	return accessRights
}

// getUnixSocketRights returns permissions for connecting to a pathname UNIX
// domain socket (connect(2)/sendmsg(2)), available since Landlock ABI V9.
func getUnixSocketRights(dir bool) landlock.AccessFSSet {
	accessRights := landlock.AccessFSSet(0)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSReadFile)
	accessRights |= landlock.AccessFSSet(syscall.AccessFSResolveUnix)
	if dir {
		accessRights |= landlock.AccessFSSet(syscall.AccessFSReadDir)
	}
	return accessRights
}

// isDirectory checks if the given path is a directory
func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

// pathRule builds a filesystem rule for the given access rights and path,
// optionally applying the IgnoreIfMissing modifier so that referencing a
// non-existing path does not lead to a runtime error.
func pathRule(rights landlock.AccessFSSet, path string, ignoreMissing bool) landlock.Rule {
	rule := landlock.PathAccess(rights, path)
	if ignoreMissing {
		return rule.IgnoreIfMissing()
	}
	return rule
}

func Apply(cfg Config) error {
	var err error
	cfg, err = ValidateConfig(cfg)
	if err != nil {
		return fmt.Errorf("invalid sandbox policy: %w", err)
	}
	if required := RequiredABI(cfg); required > 0 {
		available, probeErr := Probe()
		if probeErr != nil {
			return fmt.Errorf("cannot enforce explicitly requested Landlock controls (minimum ABI %d): %w", required, probeErr)
		}
		if available < required {
			return fmt.Errorf("cannot enforce explicitly requested Landlock controls: minimum ABI %d, kernel ABI %d", required, available)
		}
	}

	log.Info("Sandbox config: %+v", cfg)

	if cfg.UnrestrictedFilesystem {
		log.Info("Unrestricted filesystem access enabled.")
	}
	if cfg.UnrestrictedNetwork {
		log.Info("Unrestricted network access enabled.")
	}
	if cfg.UnrestrictedScoped {
		log.Info("Unrestricted IPC scoping enabled.")
	}

	// Determine which access domains should be handled (i.e. restricted).
	// A domain that is left out of the Config stays completely unrestricted.
	var configArgs []interface{}
	if !cfg.UnrestrictedFilesystem {
		configArgs = append(configArgs, fullFSAccess)
	}
	if !cfg.UnrestrictedNetwork {
		configArgs = append(configArgs, fullNetAccess)
	}
	if !cfg.UnrestrictedScoped {
		configArgs = append(configArgs, fullScoped)
	}

	// If every domain is unrestricted, there is nothing for Landlock to do.
	if len(configArgs) == 0 {
		log.Info("Unrestricted filesystem, network and IPC scoping enabled; no rules applied.")
		return nil
	}

	// Collect our rules. Filesystem rules are only meaningful when the
	// filesystem domain is handled; network rules only when the network
	// domain is handled. Adding a rule for an unhandled domain is rejected
	// by Landlock with EINVAL.
	var allRules []landlock.Rule

	if !cfg.UnrestrictedFilesystem {
		for _, path := range cfg.ReadOnlyExecutablePaths {
			log.Debug("Adding read-only executable path: %s", path)
			allRules = append(allRules, pathRule(getReadOnlyExecutableRights(isDirectory(path)), path, cfg.IgnoreMissingPaths))
		}

		for _, path := range cfg.ReadWriteExecutablePaths {
			log.Debug("Adding read-write executable path: %s", path)
			allRules = append(allRules, pathRule(getReadWriteExecutableRights(isDirectory(path)), path, cfg.IgnoreMissingPaths))
		}

		for _, path := range cfg.ReadOnlyPaths {
			log.Debug("Adding read-only path: %s", path)
			allRules = append(allRules, pathRule(getReadOnlyRights(isDirectory(path)), path, cfg.IgnoreMissingPaths))
		}

		for _, path := range cfg.ReadWritePaths {
			log.Debug("Adding read-write path: %s", path)
			allRules = append(allRules, pathRule(getReadWriteRights(isDirectory(path)), path, cfg.IgnoreMissingPaths))
		}

		for _, path := range cfg.UnixSocketPaths {
			log.Debug("Adding UNIX socket (connect) path: %s", path)
			allRules = append(allRules, pathRule(getUnixSocketRights(isDirectory(path)), path, cfg.IgnoreMissingPaths))
		}
	} else if len(cfg.UnixSocketPaths) > 0 {
		log.Info("Ignoring --unix paths because filesystem access is unrestricted.")
	}

	if !cfg.UnrestrictedNetwork {
		for _, port := range cfg.BindTCPPorts {
			log.Debug("Adding TCP bind port: %d", port)
			allRules = append(allRules, landlock.BindTCP(uint16(port)))
		}

		for _, port := range cfg.ConnectTCPPorts {
			log.Debug("Adding TCP connect port: %d", port)
			allRules = append(allRules, landlock.ConnectTCP(uint16(port)))
		}
	}

	// Build the Landlock configuration. Start from a custom config that
	// handles exactly the domains we want to restrict, so that all rules are
	// enforced in a single ruleset layer. This keeps the "refer" access
	// right working (it is implicitly denied whenever the filesystem domain
	// is not handled by a layer).
	baseCfg, err := landlock.NewConfig(configArgs...)
	if err != nil {
		return fmt.Errorf("failed to build Landlock config: %w", err)
	}
	llCfg := *baseCfg

	if cfg.BestEffort {
		llCfg = llCfg.BestEffort()
	}

	// Audit logging configuration (Landlock ABI V7+). Without --best-effort
	// these assert a V7+ kernel and will error at restriction time otherwise.
	if cfg.DisableLogOriginating {
		llCfg = llCfg.DisableLoggingForOriginatingProcess()
	}
	if cfg.EnableLogSubprocesses {
		llCfg = llCfg.EnableLoggingForSubprocesses()
	}
	if cfg.DisableLogSubdomains {
		llCfg = llCfg.DisableLoggingForSubdomains()
	}

	if len(allRules) == 0 {
		log.Info("No rules provided; applying maximum restrictions for the handled domains.")
	}

	log.Debug("Applying Landlock restrictions: %s", llCfg.String())
	if err := llCfg.Restrict(allRules...); err != nil {
		return fmt.Errorf("failed to apply Landlock restrictions: %w", err)
	}

	log.Info("Landlock restrictions applied successfully")
	return nil
}

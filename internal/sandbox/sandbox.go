package sandbox

import (
	"encoding/json"
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

// EffectivePolicy describes the access families the running kernel actually
// enforces after best-effort ABI downgrading. PolicyABI is the lowest ABI that
// fully describes the handled rights, scopes, and audit flags; enforcement
// improvements are reported separately. The rights are handled (denied by
// default), and individual rules in Config grant selected operations back.
type EffectivePolicy struct {
	Applied                 bool     `json:"applied"`
	KernelABI               int      `json:"kernel_abi"`
	PolicyABI               int      `json:"policy_abi"`
	BestEffort              bool     `json:"best_effort"`
	HandledFilesystemRights []string `json:"handled_filesystem_rights"`
	HandledNetworkRights    []string `json:"handled_network_rights"`
	HandledScopes           []string `json:"handled_scopes"`
	AuditFlags              []string `json:"audit_flags"`
	ThreadSynchronized      bool     `json:"thread_synchronized"`
}

func (p EffectivePolicy) String() string {
	encoded, err := json.Marshal(p)
	if err != nil {
		return fmt.Sprintf("effective policy encoding failed: %v", err)
	}
	return string(encoded)
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
	if cfg.UnrestrictedFilesystem && cfg.UnrestrictedNetwork && cfg.UnrestrictedScoped &&
		(cfg.DisableLogOriginating || cfg.EnableLogSubprocesses || cfg.DisableLogSubdomains) {
		return Config{}, fmt.Errorf("audit logging controls require at least one restricted domain")
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

// maxPolicyABI is the newest Landlock ABI whose access-control semantics are
// part of landrun's public policy contract. A dependency or kernel ABI upgrade
// must not change this value until new rights have explicit CLI semantics,
// compatibility checks, negative tests, and documentation.
const maxPolicyABI = 9

// fullFSAccess is the union of every filesystem access right included in
// landrun's maxPolicyABI contract. It is used as the Config's handled access
// set so that every per-path rule we build stays within its bounds.
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

// fullScoped is the union of every IPC scope included in landrun's
// maxPolicyABI contract (available since V6).
const fullScoped = landlock.ScopedSet(
	syscall.ScopeAbstractUnixSocket | syscall.ScopeSignal,
)

type accessName struct {
	bit  uint64
	name string
}

var filesystemAccessNames = []accessName{
	{uint64(syscall.AccessFSExecute), "execute"},
	{uint64(syscall.AccessFSWriteFile), "write_file"},
	{uint64(syscall.AccessFSReadFile), "read_file"},
	{uint64(syscall.AccessFSReadDir), "read_dir"},
	{uint64(syscall.AccessFSRemoveDir), "remove_dir"},
	{uint64(syscall.AccessFSRemoveFile), "remove_file"},
	{uint64(syscall.AccessFSMakeChar), "make_char"},
	{uint64(syscall.AccessFSMakeDir), "make_dir"},
	{uint64(syscall.AccessFSMakeReg), "make_reg"},
	{uint64(syscall.AccessFSMakeSock), "make_sock"},
	{uint64(syscall.AccessFSMakeFifo), "make_fifo"},
	{uint64(syscall.AccessFSMakeBlock), "make_block"},
	{uint64(syscall.AccessFSMakeSym), "make_sym"},
	{uint64(syscall.AccessFSRefer), "refer"},
	{uint64(syscall.AccessFSTruncate), "truncate"},
	{uint64(syscall.AccessFSIoctlDev), "ioctl_dev"},
	{uint64(syscall.AccessFSResolveUnix), "resolve_unix"},
}

var networkAccessNames = []accessName{
	{uint64(syscall.AccessNetBindTCP), "bind_tcp"},
	{uint64(syscall.AccessNetConnectTCP), "connect_tcp"},
}

var scopeNames = []accessName{
	{uint64(syscall.ScopeAbstractUnixSocket), "abstract_unix_socket"},
	{uint64(syscall.ScopeSignal), "signal"},
}

func namedAccesses(value uint64, names []accessName) []string {
	result := make([]string, 0, len(names))
	for _, access := range names {
		if value&access.bit != 0 {
			result = append(result, access.name)
		}
	}
	return result
}

func filesystemRightsForABI(abi int) landlock.AccessFSSet {
	if abi < 1 {
		return 0
	}
	rights := fullFSAccess
	if abi < 9 {
		rights &^= landlock.AccessFSSet(syscall.AccessFSResolveUnix)
	}
	if abi < 5 {
		rights &^= landlock.AccessFSSet(syscall.AccessFSIoctlDev)
	}
	if abi < 3 {
		rights &^= landlock.AccessFSSet(syscall.AccessFSTruncate)
	}
	if abi < 2 {
		rights &^= landlock.AccessFSSet(syscall.AccessFSRefer)
	}
	return rights
}

// effectivePolicyForABI is pure so ABI boundary behavior can be tested without
// applying a process-wide Landlock domain to the test process.
func effectivePolicyForABI(cfg Config, kernelABI int) EffectivePolicy {
	report := EffectivePolicy{
		KernelABI:               kernelABI,
		BestEffort:              cfg.BestEffort,
		HandledFilesystemRights: []string{},
		HandledNetworkRights:    []string{},
		HandledScopes:           []string{},
		AuditFlags:              []string{},
	}
	if kernelABI < 1 || (cfg.UnrestrictedFilesystem && cfg.UnrestrictedNetwork && cfg.UnrestrictedScoped) {
		return report
	}

	effectiveABI := min(kernelABI, maxPolicyABI)
	if !cfg.UnrestrictedFilesystem {
		fsRights := filesystemRightsForABI(effectiveABI)
		report.HandledFilesystemRights = namedAccesses(uint64(fsRights), filesystemAccessNames)
		switch {
		case fsRights&landlock.AccessFSSet(syscall.AccessFSResolveUnix) != 0:
			report.PolicyABI = max(report.PolicyABI, 9)
		case fsRights&landlock.AccessFSSet(syscall.AccessFSIoctlDev) != 0:
			report.PolicyABI = max(report.PolicyABI, 5)
		case fsRights&landlock.AccessFSSet(syscall.AccessFSTruncate) != 0:
			report.PolicyABI = max(report.PolicyABI, 3)
		case fsRights&landlock.AccessFSSet(syscall.AccessFSRefer) != 0:
			report.PolicyABI = max(report.PolicyABI, 2)
		case fsRights != 0:
			report.PolicyABI = max(report.PolicyABI, 1)
		}
	}
	if !cfg.UnrestrictedNetwork && effectiveABI >= 4 {
		report.HandledNetworkRights = namedAccesses(uint64(fullNetAccess), networkAccessNames)
		report.PolicyABI = max(report.PolicyABI, 4)
	}
	if !cfg.UnrestrictedScoped && effectiveABI >= 6 {
		report.HandledScopes = namedAccesses(uint64(fullScoped), scopeNames)
		report.PolicyABI = max(report.PolicyABI, 6)
	}

	if report.PolicyABI > 0 && effectiveABI >= 7 {
		if cfg.DisableLogOriginating {
			report.AuditFlags = append(report.AuditFlags, "disable_originating")
		}
		if cfg.EnableLogSubprocesses {
			report.AuditFlags = append(report.AuditFlags, "enable_subprocesses")
		}
		if cfg.DisableLogSubdomains {
			report.AuditFlags = append(report.AuditFlags, "disable_subdomains")
		}
		if len(report.AuditFlags) > 0 {
			report.PolicyABI = max(report.PolicyABI, 7)
		}
	}

	report.Applied = report.PolicyABI > 0
	report.ThreadSynchronized = report.Applied && kernelABI >= 8
	return report
}

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
	available, probeErr := Probe()
	if probeErr != nil {
		available = 0
	}
	if required := RequiredABI(cfg); required > 0 {
		if probeErr != nil {
			return fmt.Errorf("cannot enforce explicitly requested Landlock controls (minimum ABI %d): %w", required, probeErr)
		}
		if available < required {
			return fmt.Errorf("cannot enforce explicitly requested Landlock controls: minimum ABI %d, kernel ABI %d", required, available)
		}
	}
	effectivePolicy := effectivePolicyForABI(cfg, available)

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
		log.Debug("Effective Landlock policy: %s", effectivePolicy)
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

	log.Debug("Requested Landlock configuration: %s", llCfg.String())
	if err := llCfg.Restrict(allRules...); err != nil {
		return fmt.Errorf("failed to apply Landlock restrictions: %w", err)
	}

	log.Debug("Effective Landlock policy: %s", effectivePolicy)
	log.Info("Landlock restrictions applied successfully")
	return nil
}

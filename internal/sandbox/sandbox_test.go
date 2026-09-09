package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestGetReadOnlyRights(t *testing.T) {
	file := getReadOnlyRights(false)
	if file&landlock.AccessFSSet(syscall.AccessFSReadFile) == 0 {
		t.Fatal("file RO should include read_file")
	}
	if file&landlock.AccessFSSet(syscall.AccessFSReadDir) != 0 {
		t.Fatal("file RO should not include read_dir")
	}
	if file&landlock.AccessFSSet(syscall.AccessFSExecute) != 0 {
		t.Fatal("file RO should not include execute")
	}

	dir := getReadOnlyRights(true)
	if dir&landlock.AccessFSSet(syscall.AccessFSReadDir) == 0 {
		t.Fatal("dir RO should include read_dir")
	}
}

func TestGetReadOnlyExecutableRights(t *testing.T) {
	file := getReadOnlyExecutableRights(false)
	for _, bit := range []landlock.AccessFSSet{
		landlock.AccessFSSet(syscall.AccessFSExecute),
		landlock.AccessFSSet(syscall.AccessFSReadFile),
	} {
		if file&bit == 0 {
			t.Fatalf("ROX file missing bit %#x", bit)
		}
	}
	if file&landlock.AccessFSSet(syscall.AccessFSReadDir) != 0 {
		t.Fatal("ROX file should not include read_dir")
	}

	dir := getReadOnlyExecutableRights(true)
	if dir&landlock.AccessFSSet(syscall.AccessFSReadDir) == 0 {
		t.Fatal("ROX dir should include read_dir")
	}
}

func TestGetReadWriteRights(t *testing.T) {
	file := getReadWriteRights(false)
	for _, bit := range []landlock.AccessFSSet{
		landlock.AccessFSSet(syscall.AccessFSReadFile),
		landlock.AccessFSSet(syscall.AccessFSWriteFile),
		landlock.AccessFSSet(syscall.AccessFSTruncate),
		landlock.AccessFSSet(syscall.AccessFSIoctlDev),
	} {
		if file&bit == 0 {
			t.Fatalf("RW file missing bit %#x", bit)
		}
	}
	if file&landlock.AccessFSSet(syscall.AccessFSRefer) != 0 {
		t.Fatal("RW file should not include refer")
	}
	if file&landlock.AccessFSSet(syscall.AccessFSExecute) != 0 {
		t.Fatal("RW file should not include execute")
	}

	dir := getReadWriteRights(true)
	for _, bit := range []landlock.AccessFSSet{
		landlock.AccessFSSet(syscall.AccessFSReadDir),
		landlock.AccessFSSet(syscall.AccessFSRemoveDir),
		landlock.AccessFSSet(syscall.AccessFSRemoveFile),
		landlock.AccessFSSet(syscall.AccessFSMakeReg),
		landlock.AccessFSSet(syscall.AccessFSRefer),
	} {
		if dir&bit == 0 {
			t.Fatalf("RW dir missing bit %#x", bit)
		}
	}
}

func TestGetReadWriteExecutableRights(t *testing.T) {
	file := getReadWriteExecutableRights(false)
	if file&landlock.AccessFSSet(syscall.AccessFSExecute) == 0 {
		t.Fatal("RWX file should include execute")
	}
	dir := getReadWriteExecutableRights(true)
	if dir&landlock.AccessFSSet(syscall.AccessFSRefer) == 0 {
		t.Fatal("RWX dir should include refer")
	}
	if dir&landlock.AccessFSSet(syscall.AccessFSExecute) == 0 {
		t.Fatal("RWX dir should include execute")
	}
}

func TestGetUnixSocketRights(t *testing.T) {
	file := getUnixSocketRights(false)
	if file&landlock.AccessFSSet(syscall.AccessFSResolveUnix) == 0 {
		t.Fatal("unix file should include resolve_unix")
	}
	if file&landlock.AccessFSSet(syscall.AccessFSReadFile) == 0 {
		t.Fatal("unix file should include read_file")
	}
	if file&landlock.AccessFSSet(syscall.AccessFSReadDir) != 0 {
		t.Fatal("unix file should not include read_dir")
	}

	dir := getUnixSocketRights(true)
	if dir&landlock.AccessFSSet(syscall.AccessFSReadDir) == 0 {
		t.Fatal("unix dir should include read_dir")
	}
}

func TestIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if !isDirectory(dir) {
		t.Fatalf("expected %s to be a directory", dir)
	}

	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if isDirectory(f) {
		t.Fatalf("expected %s not to be a directory", f)
	}

	if isDirectory(filepath.Join(dir, "missing")) {
		t.Fatal("missing path should not be a directory")
	}
}

func TestPathRule(t *testing.T) {
	rights := getReadOnlyRights(false)
	rule := pathRule(rights, "/tmp", false)
	if rule == nil {
		t.Fatal("expected non-nil rule")
	}
	ignored := pathRule(rights, "/nonexistent-landrun-path", true)
	if ignored == nil {
		t.Fatal("expected non-nil ignore-missing rule")
	}
}

func TestValidateConfigNormalizesPolicy(t *testing.T) {
	cfg := Config{
		ReadOnlyPaths:            []string{"/z", "/a", "/z"},
		ReadWritePaths:           []string{"relative", "relative"},
		ReadOnlyExecutablePaths:  []string{"/usr", "/bin", "/usr"},
		ReadWriteExecutablePaths: []string{"/srv/app", "/srv/app"},
		UnixSocketPaths:          []string{"/run/z.sock", "/run/a.sock", "/run/z.sock"},
		BindTCPPorts:             []int{65535, 0, 443, 443},
		ConnectTCPPorts:          []int{65535, 443, 443},
	}

	got, err := ValidateConfig(cfg)
	if err != nil {
		t.Fatalf("ValidateConfig failed: %v", err)
	}

	checks := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{name: "read-only paths", got: got.ReadOnlyPaths, want: []string{"/a", "/z"}},
		{name: "read-write paths", got: got.ReadWritePaths, want: []string{"relative"}},
		{name: "read-only executable paths", got: got.ReadOnlyExecutablePaths, want: []string{"/bin", "/usr"}},
		{name: "read-write executable paths", got: got.ReadWriteExecutablePaths, want: []string{"/srv/app"}},
		{name: "UNIX socket paths", got: got.UnixSocketPaths, want: []string{"/run/a.sock", "/run/z.sock"}},
		{name: "bind ports", got: got.BindTCPPorts, want: []int{0, 443, 65535}},
		{name: "connect ports", got: got.ConnectTCPPorts, want: []int{443, 65535}},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s: got %#v, want %#v", check.name, check.got, check.want)
		}
	}
}

func TestValidateConfigRejectsInvalidPorts(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "negative bind", cfg: Config{BindTCPPorts: []int{-1}}, want: "--bind-tcp port must be between 0 and 65535: -1"},
		{name: "oversized bind", cfg: Config{BindTCPPorts: []int{65536}}, want: "--bind-tcp port must be between 0 and 65535: 65536"},
		{name: "zero connect", cfg: Config{ConnectTCPPorts: []int{0}}, want: "--connect-tcp port must be between 1 and 65535: 0"},
		{name: "negative connect", cfg: Config{ConnectTCPPorts: []int{-1}}, want: "--connect-tcp port must be between 1 and 65535: -1"},
		{name: "oversized connect", cfg: Config{ConnectTCPPorts: []int{131071}}, want: "--connect-tcp port must be between 1 and 65535: 131071"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateConfig(tc.cfg)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestValidateConfigRejectsEmptyPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		flag string
	}{
		{name: "ro", cfg: Config{ReadOnlyPaths: []string{""}}, flag: "--ro"},
		{name: "rw", cfg: Config{ReadWritePaths: []string{""}}, flag: "--rw"},
		{name: "rox", cfg: Config{ReadOnlyExecutablePaths: []string{""}}, flag: "--rox"},
		{name: "rwx", cfg: Config{ReadWriteExecutablePaths: []string{""}}, flag: "--rwx"},
		{name: "unix", cfg: Config{UnixSocketPaths: []string{""}}, flag: "--unix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateConfig(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.flag+" path must not be empty") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRequiredABI(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want int
	}{
		{name: "empty", want: 0},
		{name: "read-only path", cfg: Config{ReadOnlyPaths: []string{"/tmp"}}, want: 1},
		{name: "read-write path", cfg: Config{ReadWritePaths: []string{"/tmp"}}, want: 3},
		{name: "TCP", cfg: Config{ConnectTCPPorts: []int{443}}, want: 4},
		{name: "audit logging", cfg: Config{EnableLogSubprocesses: true}, want: 7},
		{name: "UNIX socket", cfg: Config{UnixSocketPaths: []string{"/run/app.sock"}}, want: 9},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequiredABI(tc.cfg); got != tc.want {
				t.Fatalf("RequiredABI returned %d, want %d", got, tc.want)
			}
		})
	}
}

func TestApplyValidatesBeforeUnrestrictedNoOp(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{name: "read-only rule", cfg: Config{ReadOnlyPaths: []string{"/tmp"}, UnrestrictedFilesystem: true}, want: "--unrestricted-filesystem"},
		{name: "read-write rule", cfg: Config{ReadWritePaths: []string{"/tmp"}, UnrestrictedFilesystem: true}, want: "--unrestricted-filesystem"},
		{name: "read-only executable rule", cfg: Config{ReadOnlyExecutablePaths: []string{"/tmp"}, UnrestrictedFilesystem: true}, want: "--unrestricted-filesystem"},
		{name: "read-write executable rule", cfg: Config{ReadWriteExecutablePaths: []string{"/tmp"}, UnrestrictedFilesystem: true}, want: "--unrestricted-filesystem"},
		{name: "UNIX socket rule", cfg: Config{UnixSocketPaths: []string{"/run/app.sock"}, UnrestrictedFilesystem: true}, want: "--unrestricted-filesystem"},
		{name: "bind rule", cfg: Config{BindTCPPorts: []int{443}, UnrestrictedNetwork: true}, want: "--unrestricted-network"},
		{name: "network rule", cfg: Config{ConnectTCPPorts: []int{443}, UnrestrictedNetwork: true}, want: "--unrestricted-network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Apply(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected policy validation error containing %q, got %v", tc.want, err)
			}
		})
	}
	if err := Apply(Config{UnrestrictedFilesystem: true, UnrestrictedNetwork: true, UnrestrictedScoped: true}); err != nil {
		t.Fatalf("unrestricted policy without rules should remain valid: %v", err)
	}
}

func TestApplyAllUnrestricted(t *testing.T) {
	err := Apply(Config{
		UnrestrictedFilesystem: true,
		UnrestrictedNetwork:    true,
		UnrestrictedScoped:     true,
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestApplySubprocessBestEffort(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperBestEffort")
}

func TestApplySubprocessIgnoreMissing(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperIgnoreMissing")
}

func TestApplySubprocessMissingPathFails(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperMissingPathFails")
}

func TestApplySubprocessNetAndFlags(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperNetAndFlags")
}

func TestApplySubprocessUnrestrictedFSRejectsUnix(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperUnrestrictedFSRejectsUnix")
}

func TestApplySubprocessUnrestrictedNetwork(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperUnrestrictedNetwork")
}

func TestApplySubprocessEmptyRules(t *testing.T) {
	runApplyInSubprocess(t, "TestApplyHelperEmptyRules")
}

func runApplyInSubprocess(t *testing.T, testName string) {
	t.Helper()
	if os.Getenv("LANDRUN_SANDBOX_HELPER") == "1" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(), "LANDRUN_SANDBOX_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v\n%s", testName, err, out)
	}
}

// Helpers invoked only inside the subprocess (see runApplyInSubprocess).

func TestApplyHelperBestEffort(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	dir := t.TempDir()
	err := Apply(Config{
		BestEffort:              true,
		ReadOnlyPaths:           []string{dir},
		ReadOnlyExecutablePaths: []string{"/usr"},
	})
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	// Landlock is process-wide; exit before testing.T tries to clean TempDir.
	os.Exit(0)
}

func TestApplyHelperIgnoreMissing(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	dir := t.TempDir()
	err := Apply(Config{
		BestEffort:              true,
		IgnoreMissingPaths:      true,
		ReadOnlyPaths:           []string{dir, "/nonexistent-landrun-ignore-me"},
		ReadOnlyExecutablePaths: []string{"/usr"},
	})
	if err != nil {
		t.Fatalf("Apply with ignore-missing failed: %v", err)
	}
	os.Exit(0)
}

func TestApplyHelperMissingPathFails(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	err := Apply(Config{
		BestEffort:              true,
		IgnoreMissingPaths:      false,
		ReadOnlyPaths:           []string{"/nonexistent-landrun-must-fail"},
		ReadOnlyExecutablePaths: []string{"/usr"},
	})
	if err == nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestApplyHelperNetAndFlags(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	dir := t.TempDir()
	rwFile := filepath.Join(dir, "rw.txt")
	if err := os.WriteFile(rwFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	err := Apply(Config{
		BestEffort:               true,
		ReadOnlyPaths:            []string{dir},
		ReadWritePaths:           []string{rwFile},
		ReadOnlyExecutablePaths:  []string{"/usr"},
		ReadWriteExecutablePaths: []string{rwFile},
		BindTCPPorts:             []int{18080},
		ConnectTCPPorts:          []int{443},
		DisableLogOriginating:    true,
		EnableLogSubprocesses:    true,
		DisableLogSubdomains:     true,
	})
	abi, probeErr := Probe()
	if probeErr == nil && abi < 7 {
		if err == nil {
			t.Fatalf("expected audit controls to be rejected on ABI %d", abi)
		}
	} else if err != nil {
		t.Fatalf("Apply net/flags failed: %v", err)
	}
	os.Exit(0)
}

func TestApplyHelperUnrestrictedFSRejectsUnix(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	err := Apply(Config{
		BestEffort:             true,
		UnrestrictedFilesystem: true,
		UnixSocketPaths:        []string{"/run/ignored.sock"},
		BindTCPPorts:           []int{18081},
	})
	if err == nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestApplyHelperUnrestrictedNetwork(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	dir := t.TempDir()
	err := Apply(Config{
		BestEffort:              true,
		UnrestrictedNetwork:     true,
		UnrestrictedScoped:      true,
		ReadOnlyPaths:           []string{dir},
		ReadOnlyExecutablePaths: []string{"/usr"},
	})
	if err != nil {
		t.Fatalf("Apply unrestricted network failed: %v", err)
	}
	os.Exit(0)
}

func TestApplyHelperEmptyRules(t *testing.T) {
	if os.Getenv("LANDRUN_SANDBOX_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	// No path/port rules: still create a restrictive ruleset for handled domains.
	err := Apply(Config{BestEffort: true})
	if err != nil {
		t.Fatalf("Apply empty rules failed: %v", err)
	}
	os.Exit(0)
}

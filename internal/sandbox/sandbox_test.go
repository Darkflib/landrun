package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
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

func TestFullNetAccessKeepsUDPUnrestricted(t *testing.T) {
	udpRights := landlock.AccessNetSet(syscall.AccessNetBindUDP | syscall.AccessNetConnectSendUDP)
	if fullNetAccess&udpRights != 0 {
		t.Fatalf("fullNetAccess unexpectedly enables ABI 10 UDP rights: %#x", fullNetAccess&udpRights)
	}
	if fullNetAccess != landlock.AccessNetSet(syscall.AccessNetBindTCP|syscall.AccessNetConnectTCP) {
		t.Fatalf("fullNetAccess changed unexpectedly: %#x", fullNetAccess)
	}
}

func TestEffectivePolicyForABI(t *testing.T) {
	for _, tc := range []struct {
		name          string
		abi           int
		wantPolicyABI int
		wantApplied   bool
		wantTSync     bool
		wantFS        []string
		wantNet       []string
		wantScopes    []string
	}{
		{name: "unsupported", abi: 0},
		{
			name:          "ABI 1 filesystem baseline",
			abi:           1,
			wantPolicyABI: 1,
			wantApplied:   true,
			wantFS: []string{
				"execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
				"make_char", "make_dir", "make_reg", "make_sock", "make_fifo", "make_block", "make_sym",
			},
		},
		{
			name:          "ABI 4 adds truncation and TCP",
			abi:           4,
			wantPolicyABI: 4,
			wantApplied:   true,
			wantFS: []string{
				"execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
				"make_char", "make_dir", "make_reg", "make_sock", "make_fifo", "make_block", "make_sym",
				"refer", "truncate",
			},
			wantNet: []string{"bind_tcp", "connect_tcp"},
		},
		{
			name:          "ABI 6 adds ioctl and scopes",
			abi:           6,
			wantPolicyABI: 6,
			wantApplied:   true,
			wantFS: []string{
				"execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
				"make_char", "make_dir", "make_reg", "make_sock", "make_fifo", "make_block", "make_sym",
				"refer", "truncate", "ioctl_dev",
			},
			wantNet:    []string{"bind_tcp", "connect_tcp"},
			wantScopes: []string{"abstract_unix_socket", "signal"},
		},
		{
			name:          "ABI 8 synchronizes threads without adding handled rights",
			abi:           8,
			wantPolicyABI: 6,
			wantApplied:   true,
			wantTSync:     true,
			wantFS: []string{
				"execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
				"make_char", "make_dir", "make_reg", "make_sock", "make_fifo", "make_block", "make_sym",
				"refer", "truncate", "ioctl_dev",
			},
			wantNet:    []string{"bind_tcp", "connect_tcp"},
			wantScopes: []string{"abstract_unix_socket", "signal"},
		},
		{
			name:          "ABI 9 adds pathname UNIX resolution",
			abi:           9,
			wantPolicyABI: 9,
			wantApplied:   true,
			wantTSync:     true,
			wantFS: []string{
				"execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
				"make_char", "make_dir", "make_reg", "make_sock", "make_fifo", "make_block", "make_sym",
				"refer", "truncate", "ioctl_dev", "resolve_unix",
			},
			wantNet:    []string{"bind_tcp", "connect_tcp"},
			wantScopes: []string{"abstract_unix_socket", "signal"},
		},
		{
			name:          "ABI 10 remains capped at landrun ABI 9 rights",
			abi:           10,
			wantPolicyABI: 9,
			wantApplied:   true,
			wantTSync:     true,
			wantFS: []string{
				"execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file",
				"make_char", "make_dir", "make_reg", "make_sock", "make_fifo", "make_block", "make_sym",
				"refer", "truncate", "ioctl_dev", "resolve_unix",
			},
			wantNet:    []string{"bind_tcp", "connect_tcp"},
			wantScopes: []string{"abstract_unix_socket", "signal"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := effectivePolicyForABI(Config{BestEffort: true}, tc.abi)
			if got.KernelABI != tc.abi || got.PolicyABI != tc.wantPolicyABI || got.Applied != tc.wantApplied || got.ThreadSynchronized != tc.wantTSync {
				t.Fatalf("unexpected policy metadata: %+v", got)
			}
			if !slices.Equal(got.HandledFilesystemRights, tc.wantFS) {
				t.Errorf("filesystem rights: got %v, want %v", got.HandledFilesystemRights, tc.wantFS)
			}
			if !slices.Equal(got.HandledNetworkRights, tc.wantNet) {
				t.Errorf("network rights: got %v, want %v", got.HandledNetworkRights, tc.wantNet)
			}
			if !slices.Equal(got.HandledScopes, tc.wantScopes) {
				t.Errorf("scopes: got %v, want %v", got.HandledScopes, tc.wantScopes)
			}
		})
	}
}

func TestEffectivePolicyRespectsUnrestrictedDomainsAndAuditFlags(t *testing.T) {
	networkOnly := effectivePolicyForABI(Config{
		BestEffort:             true,
		UnrestrictedFilesystem: true,
		UnrestrictedScoped:     true,
	}, 9)
	if networkOnly.PolicyABI != 4 || !slices.Equal(networkOnly.HandledNetworkRights, []string{"bind_tcp", "connect_tcp"}) {
		t.Fatalf("unexpected network-only policy: %+v", networkOnly)
	}
	if len(networkOnly.HandledFilesystemRights) != 0 || len(networkOnly.HandledScopes) != 0 {
		t.Fatalf("unrestricted domains reported handled rights: %+v", networkOnly)
	}

	audited := effectivePolicyForABI(Config{
		BestEffort:            true,
		DisableLogOriginating: true,
		EnableLogSubprocesses: true,
		DisableLogSubdomains:  true,
	}, 7)
	if audited.PolicyABI != 7 || !slices.Equal(audited.AuditFlags, []string{"disable_originating", "enable_subprocesses", "disable_subdomains"}) {
		t.Fatalf("unexpected audited policy: %+v", audited)
	}

	unrestricted := effectivePolicyForABI(Config{
		BestEffort:             true,
		UnrestrictedFilesystem: true,
		UnrestrictedNetwork:    true,
		UnrestrictedScoped:     true,
	}, 9)
	if unrestricted.Applied || unrestricted.PolicyABI != 0 {
		t.Fatalf("all-unrestricted policy should be a no-op: %+v", unrestricted)
	}
}

func TestEffectivePolicyStringIsStructuredAndDeterministic(t *testing.T) {
	report := effectivePolicyForABI(Config{
		BestEffort:             true,
		UnrestrictedFilesystem: true,
		UnrestrictedScoped:     true,
	}, 9)
	want := `{"applied":true,"kernel_abi":9,"policy_abi":4,"best_effort":true,"handled_filesystem_rights":[],"handled_network_rights":["bind_tcp","connect_tcp"],"handled_scopes":[],"audit_flags":[],"thread_synchronized":true}`
	if got := report.String(); got != want {
		t.Fatalf("EffectivePolicy.String() = %q, want %q", got, want)
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
		{
			name: "disable originating audit without a restricted domain",
			cfg: Config{
				UnrestrictedFilesystem: true,
				UnrestrictedNetwork:    true,
				UnrestrictedScoped:     true,
				DisableLogOriginating:  true,
			},
			want: "audit logging controls require at least one restricted domain",
		},
		{
			name: "enable subprocess audit without a restricted domain",
			cfg: Config{
				UnrestrictedFilesystem: true,
				UnrestrictedNetwork:    true,
				UnrestrictedScoped:     true,
				EnableLogSubprocesses:  true,
			},
			want: "audit logging controls require at least one restricted domain",
		},
		{
			name: "disable subdomain audit without a restricted domain",
			cfg: Config{
				UnrestrictedFilesystem: true,
				UnrestrictedNetwork:    true,
				UnrestrictedScoped:     true,
				DisableLogSubdomains:   true,
			},
			want: "audit logging controls require at least one restricted domain",
		},
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
	if runtime.GOOS != "linux" {
		t.Skip("Landlock integration tests require Linux")
	}
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

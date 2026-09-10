package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/zouuup/landrun/internal/sandbox"
)

func TestLoadPolicyFile(t *testing.T) {
	path := writePolicyFile(t, `{
  "version": 1,
  "ro": ["relative/ro"],
  "rox": ["/rox"],
  "rw": ["/rw"],
  "rwx": ["/rwx"],
  "unix": ["/run/service.sock"],
  "bind-tcp": [0, 8080],
  "connect-tcp": [443],
  "env": ["HOME", "MODE=test"],
  "preserve-fd": [3],
  "best-effort": true,
  "unrestricted-filesystem": false,
  "unrestricted-network": false,
  "unrestricted-scoped": true,
  "ignore-missing": true,
  "log-disable-originating": true,
  "log-enable-subprocesses": true,
  "log-disable-subdomains": true,
  "ldd": true,
  "add-exec": true
}`)

	got, err := loadPolicyFile(path)
	if err != nil {
		t.Fatalf("loadPolicyFile() error = %v", err)
	}
	want := launchPolicy{
		Sandbox: sandbox.Config{
			ReadOnlyPaths:            []string{"relative/ro", "/rox"},
			ReadWritePaths:           []string{"/rw", "/rwx"},
			ReadOnlyExecutablePaths:  []string{"/rox"},
			ReadWriteExecutablePaths: []string{"/rwx"},
			UnixSocketPaths:          []string{"/run/service.sock"},
			BindTCPPorts:             []int{0, 8080},
			ConnectTCPPorts:          []int{443},
			BestEffort:               true,
			UnrestrictedScoped:       true,
			IgnoreMissingPaths:       true,
			DisableLogOriginating:    true,
			EnableLogSubprocesses:    true,
			DisableLogSubdomains:     true,
		},
		Environment:         []string{"HOME", "MODE=test"},
		PreserveDescriptors: []int{3},
		ResolveLibraries:    true,
		AddExecutable:       true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loadPolicyFile() = %#v, want %#v", got, want)
	}
}

func TestLoadPolicyFileRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "missing version", content: `{}`, wantErr: "unsupported policy file version 0"},
		{name: "future version", content: `{"version": 2}`, wantErr: "unsupported policy file version 2"},
		{name: "unknown field", content: `{"version": 1, "readonly": []}`, wantErr: "unknown field"},
		{name: "duplicate field", content: `{"version": 1, "ro": [], "ro": []}`, wantErr: `duplicate object key "ro"`},
		{name: "trailing document", content: `{"version": 1} {"version": 1}`, wantErr: "exactly one JSON value"},
		{name: "wrong type", content: `{"version": 1, "connect-tcp": ["443"]}`, wantErr: "cannot unmarshal"},
		{name: "null field", content: `{"version": 1, "ro": null}`, wantErr: "null values are not allowed"},
		{name: "null array entry", content: `{"version": 1, "bind-tcp": [null]}`, wantErr: "null values are not allowed"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadPolicyFile(writePolicyFile(t, test.content))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("loadPolicyFile() error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestLoadPolicyFileRejectsNonRegularAndOversizedFiles(t *testing.T) {
	if _, err := loadPolicyFile(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v, want regular-file error", err)
	}

	oversized := `{"version":1,"padding":"` + strings.Repeat("x", maxPolicyFileSize) + `"}`
	if _, err := loadPolicyFile(writePolicyFile(t, oversized)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized error = %v, want size-limit error", err)
	}
}

func TestMergeLaunchPoliciesComposesGrantsAndOptions(t *testing.T) {
	base := launchPolicy{
		Sandbox: sandbox.Config{
			ReadOnlyPaths:   []string{"from-file"},
			ConnectTCPPorts: []int{443},
			BestEffort:      true,
		},
		Environment:      []string{"FROM_FILE=1"},
		ResolveLibraries: true,
	}
	additional := launchPolicy{
		Sandbox: sandbox.Config{
			ReadOnlyPaths:      []string{"from-cli"},
			BindTCPPorts:       []int{8080},
			UnrestrictedScoped: true,
		},
		Environment:   []string{"FROM_CLI=1"},
		AddExecutable: true,
	}

	got := mergeLaunchPolicies(base, additional)
	if want := []string{"from-file", "from-cli"}; !reflect.DeepEqual(got.Sandbox.ReadOnlyPaths, want) {
		t.Fatalf("read-only paths = %#v, want %#v", got.Sandbox.ReadOnlyPaths, want)
	}
	if want := []int{443}; !reflect.DeepEqual(got.Sandbox.ConnectTCPPorts, want) {
		t.Fatalf("connect ports = %#v, want %#v", got.Sandbox.ConnectTCPPorts, want)
	}
	if want := []int{8080}; !reflect.DeepEqual(got.Sandbox.BindTCPPorts, want) {
		t.Fatalf("bind ports = %#v, want %#v", got.Sandbox.BindTCPPorts, want)
	}
	if !got.Sandbox.BestEffort || !got.Sandbox.UnrestrictedScoped || !got.ResolveLibraries || !got.AddExecutable {
		t.Fatalf("merged boolean options were not preserved: %#v", got)
	}
	if want := []string{"FROM_FILE=1", "FROM_CLI=1"}; !reflect.DeepEqual(got.Environment, want) {
		t.Fatalf("environment = %#v, want %#v", got.Environment, want)
	}

	got.Sandbox.ReadOnlyPaths[0] = "changed"
	if base.Sandbox.ReadOnlyPaths[0] != "from-file" {
		t.Fatal("mergeLaunchPolicies() aliased its input slices")
	}
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/policy.json"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

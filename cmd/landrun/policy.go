package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/zouuup/landrun/internal/sandbox"
)

const (
	policyFileVersion = 1
	maxPolicyFileSize = 1 << 20
)

// policyFile mirrors the policy-related CLI flags. The command, log level,
// version, and probe controls intentionally remain outside policy files.
type policyFile struct {
	Version                int      `json:"version"`
	ReadOnly               []string `json:"ro"`
	ReadOnlyExecutable     []string `json:"rox"`
	ReadWrite              []string `json:"rw"`
	ReadWriteExecutable    []string `json:"rwx"`
	UnixSockets            []string `json:"unix"`
	BindTCP                []int    `json:"bind-tcp"`
	ConnectTCP             []int    `json:"connect-tcp"`
	Environment            []string `json:"env"`
	PreserveDescriptors    []int    `json:"preserve-fd"`
	BestEffort             bool     `json:"best-effort"`
	UnrestrictedFilesystem bool     `json:"unrestricted-filesystem"`
	UnrestrictedNetwork    bool     `json:"unrestricted-network"`
	UnrestrictedScoped     bool     `json:"unrestricted-scoped"`
	IgnoreMissing          bool     `json:"ignore-missing"`
	DisableLogOriginating  bool     `json:"log-disable-originating"`
	EnableLogSubprocesses  bool     `json:"log-enable-subprocesses"`
	DisableLogSubdomains   bool     `json:"log-disable-subdomains"`
	ResolveLibraries       bool     `json:"ldd"`
	AddExecutable          bool     `json:"add-exec"`
}

type launchPolicy struct {
	Sandbox             sandbox.Config
	Environment         []string
	PreserveDescriptors []int
	ResolveLibraries    bool
	AddExecutable       bool
}

func loadPolicyFile(path string) (launchPolicy, error) {
	file, err := os.Open(path)
	if err != nil {
		return launchPolicy{}, fmt.Errorf("open policy file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return launchPolicy{}, fmt.Errorf("inspect policy file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return launchPolicy{}, fmt.Errorf("policy file must be a regular file: %s", path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return launchPolicy{}, fmt.Errorf("read policy file: %w", err)
	}
	if len(data) > maxPolicyFileSize {
		return launchPolicy{}, fmt.Errorf("policy file exceeds %d bytes", maxPolicyFileSize)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return launchPolicy{}, fmt.Errorf("parse policy file: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy policyFile
	if err := decoder.Decode(&policy); err != nil {
		return launchPolicy{}, fmt.Errorf("parse policy file: %w", err)
	}
	if err := expectJSONEOF(decoder); err != nil {
		return launchPolicy{}, fmt.Errorf("parse policy file: %w", err)
	}
	if policy.Version != policyFileVersion {
		return launchPolicy{}, fmt.Errorf(
			"unsupported policy file version %d (expected %d)",
			policy.Version,
			policyFileVersion,
		)
	}

	return policy.launchPolicy(), nil
}

func (p policyFile) launchPolicy() launchPolicy {
	return launchPolicy{
		Sandbox: sandbox.Config{
			ReadOnlyPaths:            joinSlices(p.ReadOnly, p.ReadOnlyExecutable),
			ReadWritePaths:           joinSlices(p.ReadWrite, p.ReadWriteExecutable),
			ReadOnlyExecutablePaths:  append([]string(nil), p.ReadOnlyExecutable...),
			ReadWriteExecutablePaths: append([]string(nil), p.ReadWriteExecutable...),
			UnixSocketPaths:          append([]string(nil), p.UnixSockets...),
			BindTCPPorts:             append([]int(nil), p.BindTCP...),
			ConnectTCPPorts:          append([]int(nil), p.ConnectTCP...),
			BestEffort:               p.BestEffort,
			UnrestrictedFilesystem:   p.UnrestrictedFilesystem,
			UnrestrictedNetwork:      p.UnrestrictedNetwork,
			UnrestrictedScoped:       p.UnrestrictedScoped,
			IgnoreMissingPaths:       p.IgnoreMissing,
			DisableLogOriginating:    p.DisableLogOriginating,
			EnableLogSubprocesses:    p.EnableLogSubprocesses,
			DisableLogSubdomains:     p.DisableLogSubdomains,
		},
		Environment:         append([]string(nil), p.Environment...),
		PreserveDescriptors: append([]int(nil), p.PreserveDescriptors...),
		ResolveLibraries:    p.ResolveLibraries,
		AddExecutable:       p.AddExecutable,
	}
}

func mergeLaunchPolicies(base, additional launchPolicy) launchPolicy {
	return launchPolicy{
		Sandbox: sandbox.Config{
			ReadOnlyPaths:            joinSlices(base.Sandbox.ReadOnlyPaths, additional.Sandbox.ReadOnlyPaths),
			ReadWritePaths:           joinSlices(base.Sandbox.ReadWritePaths, additional.Sandbox.ReadWritePaths),
			ReadOnlyExecutablePaths:  joinSlices(base.Sandbox.ReadOnlyExecutablePaths, additional.Sandbox.ReadOnlyExecutablePaths),
			ReadWriteExecutablePaths: joinSlices(base.Sandbox.ReadWriteExecutablePaths, additional.Sandbox.ReadWriteExecutablePaths),
			UnixSocketPaths:          joinSlices(base.Sandbox.UnixSocketPaths, additional.Sandbox.UnixSocketPaths),
			BindTCPPorts:             joinSlices(base.Sandbox.BindTCPPorts, additional.Sandbox.BindTCPPorts),
			ConnectTCPPorts:          joinSlices(base.Sandbox.ConnectTCPPorts, additional.Sandbox.ConnectTCPPorts),
			BestEffort:               base.Sandbox.BestEffort || additional.Sandbox.BestEffort,
			UnrestrictedFilesystem:   base.Sandbox.UnrestrictedFilesystem || additional.Sandbox.UnrestrictedFilesystem,
			UnrestrictedNetwork:      base.Sandbox.UnrestrictedNetwork || additional.Sandbox.UnrestrictedNetwork,
			UnrestrictedScoped:       base.Sandbox.UnrestrictedScoped || additional.Sandbox.UnrestrictedScoped,
			IgnoreMissingPaths:       base.Sandbox.IgnoreMissingPaths || additional.Sandbox.IgnoreMissingPaths,
			DisableLogOriginating:    base.Sandbox.DisableLogOriginating || additional.Sandbox.DisableLogOriginating,
			EnableLogSubprocesses:    base.Sandbox.EnableLogSubprocesses || additional.Sandbox.EnableLogSubprocesses,
			DisableLogSubdomains:     base.Sandbox.DisableLogSubdomains || additional.Sandbox.DisableLogSubdomains,
		},
		Environment:         joinSlices(base.Environment, additional.Environment),
		PreserveDescriptors: joinSlices(base.PreserveDescriptors, additional.PreserveDescriptors),
		ResolveLibraries:    base.ResolveLibraries || additional.ResolveLibraries,
		AddExecutable:       base.AddExecutable || additional.AddExecutable,
	}
}

func joinSlices[T any](first, second []T) []T {
	joined := make([]T, 0, len(first)+len(second))
	joined = append(joined, first...)
	return append(joined, second...)
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	return expectJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		if token == nil {
			return errors.New("null values are not allowed")
		}
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}

	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	expected := json.Delim('}')
	if delimiter == '[' {
		expected = ']'
	}
	if closing != expected {
		return fmt.Errorf("unexpected JSON delimiter %q", closing)
	}
	return nil
}

func expectJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("policy file must contain exactly one JSON value")
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/urfave/cli/v3"
	"github.com/zouuup/landrun/internal/elfdeps"
	"github.com/zouuup/landrun/internal/exec"
	"github.com/zouuup/landrun/internal/log"
	"github.com/zouuup/landrun/internal/sandbox"
)

// Version is the current version of landrun
const Version = "0.1.20"

// launcherErrorExitCode distinguishes landrun setup and policy failures from
// the exit status of a command that was successfully executed.
const launcherErrorExitCode = 125

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	if err := newCommand().Run(context.Background(), args); err != nil {
		log.Error("%v", err)
		return launcherErrorExitCode
	}
	return 0
}

func newCommand() *cli.Command {
	return &cli.Command{
		Name:    "landrun",
		Usage:   "Run a command in a Landlock sandbox",
		Version: versionString(),
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "probe",
				Usage: "Report the running kernel's Landlock ABI and exit",
			},
			&cli.BoolFlag{
				Name:  "probe-json",
				Usage: "Report the running kernel's Landlock ABI as JSON and exit",
			},
			&cli.StringFlag{
				Name:    "log-level",
				Usage:   "Set logging level (error, info, debug)",
				Value:   "error",
				Sources: cli.EnvVars("LANDRUN_LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:     "policy",
				Usage:    "Load policy options from this versioned JSON file",
				OnlyOnce: true,
			},
			&cli.StringSliceFlag{
				Name:  "ro",
				Usage: "Allow read-only access to this path",
			},
			&cli.StringSliceFlag{
				Name:  "rox",
				Usage: "Allow read-only access with execution to this path",
			},
			&cli.StringSliceFlag{
				Name:  "rw",
				Usage: "Allow read-write access to this path",
			},
			&cli.StringSliceFlag{
				Name:  "rwx",
				Usage: "Allow read-write access with execution to this path",
			},
			&cli.StringSliceFlag{
				Name:  "unix",
				Usage: "Allow connect(2)/sendmsg(2) on this pathname UNIX domain socket (Landlock ABI v9+)",
			},
			&cli.IntSliceFlag{
				Name:   "bind-tcp",
				Usage:  "Allow binding to these TCP ports (0-65535; 0 requests an ephemeral port)",
				Hidden: false,
			},
			&cli.IntSliceFlag{
				Name:   "connect-tcp",
				Usage:  "Allow connecting to these TCP ports (1-65535)",
				Hidden: false,
			},
			&cli.BoolFlag{
				Name:  "best-effort",
				Usage: "Use best effort mode (fall back to less restrictive sandbox if necessary)",
				Value: false,
			},
			&cli.StringSliceFlag{
				Name:  "env",
				Usage: "Environment variables to pass to the sandboxed command (KEY=VALUE or just KEY to pass current value)",
			},
			&cli.IntSliceFlag{
				Name:  "preserve-fd",
				Usage: "Preserve this already-open file descriptor (3 or greater) across exec",
			},
			&cli.BoolFlag{
				Name:  "unrestricted-filesystem",
				Usage: "Allow unrestricted filesystem access",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "unrestricted-network",
				Usage: "Allow unrestricted network access",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "unrestricted-scoped",
				Usage: "Allow unrestricted IPC scoping (do not restrict abstract UNIX sockets and signals; Landlock ABI v6+)",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "ignore-missing",
				Usage: "Gracefully ignore paths that do not exist instead of failing",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "log-disable-originating",
				Usage: "Disable audit logging of denials from the originating process (Landlock ABI v7+)",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "log-enable-subprocesses",
				Usage: "Enable audit logging of denials after execve(2) in subprocesses (Landlock ABI v7+)",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "log-disable-subdomains",
				Usage: "Disable audit logging of denials from nested Landlock domains (Landlock ABI v7+)",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "ldd",
				Usage: "Automatically detect and add library dependencies to --rox",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "add-exec",
				Usage: "Automatically add the executable path to --rox",
				Value: false,
			},
		},
		Before: func(ctx context.Context, c *cli.Command) (context.Context, error) {
			log.SetLevel(c.String("log-level"))
			return ctx, nil
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			if c.Bool("probe") || c.Bool("probe-json") {
				return reportProbe(c.Bool("probe-json"))
			}
			args := c.Args().Slice()
			if len(args) == 0 {
				return errors.New("missing command to run")
			}

			policy := launchPolicy{}
			if c.IsSet("policy") {
				policyPath := c.String("policy")
				if policyPath == "" {
					return errors.New("policy file path must not be empty")
				}
				filePolicy, err := loadPolicyFile(policyPath)
				if err != nil {
					return fmt.Errorf("invalid policy file %q: %w", policyPath, err)
				}
				policy = filePolicy
			}
			policy = mergeLaunchPolicies(policy, policyFromCommand(c))

			preservedDescriptors := policy.PreserveDescriptors
			if err := exec.ValidateInheritedDescriptors(preservedDescriptors); err != nil {
				return fmt.Errorf("invalid inherited descriptors: %w", err)
			}

			binary, err := osexec.LookPath(args[0])
			if err != nil {
				return fmt.Errorf("failed to find binary: %w", err)
			}
			executable, err := exec.OpenExecutable(binary)
			if err != nil {
				return fmt.Errorf("failed to open executable: %w", err)
			}
			defer executable.Close()

			// Add command to readOnlyExecutablePaths
			if policy.AddExecutable {
				policy.Sandbox.ReadOnlyExecutablePaths = append(policy.Sandbox.ReadOnlyExecutablePaths, binary)
				log.Debug("Added executable path: %v", binary)
			}

			// If --ldd flag is set, detect and add library dependencies
			if policy.ResolveLibraries {
				libPaths, err := elfdeps.GetLibraryDependencies(binary)
				if err != nil {
					return fmt.Errorf("failed to detect library dependencies: %w", err)
				}
				// Add library directories to readOnlyExecutablePaths
				policy.Sandbox.ReadOnlyExecutablePaths = append(policy.Sandbox.ReadOnlyExecutablePaths, libPaths...)
				log.Debug("Added library paths: %v", libPaths)
			}

			// Process environment variables
			envVars := processEnvironmentVars(policy.Environment)

			if err := sandbox.Apply(policy.Sandbox); err != nil {
				return fmt.Errorf("failed to apply sandbox: %w", err)
			}
			if err := exec.PrepareInheritedDescriptors(preservedDescriptors); err != nil {
				return fmt.Errorf("failed to prepare inherited descriptors: %w", err)
			}

			if err := exec.RunFile(executable, args, envVars); err != nil {
				return fmt.Errorf("failed to execute command: %w", err)
			}
			return nil
		},
	}
}

func policyFromCommand(c *cli.Command) launchPolicy {
	readOnlyExecutable := c.StringSlice("rox")
	readWriteExecutable := c.StringSlice("rwx")
	return launchPolicy{
		Sandbox: sandbox.Config{
			ReadOnlyPaths:            joinSlices(c.StringSlice("ro"), readOnlyExecutable),
			ReadWritePaths:           joinSlices(c.StringSlice("rw"), readWriteExecutable),
			ReadOnlyExecutablePaths:  append([]string(nil), readOnlyExecutable...),
			ReadWriteExecutablePaths: append([]string(nil), readWriteExecutable...),
			UnixSocketPaths:          c.StringSlice("unix"),
			BindTCPPorts:             c.IntSlice("bind-tcp"),
			ConnectTCPPorts:          c.IntSlice("connect-tcp"),
			BestEffort:               c.Bool("best-effort"),
			UnrestrictedFilesystem:   c.Bool("unrestricted-filesystem"),
			UnrestrictedNetwork:      c.Bool("unrestricted-network"),
			UnrestrictedScoped:       c.Bool("unrestricted-scoped"),
			IgnoreMissingPaths:       c.Bool("ignore-missing"),
			DisableLogOriginating:    c.Bool("log-disable-originating"),
			EnableLogSubprocesses:    c.Bool("log-enable-subprocesses"),
			DisableLogSubdomains:     c.Bool("log-disable-subdomains"),
		},
		Environment:         c.StringSlice("env"),
		PreserveDescriptors: c.IntSlice("preserve-fd"),
		ResolveLibraries:    c.Bool("ldd"),
		AddExecutable:       c.Bool("add-exec"),
	}
}

func versionString() string {
	goVersion := runtime.Version()
	revision := "unknown"
	modified := false
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.GoVersion != "" {
			goVersion = info.GoVersion
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
	}
	if modified && revision != "unknown" {
		revision += "+modified"
	}
	return fmt.Sprintf("%s (revision %s, %s)", Version, revision, goVersion)
}

func reportProbe(asJSON bool) error {
	abi, err := sandbox.Probe()
	if asJSON {
		result := struct {
			ABI       int    `json:"abi"`
			Supported bool   `json:"supported"`
			Error     string `json:"error,omitempty"`
		}{ABI: abi, Supported: err == nil && abi > 0}
		if err != nil {
			result.Error = err.Error()
		}
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return fmt.Errorf("encode Landlock probe result: %w", marshalErr)
		}
		fmt.Println(string(encoded))
		if err != nil {
			return fmt.Errorf("Landlock is unavailable: %w", err)
		}
		return nil
	}

	if err != nil {
		return fmt.Errorf("Landlock is unavailable: %w", err)
	}
	fmt.Printf("Landlock ABI: %d\n", abi)
	return nil
}

// processEnvironmentVars processes the env flag values
func processEnvironmentVars(envFlags []string) []string {
	result := []string{}

	for _, env := range envFlags {
		// If the flag is just a key (no = sign), get the value from the current environment
		if !strings.Contains(env, "=") {
			if val, exists := os.LookupEnv(env); exists {
				result = append(result, env+"="+val)
			}
		} else {
			// Flag already contains the value (KEY=VALUE format)
			result = append(result, env)
		}
	}

	return result
}

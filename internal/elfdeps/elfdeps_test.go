//go:build linux

package elfdeps

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Test helpers against a known binary in the system: find `true` via LookPath
func TestParseAndResolveTrue(t *testing.T) {
	bin, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("failed to find 'true' binary: %v", err)
	}

	file, err := os.Open(bin)
	if err != nil {
		t.Fatalf("failed to open %s: %v", bin, err)
	}
	defer func() { _ = file.Close() }()

	f, err := elf.NewFile(file)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", bin, err)
	}

	interp := parseInterp(f)
	if interp == "" {
		t.Fatalf("expected interpreter for %s, got empty", bin)
	}

	needed, rpaths := parseDynamic(f)
	if needed == nil {
		needed = []string{}
	}

	origin := filepath.Dir(bin)
	rpaths = normalizeRpaths(rpaths, origin)
	flags, err := readELFFlags(file, f)
	if err != nil {
		t.Fatalf("failed to read ELF flags from %s: %v", bin, err)
	}
	paths, unresolved := resolveSonames(needed, rpaths, f.Class, f.Machine, f.Data, flags)
	if len(unresolved) != 0 {
		t.Fatalf("unresolved libraries for %s: %v", bin, unresolved)
	}
	if paths == nil {
		paths = []string{}
	}

	// Ensure interpreter path exists on filesystem
	if _, err := os.Stat(interp); err != nil {
		t.Fatalf("interp path %s does not exist: %v", interp, err)
	}

	// If there are resolved library paths, they must exist and match the
	// binary's architecture (not e.g. an x32 libc for an x86-64 binary).
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("resolved library path %s does not exist: %v", p, err)
		}
		lib, err := elf.Open(p)
		if err != nil {
			continue
		}
		if lib.Class != f.Class || lib.Machine != f.Machine {
			lib.Close()
			t.Fatalf("resolved %s has class/machine %v/%v, want %v/%v",
				p, lib.Class, lib.Machine, f.Class, f.Machine)
		}
		lib.Close()
	}
}

func TestRecursiveDependencies(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found, skipping test")
	}
	// Create a temporary directory for compiled artifacts
	tempDir := t.TempDir()

	// Compile liba.so
	libaSrc := "testdata/liba.c"
	libaSo := filepath.Join(tempDir, "liba.so")
	cmd := exec.Command("gcc", "-fPIC", "-shared", "-o", libaSo, libaSrc)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile liba.so: %v\n%s", err, string(out))
	}

	// Compile libb.so
	libbSrc := "testdata/libb.c"
	libbSo := filepath.Join(tempDir, "libb.so")
	cmd = exec.Command("gcc", "-fPIC", "-shared", "-o", libbSo, libbSrc, "-L"+tempDir, "-la", "-Wl,-rpath,$ORIGIN")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile libb.so: %v\n%s", err, string(out))
	}

	// Compile test_binary
	mainSrc := "testdata/main.c"
	testBin := filepath.Join(tempDir, "test_binary")
	cmd = exec.Command("gcc", "-o", testBin, mainSrc, "-L"+tempDir, "-lb", "-Wl,-rpath,$ORIGIN")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile test_binary: %v\n%s", err, string(out))
	}

	// Run the actual test logic
	deps, err := GetLibraryDependencies(testBin)
	if err != nil {
		t.Fatalf("GetLibraryDependencies failed: %v", err)
	}

	foundA := false
	foundB := false
	for _, dep := range deps {
		if dep == libaSo {
			foundA = true
		}
		if dep == libbSo {
			foundB = true
		}
	}

	if !foundA {
		t.Errorf("expected to find %s in dependency list, but didn't. Found: %v", libaSo, deps)
	}
	if !foundB {
		t.Errorf("expected to find %s in dependency list, but didn't. Found: %v", libbSo, deps)
	}
}

func TestUnresolvedDependencyDoesNotExecuteLdconfigFromPath(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not found, skipping test")
	}

	tempDir := t.TempDir()
	libPath := filepath.Join(tempDir, "libhostile.so")
	cmd := exec.Command("gcc", "-fPIC", "-shared", "-o", libPath, "testdata/liba.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile test library: %v\n%s", err, string(out))
	}

	testBin := filepath.Join(tempDir, "needs-hostile-library")
	cmd = exec.Command("gcc", "-o", testBin, "testdata/maina.c", "-L"+tempDir, "-lhostile")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile test binary: %v\n%s", err, string(out))
	}
	if err := os.Remove(libPath); err != nil {
		t.Fatalf("failed to remove test library: %v", err)
	}

	fakeBinDir := filepath.Join(tempDir, "fake-bin")
	if err := os.Mkdir(fakeBinDir, 0o755); err != nil {
		t.Fatalf("failed to create fake bin directory: %v", err)
	}
	marker := filepath.Join(tempDir, "ldconfig-ran")
	fakeLdconfig := filepath.Join(fakeBinDir, "ldconfig")
	script := "#!/bin/sh\n: > \"$LANDRUN_LDCONFIG_MARKER\"\n"
	if err := os.WriteFile(fakeLdconfig, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to create fake ldconfig: %v", err)
	}
	t.Setenv("LANDRUN_LDCONFIG_MARKER", marker)
	t.Setenv("PATH", fakeBinDir)

	_, err := GetLibraryDependencies(testBin)
	if err == nil || !strings.Contains(err.Error(), "libhostile.so") {
		t.Fatalf("expected unresolved libhostile.so error, got %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("dependency discovery executed ambient ldconfig; marker stat error: %v", statErr)
	}
}

func TestGetLibraryDependencies(t *testing.T) {
	bin, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("failed to find 'true' binary: %v", err)
	}
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("failed to open %s: %v", bin, err)
	}
	class, machine := f.Class, f.Machine
	f.Close()

	paths, err := GetLibraryDependencies(bin)
	if err != nil {
		t.Fatalf("GetLibraryDependencies failed: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected non-empty dependency list for %s", bin)
	}
	// ensure returned paths are absolute, exist, and match the binary arch
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			t.Fatalf("expected absolute path, got %s", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("path %s does not exist: %v", p, err)
		}
		if strings.Contains(p, "libx32") && class == elf.ELFCLASS64 {
			t.Fatalf("x86-64 binary resolved to x32 path %s", p)
		}
		lib, err := elf.Open(p)
		if err != nil {
			continue // e.g. ld.so.cache
		}
		mismatched := lib.Class != class || lib.Machine != machine
		lib.Close()
		if mismatched {
			t.Fatalf("dependency %s does not match binary arch", p)
		}
	}
}

func TestResolveSonamesOriginExpansion(t *testing.T) {
	// Create a temp dir and a lib subdir to simulate $ORIGIN/lib
	tmpDir := t.TempDir()
	libDir := filepath.Join(tmpDir, "lib")
	if err := os.Mkdir(libDir, 0755); err != nil {
		t.Fatalf("failed create lib dir: %v", err)
	}

	libName := "liborigin.so"
	libPath := filepath.Join(libDir, libName)
	f, err := os.Create(libPath)
	if err != nil {
		t.Fatalf("failed to create lib file: %v", err)
	}
	f.Close()

	// rpath using $ORIGIN should resolve to tmpDir/lib
	rpaths1 := normalizeRpaths([]string{"$ORIGIN/lib"}, tmpDir)
	out, unresolved := resolveSonames([]string{libName}, rpaths1, elf.ELFCLASS64, elf.EM_X86_64, elf.ELFDATA2LSB, 0)
	if len(unresolved) != 0 {
		t.Fatalf("unexpected unresolved libraries: %v", unresolved)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 resolved path for $ORIGIN, got %d", len(out))
	}
	if out[0] != libPath {
		t.Fatalf("expected %s, got %s", libPath, out[0])
	}

	// relative rpath should also resolve against origin
	rpaths2 := normalizeRpaths([]string{"lib"}, tmpDir)
	out2, unresolved := resolveSonames([]string{libName}, rpaths2, elf.ELFCLASS64, elf.EM_X86_64, elf.ELFDATA2LSB, 0)
	if len(unresolved) != 0 {
		t.Fatalf("unexpected unresolved libraries: %v", unresolved)
	}
	if len(out2) != 1 {
		t.Fatalf("expected 1 resolved path for relative rpath, got %d", len(out2))
	}
	if out2[0] != libPath {
		t.Fatalf("expected %s, got %s", libPath, out2[0])
	}
}

func TestStandardLibDirs(t *testing.T) {
	cases := []struct {
		name      string
		class     elf.Class
		machine   elf.Machine
		data      elf.Data
		flags     uint32
		needles   []string
		forbidden string
	}{
		{name: "amd64", class: elf.ELFCLASS64, machine: elf.EM_X86_64, data: elf.ELFDATA2LSB, needles: []string{"/lib/x86_64-linux-gnu"}},
		{name: "x32", class: elf.ELFCLASS32, machine: elf.EM_X86_64, data: elf.ELFDATA2LSB, needles: []string{"/libx32", "/lib/x86_64-linux-gnux32"}},
		{name: "i386", class: elf.ELFCLASS32, machine: elf.EM_386, data: elf.ELFDATA2LSB, needles: []string{"/lib/i386-linux-gnu"}},
		{name: "arm64", class: elf.ELFCLASS64, machine: elf.EM_AARCH64, data: elf.ELFDATA2LSB, needles: []string{"/lib/aarch64-linux-gnu"}, forbidden: "/lib/aarch64_be-linux-gnu"},
		{name: "arm64 big endian", class: elf.ELFCLASS64, machine: elf.EM_AARCH64, data: elf.ELFDATA2MSB, needles: []string{"/lib/aarch64_be-linux-gnu"}, forbidden: "/lib/aarch64-linux-gnu"},
		{name: "armhf", class: elf.ELFCLASS32, machine: elf.EM_ARM, data: elf.ELFDATA2LSB, needles: []string{"/lib/arm-linux-gnueabihf"}},
		{name: "armeb", class: elf.ELFCLASS32, machine: elf.EM_ARM, data: elf.ELFDATA2MSB, needles: []string{"/lib/armeb-linux-gnu"}, forbidden: "/lib/armeb-linux-gnueabi"},
		{name: "riscv64", class: elf.ELFCLASS64, machine: elf.EM_RISCV, data: elf.ELFDATA2LSB, needles: []string{"/lib/riscv64-linux-gnu"}},
		{name: "riscv32", class: elf.ELFCLASS32, machine: elf.EM_RISCV, data: elf.ELFDATA2LSB, needles: []string{"/lib/riscv32-linux-gnu"}},
		{name: "ppc64el", class: elf.ELFCLASS64, machine: elf.EM_PPC64, data: elf.ELFDATA2LSB, needles: []string{"/lib/powerpc64le-linux-gnu"}, forbidden: "/lib/powerpc64-linux-gnu"},
		{name: "ppc64", class: elf.ELFCLASS64, machine: elf.EM_PPC64, data: elf.ELFDATA2MSB, needles: []string{"/lib/powerpc64-linux-gnu"}, forbidden: "/lib/powerpc64le-linux-gnu"},
		{name: "ppc32", class: elf.ELFCLASS32, machine: elf.EM_PPC, data: elf.ELFDATA2MSB, needles: []string{"/lib/powerpc-linux-gnu"}, forbidden: "/lib/powerpc-linux-gnuspe"},
		{name: "ppcspe", class: elf.ELFCLASS32, machine: elf.EM_PPC, data: elf.ELFDATA2MSB, flags: ppcEmbedded, needles: []string{"/lib/powerpc-linux-gnuspe"}, forbidden: "/lib/powerpc-linux-gnu"},
		{name: "s390x", class: elf.ELFCLASS64, machine: elf.EM_S390, data: elf.ELFDATA2MSB, needles: []string{"/lib/s390x-linux-gnu"}},
		{name: "s390", class: elf.ELFCLASS32, machine: elf.EM_S390, data: elf.ELFDATA2MSB, needles: []string{"/lib/s390-linux-gnu"}},
		{name: "ia64", class: elf.ELFCLASS64, machine: elf.EM_IA_64, data: elf.ELFDATA2LSB, needles: []string{"/lib/ia64-linux-gnu"}},
		{name: "sparc64", class: elf.ELFCLASS64, machine: elf.EM_SPARCV9, data: elf.ELFDATA2MSB, needles: []string{"/lib/sparc64-linux-gnu"}},
		{name: "sparc32", class: elf.ELFCLASS32, machine: elf.EM_SPARC, data: elf.ELFDATA2MSB, needles: []string{"/lib/sparc-linux-gnu"}},
		{name: "mips64el", class: elf.ELFCLASS64, machine: elf.EM_MIPS, data: elf.ELFDATA2LSB, needles: []string{"/lib/mips64el-linux-gnuabi64"}, forbidden: "/lib/mips64-linux-gnuabi64"},
		{name: "mips64", class: elf.ELFCLASS64, machine: elf.EM_MIPS, data: elf.ELFDATA2MSB, needles: []string{"/lib/mips64-linux-gnuabi64"}, forbidden: "/lib/mips64el-linux-gnuabi64"},
		{name: "mipsel o32", class: elf.ELFCLASS32, machine: elf.EM_MIPS, data: elf.ELFDATA2LSB, needles: []string{"/lib/mipsel-linux-gnu"}, forbidden: "/lib/mips-linux-gnu"},
		{name: "mips n32", class: elf.ELFCLASS32, machine: elf.EM_MIPS, data: elf.ELFDATA2MSB, flags: mipsABI2, needles: []string{"/lib/mips64-linux-gnuabin32"}, forbidden: "/lib/mips-linux-gnu"},
		{name: "mips32r6el", class: elf.ELFCLASS32, machine: elf.EM_MIPS, data: elf.ELFDATA2LSB, flags: mipsArch32R6, needles: []string{"/lib/mipsisa32r6el-linux-gnu"}, forbidden: "/lib/mipsel-linux-gnu"},
		{name: "mips64r6", class: elf.ELFCLASS64, machine: elf.EM_MIPS, data: elf.ELFDATA2MSB, flags: mipsArch64R6, needles: []string{"/lib/mipsisa64r6-linux-gnuabi64"}, forbidden: "/lib/mips64-linux-gnuabi64"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dirs := standardLibDirs(tc.class, tc.machine, tc.data, tc.flags)
			for _, needle := range tc.needles {
				if !containsString(dirs, needle) {
					t.Fatalf("missing %s in %v", needle, dirs)
				}
			}
			if tc.forbidden != "" && containsString(dirs, tc.forbidden) {
				t.Fatalf("included incompatible directory %s in %v", tc.forbidden, dirs)
			}
			if !containsString(dirs, "/lib") {
				t.Fatalf("expected /lib fallback in %v", dirs)
			}
		})
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestNormalizeRpathsOriginBraceAndEmpty(t *testing.T) {
	origin := "/opt/app"
	got := normalizeRpaths([]string{"", "${ORIGIN}/lib", "$ORIGIN/../lib"}, origin)
	want := []string{"/opt/app/lib", "/opt/app/../lib"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %s want %s", i, got[i], want[i])
		}
	}
}

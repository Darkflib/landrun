package elfdeps

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// standardLibDirs returns library directories for the supported Intel and ARM
// ELF ABIs. Other architectures fail closed instead of guessing at ABI-specific
// paths that this resolver cannot validate.
func standardLibDirs(class elf.Class, machine elf.Machine, data elf.Data, flags uint32) ([]string, error) {
	var dirs []string
	switch {
	case machine == elf.EM_X86_64 && class == elf.ELFCLASS64 && data == elf.ELFDATA2LSB:
		dirs = []string{
			"/lib64", "/usr/lib64",
			"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		}
	case machine == elf.EM_X86_64 && class == elf.ELFCLASS32 && data == elf.ELFDATA2LSB: // x32
		dirs = append(multiarchLibDirs("x86_64-linux-gnux32"), "/libx32", "/usr/libx32")
	case machine == elf.EM_386 && class == elf.ELFCLASS32 && data == elf.ELFDATA2LSB:
		dirs = []string{
			"/lib32", "/usr/lib32",
			"/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu",
		}
	case machine == elf.EM_AARCH64 && class == elf.ELFCLASS64:
		tuple := "aarch64-linux-gnu"
		if data == elf.ELFDATA2MSB {
			tuple = "aarch64_be-linux-gnu"
		}
		dirs = append(multiarchLibDirs(tuple), "/lib64", "/usr/lib64")
	case machine == elf.EM_ARM && class == elf.ELFCLASS32:
		if data == elf.ELFDATA2MSB {
			dirs = multiarchLibDirs("armeb-linux-gnu")
		} else if flags&armFloatHard != 0 && flags&armFloatSoft == 0 {
			dirs = multiarchLibDirs("arm-linux-gnueabihf")
		} else if flags&armFloatSoft != 0 && flags&armFloatHard == 0 {
			dirs = multiarchLibDirs("arm-linux-gnueabi")
		} else {
			return nil, fmt.Errorf("unsupported or ambiguous ARM floating-point ABI flags %#x", flags)
		}
	default:
		return nil, fmt.Errorf("unsupported ELF ABI: class=%s machine=%s data=%s", class, machine, data)
	}
	return append(dirs, "/lib", "/usr/lib", "/usr/local/lib"), nil
}

const (
	armFloatSoft = 0x00000200
	armFloatHard = 0x00000400
)

func multiarchLibDirs(tuples ...string) []string {
	dirs := make([]string, 0, len(tuples)*2)
	for _, tuple := range tuples {
		dirs = append(dirs, filepath.Join("/lib", tuple), filepath.Join("/usr/lib", tuple))
	}
	return dirs
}

func readELFFlags(r io.ReaderAt, f *elf.File) (uint32, error) {
	offset := int64(36)
	if f.Class == elf.ELFCLASS64 {
		offset = 48
	}

	raw := make([]byte, 4)
	if _, err := r.ReadAt(raw, offset); err != nil {
		return 0, err
	}
	return f.ByteOrder.Uint32(raw), nil
}

// parseInterp extracts the PT_INTERP interpreter path from an ELF file.
func parseInterp(f *elf.File) string {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			r := prog.Open()
			if r == nil {
				// Can't read interpreter
				return ""
			}
			if data, err := io.ReadAll(r); err == nil {
				return strings.TrimRight(string(data), "\x00")
			}
		}
	}
	return ""
}

// parseDynamic extracts DT_NEEDED and RPATH/RUNPATH entries from the .dynamic section.
func parseDynamic(f *elf.File) (needed []string, rpaths []string) {
	needed = []string{}
	rpaths = []string{}

	if libs, err := f.DynString(elf.DT_NEEDED); err == nil {
		needed = append(needed, libs...)
	}

	// DT_RPATH and DT_RUNPATH may both be present; split on ':' and append
	if rp, err := f.DynString(elf.DT_RPATH); err == nil {
		for _, v := range rp {
			if v == "" {
				continue
			}
			rpaths = append(rpaths, strings.Split(v, ":")...)
		}
	}
	if rp, err := f.DynString(elf.DT_RUNPATH); err == nil {
		for _, v := range rp {
			if v == "" {
				continue
			}
			rpaths = append(rpaths, strings.Split(v, ":")...)
		}
	}
	return
}

// normalizeRpaths expands common tokens like $ORIGIN and makes relative
// rpath entries absolute using the provided origin directory.
func normalizeRpaths(rpaths []string, origin string) []string {
	out := []string{}
	for _, rp := range rpaths {
		if rp == "" {
			continue
		}
		// expand $ORIGIN (common token in RPATH/RUNPATH)
		rp = strings.ReplaceAll(rp, "$ORIGIN", origin)
		rp = strings.ReplaceAll(rp, "${ORIGIN}", origin)
		// make relative rpath entries absolute using origin
		if !filepath.IsAbs(rp) {
			rp = filepath.Join(origin, rp)
		}
		out = append(out, rp)
	}
	return out
}

// resolveSingleSoname attempts to resolve a single soname using rpaths and
// architecture-specific standard library directories. It deliberately does
// not invoke ldconfig: dependency discovery happens before Landlock is applied
// and must never execute code selected through the ambient environment.
func resolveSingleSoname(soname string, rpaths []string, stdDirs []string) string {
	// check rpaths first
	for _, rp := range rpaths {
		candidate := filepath.Join(rp, soname)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// then check standard dirs
	for _, d := range stdDirs {
		candidate := filepath.Join(d, soname)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return ""
}

// resolveSonames attempts to resolve sonames to absolute paths using rpaths,
// then architecture-specific standard library directories. Unresolved names
// are returned separately so callers can fail closed.
func resolveSonames(needed []string, rpaths []string, class elf.Class, machine elf.Machine, data elf.Data, flags uint32) ([]string, []string, error) {
	seen := map[string]struct{}{}
	stdDirs, err := standardLibDirs(class, machine, data, flags)
	if err != nil {
		return nil, nil, err
	}
	resolved := make([]string, 0, len(needed))
	unresolved := make([]string, 0)

	for _, soname := range needed {
		if _, ok := seen[soname]; ok {
			continue
		}
		seen[soname] = struct{}{}
		if path := resolveSingleSoname(soname, rpaths, stdDirs); path != "" {
			resolved = append(resolved, path)
		} else {
			unresolved = append(unresolved, soname)
		}
	}
	return resolved, unresolved, nil
}

// GetLibraryDependencies returns a list of library paths that the given binary depends on
func GetLibraryDependencies(binary string) ([]string, error) {
	queue := []string{binary}
	processed := map[string]struct{}{}
	finalMap := map[string]struct{}{}

	// Add /etc/ld.so.cache if present
	if _, err := os.Stat("/etc/ld.so.cache"); err == nil {
		finalMap["/etc/ld.so.cache"] = struct{}{}
	}

	for len(queue) > 0 {
		// Dequeue
		curr := queue[0]
		queue = queue[1:]

		if _, ok := processed[curr]; ok {
			continue
		}
		processed[curr] = struct{}{}

		file, err := os.Open(curr)
		if err != nil {
			// This can happen with non-ELF files in the dependency chain
			// (e.g. ld.so.cache). Ignore them.
			continue
		}
		f, err := elf.NewFile(file)
		if err != nil {
			_ = file.Close()
			continue
		}

		// The first binary in the queue is the main one; grab its interpreter
		if curr == binary {
			if interpPath := parseInterp(f); interpPath != "" {
				finalMap[interpPath] = struct{}{}
				queue = append(queue, interpPath)
			}
		}

		needed, rpaths := parseDynamic(f)
		flags, err := readELFFlags(file, f)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("read ELF flags from %s: %w", curr, err)
		}
		origin := filepath.Dir(curr)
		rpaths = normalizeRpaths(rpaths, origin)
		libPaths, unresolved, err := resolveSonames(needed, rpaths, f.Class, f.Machine, f.Data, flags)
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", curr, err)
		}
		if len(unresolved) > 0 {
			return nil, fmt.Errorf("%s: unable to resolve shared libraries: %s", curr, strings.Join(unresolved, ", "))
		}

		for _, p := range libPaths {
			if _, ok := finalMap[p]; !ok {
				finalMap[p] = struct{}{}
				queue = append(queue, p)
			}
		}
	}

	out := make([]string, 0, len(finalMap))
	for p := range finalMap {
		out = append(out, p)
	}
	sort.Strings(out)

	return out, nil
}

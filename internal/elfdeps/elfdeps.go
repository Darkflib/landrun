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

// standardLibDirs returns library directories to search for the given ELF ABI,
// including Debian/Ubuntu multiarch paths. Endianness matters for architectures
// such as MIPS and PowerPC, where incompatible ABIs share an ELF machine value.
func standardLibDirs(class elf.Class, machine elf.Machine, data elf.Data, flags uint32) []string {
	var dirs []string
	switch {
	case machine == elf.EM_X86_64 && class == elf.ELFCLASS64:
		dirs = []string{
			"/lib64", "/usr/lib64",
			"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		}
	case machine == elf.EM_X86_64 && class == elf.ELFCLASS32: // x32
		dirs = append(multiarchLibDirs("x86_64-linux-gnux32"), "/libx32", "/usr/libx32")
	case machine == elf.EM_386:
		dirs = []string{
			"/lib32", "/usr/lib32",
			"/lib/i386-linux-gnu", "/usr/lib/i386-linux-gnu",
		}
	case machine == elf.EM_AARCH64:
		tuple := "aarch64-linux-gnu"
		if data == elf.ELFDATA2MSB {
			tuple = "aarch64_be-linux-gnu"
		}
		dirs = append(multiarchLibDirs(tuple), "/lib64", "/usr/lib64")
	case machine == elf.EM_ARM:
		if data == elf.ELFDATA2MSB {
			dirs = multiarchLibDirs("armeb-linux-gnu")
		} else {
			dirs = multiarchLibDirs("arm-linux-gnueabihf", "arm-linux-gnueabi")
		}
	case machine == elf.EM_RISCV:
		if class == elf.ELFCLASS64 {
			dirs = append(multiarchLibDirs("riscv64-linux-gnu"), "/lib64", "/usr/lib64")
		} else {
			dirs = append(multiarchLibDirs("riscv32-linux-gnu"), "/lib32", "/usr/lib32")
		}
	case machine == elf.EM_PPC64:
		tuple := "powerpc64-linux-gnu"
		if data == elf.ELFDATA2LSB {
			tuple = "powerpc64le-linux-gnu"
		}
		dirs = append(multiarchLibDirs(tuple), "/lib64", "/usr/lib64")
	case machine == elf.EM_PPC:
		if data == elf.ELFDATA2LSB {
			dirs = multiarchLibDirs("powerpcle-linux-gnu")
		} else if flags&ppcEmbedded != 0 {
			dirs = multiarchLibDirs("powerpc-linux-gnuspe")
		} else {
			dirs = multiarchLibDirs("powerpc-linux-gnu")
		}
	case machine == elf.EM_S390:
		if class == elf.ELFCLASS64 {
			dirs = append(multiarchLibDirs("s390x-linux-gnu"), "/lib64", "/usr/lib64")
		} else {
			dirs = append(multiarchLibDirs("s390-linux-gnu"), "/lib32", "/usr/lib32")
		}
	case machine == elf.EM_IA_64:
		dirs = append(multiarchLibDirs("ia64-linux-gnu"), "/lib64", "/usr/lib64")
	case machine == elf.EM_SPARCV9:
		dirs = append(multiarchLibDirs("sparc64-linux-gnu"), "/lib64", "/usr/lib64")
	case machine == elf.EM_SPARC:
		dirs = append(multiarchLibDirs("sparc-linux-gnu"), "/lib32", "/usr/lib32")
	case machine == elf.EM_MIPS:
		dirs = multiarchLibDirs(mipsMultiarchTuple(class, data, flags))
		if class == elf.ELFCLASS64 {
			dirs = append(dirs, "/lib64", "/usr/lib64")
		} else {
			dirs = append(dirs, "/lib32", "/usr/lib32")
		}
	}
	return append(dirs, "/lib", "/usr/lib", "/usr/local/lib")
}

const (
	ppcEmbedded = 0x80000000

	mipsABI2     = 0x00000020
	mipsArchMask = 0xf0000000
	mipsArch32R6 = 0x90000000
	mipsArch64R6 = 0xa0000000
)

func mipsMultiarchTuple(class elf.Class, data elf.Data, flags uint32) string {
	littleEndian := data == elf.ELFDATA2LSB
	r6 := flags&mipsArchMask == mipsArch32R6 || flags&mipsArchMask == mipsArch64R6

	if class == elf.ELFCLASS64 {
		if r6 && littleEndian {
			return "mipsisa64r6el-linux-gnuabi64"
		}
		if r6 {
			return "mipsisa64r6-linux-gnuabi64"
		}
		if littleEndian {
			return "mips64el-linux-gnuabi64"
		}
		return "mips64-linux-gnuabi64"
	}

	if flags&mipsABI2 != 0 {
		if r6 && littleEndian {
			return "mipsisa64r6el-linux-gnuabin32"
		}
		if r6 {
			return "mipsisa64r6-linux-gnuabin32"
		}
		if littleEndian {
			return "mips64el-linux-gnuabin32"
		}
		return "mips64-linux-gnuabin32"
	}

	if r6 && littleEndian {
		return "mipsisa32r6el-linux-gnu"
	}
	if r6 {
		return "mipsisa32r6-linux-gnu"
	}
	if littleEndian {
		return "mipsel-linux-gnu"
	}
	return "mips-linux-gnu"
}

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
func resolveSonames(needed []string, rpaths []string, class elf.Class, machine elf.Machine, data elf.Data, flags uint32) ([]string, []string) {
	seen := map[string]struct{}{}
	stdDirs := standardLibDirs(class, machine, data, flags)
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
	return resolved, unresolved
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
		libPaths, unresolved := resolveSonames(needed, rpaths, f.Class, f.Machine, f.Data, flags)
		_ = file.Close()
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

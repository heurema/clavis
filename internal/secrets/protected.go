package secrets

import (
	"os"
	"slices"
	"syscall"
)

// ProtectedFile reports whether an opened regular file is safe to read as a
// secret: nothing granted to others, nothing but read granted to the group,
// and, when group-read is set, a group the process belongs to. A Kubernetes
// Secret volume mounted under fsGroup produces exactly that group-read case,
// so a wrapper that copies secrets into owner-only files is unnecessary.
// Callers pass the stat of the descriptor they already opened, never a
// pre-open stat of the path.
func ProtectedFile(info os.FileInfo) bool {
	mode := info.Mode().Perm()
	if mode&0o037 != 0 {
		return false
	}
	if mode&0o040 == 0 {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	gid := int(stat.Gid)
	if gid == os.Getegid() {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	return slices.Contains(groups, gid)
}

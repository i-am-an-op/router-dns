package control

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func (m *Manager) Protected(v Manifest) error {
	b, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		return e
	}
	mounted := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 5 {
			mounted[f[4]] = strings.Contains(","+f[5]+",", ",ro,")
		}
	}
	for _, x := range v.Mounts {
		if !mounted[x.Target] {
			return errors.New("read-only bind absent")
		}
		a, e := os.Stat(filepath.Join(m.gen(v.ID), x.Source))
		if e != nil {
			return e
		}
		b, e := os.Stat(x.Target)
		if e != nil || !os.SameFile(a, b) {
			return errors.New("protected path was replaced")
		}
		if b.Mode().Perm()&0022 != 0 {
			return errors.New("writable protected path")
		}
	}
	return nil
}
func (m *Manager) Mount(v Manifest) error {
	for _, x := range v.Mounts {
		source := filepath.Join(m.gen(v.ID), x.Source)
		// Refuse symlink target traversal even for a missing-core recovery.
		parent := filepath.Dir(x.Target)
		resolved, e := filepath.EvalSymlinks(parent)
		if e != nil || resolved != parent {
			return errors.New("mount parent must exist without aliases")
		}
		if s, e := os.Lstat(x.Target); os.IsNotExist(e) {
			f, e := os.OpenFile(x.Target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return e
			}
			f.Close()
			if e = SyncDir(parent); e != nil {
				return e
			}
		} else if e != nil || !s.Mode().IsRegular() {
			return errors.New("nonregular mount target")
		}
		a, e := os.Stat(source)
		if e != nil {
			return e
		}
		b, e := os.Stat(x.Target)
		if e != nil {
			return e
		}
		if !os.SameFile(a, b) {
			if e = syscall.Mount(source, x.Target, "", syscall.MS_BIND, ""); e != nil {
				return e
			}
		}
		if e = syscall.Mount("", x.Target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); e != nil {
			return e
		}
	}
	return m.Protected(v)
}
func (m *Manager) Unmount(v Manifest) error {
	for i := len(v.Mounts) - 1; i >= 0; i-- {
		e := syscall.Unmount(v.Mounts[i].Target, 0)
		if e != nil && e != syscall.EINVAL && e != syscall.ENOENT {
			return e
		}
	}
	return nil
}
func (m *Manager) Runtime(op string) error {
	v, e := m.Active()
	if e != nil {
		return e
	}
	switch op {
	case "mount":
		return m.Mount(v)
	case "unmount":
		return m.Unmount(v)
	case "protected":
		return m.Protected(v)
	case "probe":
		for _, p := range v.Readiness {
			if e = DNSProbe(p); e != nil {
				return e
			}
		}
		return nil
	case "manifest":
		return json.NewEncoder(os.Stdout).Encode(v)
	default:
		return errors.New("unknown runtime operation")
	}
}
func SecureStore(store, key string) error {
	for _, p := range []string{store, key} {
		s, e := os.Lstat(p)
		if e != nil {
			return e
		}
		t, ok := s.Sys().(*syscall.Stat_t)
		if !ok || t.Uid != 0 || s.Mode().Perm()&0022 != 0 || s.Mode()&os.ModeSymlink != 0 {
			return errors.New("store/key ownership or mode unsafe")
		}
	}
	return nil
}

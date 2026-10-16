package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PackagePlan requires a reviewed complete write set from an offline APK solve
// and extraction, including its database/world and removed paths. Hooks remain
// disabled. It is not a general-purpose wrapper around arbitrary apk commands.
// Router package acceptance must verify that actual writes match this set.
type PackagePlan struct {
	Schema   int      `json:"schema"`
	ID       string   `json:"id"`
	Before   []Pin    `json:"before"`
	After    []Pin    `json:"after"`
	Files    []File   `json:"files"`
	WriteSet []string `json:"write_set"`
	Adapter  string   `json:"adapter"`
}
type Backup struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Mode    uint32 `json:"mode"`
	SHA256  string `json:"sha256"`
}
type PackageJournal struct {
	ID      string   `json:"id"`
	Phase   string   `json:"phase"`
	Entries []Backup `json:"entries"`
}

func (m *Manager) packagePlan(dir string) (PackagePlan, error) {
	var p PackagePlan
	b, e := os.ReadFile(filepath.Join(dir, "package.json"))
	if e != nil {
		return p, e
	}
	sig, e := os.ReadFile(filepath.Join(dir, "package.sig"))
	if e != nil {
		return p, e
	}
	s, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if e != nil || !ed25519.Verify(m.Key, b, s) {
		return p, errors.New("package review signature invalid")
	}
	if e = Decode(b, &p); e != nil {
		return p, e
	}
	if p.Schema != 1 || !identifier.MatchString(p.ID) || len(p.Before) == 0 || len(p.After) == 0 || len(p.WriteSet) == 0 {
		return p, errors.New("incomplete package plan")
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if !relative(f.Path) || seen[f.Path] || f.Mode&0022 != 0 {
			return p, errors.New("unsafe package file")
		}
		seen[f.Path] = true
		if e = noLinks(dir, f.Path); e != nil {
			return p, e
		}
		b, e := os.ReadFile(filepath.Join(dir, f.Path))
		if e != nil || Hash(b) != f.SHA256 {
			return p, errors.New("package payload identity differs")
		}
	}
	if !seen[p.Adapter] {
		return p, errors.New("unverified package adapter")
	}
	for _, path := range p.WriteSet {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return p, errors.New("unsafe package write set")
		}
	}
	return p, nil
}
func (m *Manager) pins(pins []Pin) error {
	for _, p := range pins {
		if !filepath.IsAbs(p.Path) || !digest.MatchString(p.SHA256) {
			return errors.New("invalid package pin")
		}
		b, e := os.ReadFile(filepath.Join(m.HostRoot, p.Path))
		if e != nil || Hash(b) != p.SHA256 {
			return errors.New("package state differs")
		}
	}
	return nil
}
func (m *Manager) PackageApply(dir string) error {
	return m.locked(func() error {
		if _, e := os.Stat(filepath.Join(m.Store, "package-journal.json")); !os.IsNotExist(e) {
			return errors.New("recover package transaction first")
		}
		p, e := m.packagePlan(dir)
		if e != nil {
			return e
		}
		if e = m.pins(p.Before); e != nil {
			return e
		}
		backup := filepath.Join(m.Store, "package-backups", p.ID)
		if e = os.MkdirAll(backup, 0700); e != nil {
			return e
		}
		j := PackageJournal{ID: p.ID, Phase: "prepared"}
		seen := map[string]bool{}
		for _, path := range p.WriteSet {
			if seen[path] {
				return errors.New("duplicate package path")
			}
			seen[path] = true
			entry := Backup{Path: path}
			src := filepath.Join(m.HostRoot, path)
			s, e := os.Lstat(src)
			if e == nil {
				if !s.Mode().IsRegular() {
					return errors.New("package write set must enumerate regular files; symlink/dir migrations need separate review")
				}
				b, e := os.ReadFile(src)
				if e != nil {
					return e
				}
				entry.Present = true
				entry.Mode = uint32(s.Mode().Perm())
				entry.SHA256 = Hash(b)
				if e = Atomic(filepath.Join(backup, strings.TrimPrefix(path, "/")), b, 0600); e != nil {
					return e
				}
			} else if !os.IsNotExist(e) {
				return e
			}
			j.Entries = append(j.Entries, entry)
		}
		for _, pin := range append(p.Before, p.After...) {
			if !seen[pin.Path] {
				return errors.New("package DB pin outside rollback write set")
			}
		}
		if e = SyncTree(backup); e != nil {
			return e
		}
		if e = put(filepath.Join(m.Store, "package-journal.json"), j); e != nil {
			return e
		}
		if m.Fault != nil {
			if e = m.Fault("package-prepared"); e != nil {
				return e
			}
		}
		// An adapter must unmount only plugin paths after checking a running protected
		// frontend, run APK with scripts and commit hooks disabled, then check its DB.
		v := Manifest{ID: p.ID, Adapter: p.Adapter}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		e = m.Runner.Run(ctx, dir, v, m.Store, "package-apply")
		if e == nil {
			e = m.pins(p.After)
		}
		if e != nil {
			if r := m.packageRecover(); r != nil {
				return r
			}
			return errors.New("package operation rejected; filesystem/database restored")
		}
		j.Phase = "applied-awaiting-integration"
		if e = put(filepath.Join(m.Store, "package-journal.json"), j); e != nil {
			return e
		}
		// Keep the backup and journal until a compatible generation passes promotion.
		return nil
	})
}
func (m *Manager) PackageCommit() error {
	return m.locked(func() error {
		var j PackageJournal
		if e := ReadJSON(filepath.Join(m.Store, "package-journal.json"), &j); e != nil {
			return e
		}
		if j.Phase != "applied-awaiting-integration" {
			return errors.New("package not applied")
		}
		if e := m.Check(); e != nil {
			return e
		}
		if e := os.Remove(filepath.Join(m.Store, "package-journal.json")); e != nil {
			return e
		}
		return SyncDir(m.Store)
	})
}
func (m *Manager) PackageRecover() error { return m.locked(m.packageRecover) }
func (m *Manager) packageRecover() error {
	var j PackageJournal
	e := ReadJSON(filepath.Join(m.Store, "package-journal.json"), &j)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !identifier.MatchString(j.ID) {
		return errors.New("invalid package recovery record")
	}
	// Validate ALL rollback bytes before restoring any file.
	root := filepath.Join(m.Store, "package-backups", j.ID)
	for _, x := range j.Entries {
		if !filepath.IsAbs(x.Path) || filepath.Clean(x.Path) != x.Path {
			return errors.New("invalid backup path")
		}
		if x.Present {
			b, e := os.ReadFile(filepath.Join(root, x.Path))
			if e != nil || Hash(b) != x.SHA256 {
				return errors.New("rollback backup corrupt")
			}
		}
	}
	for _, x := range j.Entries {
		target := filepath.Join(m.HostRoot, x.Path)
		if x.Present {
			b, _ := os.ReadFile(filepath.Join(root, x.Path))
			if e = Atomic(target, b, os.FileMode(x.Mode)); e != nil {
				return e
			}
		} else {
			if e = os.Remove(target); e != nil && !os.IsNotExist(e) {
				return e
			}
			if e = SyncDir(filepath.Dir(target)); e != nil {
				return e
			}
		}
	}
	if e = os.Remove(filepath.Join(m.Store, "package-journal.json")); e != nil {
		return e
	}
	return SyncDir(m.Store)
}
func MarshalPackage(p PackagePlan) []byte { b, _ := json.Marshal(p); return b }

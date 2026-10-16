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
	"syscall"
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
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	SHA256  string `json:"sha256"`
}
type PackageJournal struct {
	ID             string   `json:"id"`
	Phase          string   `json:"phase"`
	Entries        []Backup `json:"entries"`
	Before         []Pin    `json:"before"`
	After          []Pin    `json:"after"`
	Generation     string   `json:"generation"`
	NextGeneration string   `json:"next_generation"`
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
	seen := map[string]bool{"package.json": true, "package.sig": true}
	for _, f := range p.Files {
		if !relative(f.Path) || seen[f.Path] || f.Mode&0022 != 0 || f.Mode&^0755 != 0 || !digest.MatchString(f.SHA256) {
			return p, errors.New("unsafe package file")
		}
		seen[f.Path] = true
		if e = noLinks(dir, f.Path); e != nil {
			return p, e
		}
		info, e := regular(filepath.Join(dir, f.Path))
		if e != nil || uint32(info.Mode().Perm()) != f.Mode {
			return p, errors.New("package payload mode differs")
		}
		b, e := os.ReadFile(filepath.Join(dir, f.Path))
		if e != nil || Hash(b) != f.SHA256 {
			return p, errors.New("package payload identity differs")
		}
	}
	if e = filepath.WalkDir(dir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if !seen[rel] {
			return errors.New("unmanifested package payload")
		}
		return nil
	}); e != nil {
		return p, e
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
		if e = os.MkdirAll(filepath.Dir(backup), 0700); e != nil {
			return e
		}
		if e = os.Mkdir(backup, 0700); e != nil {
			return errors.New("package transaction ID already used")
		}

		state, e := m.State()
		if e != nil {
			return e
		}
		j := PackageJournal{ID: p.ID, Phase: "prepared", Before: p.Before, After: p.After, Generation: state.Current}
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
				owner := s.Sys().(*syscall.Stat_t)
				entry.UID = int(owner.Uid)
				entry.GID = int(owner.Gid)
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
		if state.Current != "" {
			old, err := m.verify(m.gen(state.Current), true)
			if err != nil {
				return err
			}
			for _, op := range []string{"preflight", "protect", "stop", "unmount"} {
				if err = m.run(old, op); err != nil {
					return err
				}
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
		if state.Current != "" {
			old, err := m.verify(m.gen(state.Current), true)
			if err != nil {
				return err
			}
			if err = m.active(state.Current); err != nil {
				return err
			}
			if err = m.run(old, "mount"); err != nil {
				return err
			}
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
		if e := m.pins(j.After); e != nil {
			return e
		}
		state, e := m.State()
		if e != nil {
			return e
		}
		if state.Current == j.Generation {
			return errors.New("new compatible generation not promoted")
		}
		if e := m.Check(); e != nil {
			return e
		}
		j.NextGeneration = state.Current
		j.Phase = "committed"
		if e := put(filepath.Join(m.Store, "package-history", j.ID+".json"), j); e != nil {
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
	// Protected files may still be bound to the pre-upgrade integration. Use
	// only its signature-verified offline adapter to quiesce/unmount before restoring.
	if j.Generation != "" {
		old, err := m.verify(m.gen(j.Generation), false)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		if err = m.active(old.ID); err != nil {
			return err
		}
		for _, op := range []string{"stop", "unmount"} {
			if err = m.Runner.Run(ctx, m.gen(old.ID), old, m.Store, op); err != nil {
				return err
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
			st, e := os.Stat(target)
			if e != nil {
				return e
			}
			owner := st.Sys().(*syscall.Stat_t)
			if int(owner.Uid) != x.UID || int(owner.Gid) != x.GID {
				if e = os.Chown(target, x.UID, x.GID); e != nil {
					return e
				}
				f, e := os.Open(target)
				if e != nil {
					return e
				}
				e = f.Sync()
				f.Close()
				if e != nil {
					return e
				}
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
	if j.Generation != "" {
		old, err := m.verify(m.gen(j.Generation), true)
		if err != nil {
			return err
		}
		if err = m.active(old.ID); err != nil {
			return err
		}
		for _, op := range []string{"preflight", "protect", "mount", "start"} {
			if err = m.run(old, op); err != nil {
				return err
			}
		}
		if err = m.probation(old); err != nil {
			return err
		}
		if err = put(filepath.Join(m.Store, "state.json"), State{Current: old.ID}); err != nil {
			return err
		}
		var promotion Journal
		e := ReadJSON(filepath.Join(m.Store, "journal.json"), &promotion)
		if e == nil {
			if promotion.Old != old.ID {
				return errors.New("unrelated generation transaction pending")
			}
			if err = m.finish(); err != nil {
				return err
			}
		} else if !os.IsNotExist(e) {
			return e
		}

	}
	if e = os.Remove(filepath.Join(m.Store, "package-journal.json")); e != nil {
		return e
	}
	return SyncDir(m.Store)
}
func MarshalPackage(p PackagePlan) []byte { b, _ := json.Marshal(p); return b }

// A package bridge is limited to the exact before/after pins from the previously
// signature-verified package transaction. It cannot authorize an arbitrary upgrade.
func (m *Manager) packageBridge(pin Pin, actual string) bool {
	var j PackageJournal
	if ReadJSON(filepath.Join(m.Store, "package-journal.json"), &j) != nil || j.Phase != "applied-awaiting-integration" {
		return false
	}
	before, after := false, false
	for _, p := range j.Before {
		if p == pin {
			before = true
		}
	}
	for _, p := range j.After {
		if p.Path == pin.Path && p.SHA256 == actual {
			after = true
		}
	}
	return before && after
}

func (m *Manager) packageRollbackTo(target, current string) error {
	entries, e := os.ReadDir(filepath.Join(m.Store, "package-history"))
	if e != nil {
		return errors.New("no package rollback history")
	}
	for _, entry := range entries {
		var j PackageJournal
		if !entry.Type().IsRegular() {
			continue
		}
		if ReadJSON(filepath.Join(m.Store, "package-history", entry.Name()), &j) != nil {
			continue
		}
		if j.Generation != target || j.NextGeneration != current || j.Phase != "committed" {
			continue
		}
		if e = m.pins(j.After); e != nil {
			return e
		}
		if _, e = m.verify(m.gen(target), false); e != nil {
			return e
		}
		j.Phase = "applied-awaiting-integration"
		if e = put(filepath.Join(m.Store, "package-journal.json"), j); e != nil {
			return e
		}
		return m.packageRecover()
	}
	return errors.New("no matching accepted package rollback")
}

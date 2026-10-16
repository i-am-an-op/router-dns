// Package control implements an offline generation store and recoverable promotion.
// It never downloads a core or silently substitutes an unaccepted generation.
package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type Pin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
}
type Probe struct {
	Address    string `json:"address"`
	Network    string `json:"network"`
	Name       string `json:"name"`
	Type       uint16 `json:"type"`
	Rcode      int    `json:"rcode"`
	AD         bool   `json:"ad"`
	MinAnswers int    `json:"min_answers"`
}
type Manifest struct {
	Schema       int     `json:"schema"`
	ID           string  `json:"id"`
	Architecture string  `json:"architecture"`
	OpenClash    string  `json:"openclash"`
	Mode         string  `json:"mode"`
	Transport    string  `json:"transport"`
	Files        []File  `json:"files"`
	HostPins     []Pin   `json:"host_pins"`
	Mounts       []Mount `json:"mounts"`
	Core         string  `json:"core"`
	Profile      string  `json:"profile"`
	Adapter      string  `json:"adapter"`
	DNSHash      string  `json:"dns_hash"`
	RoutingHash  string  `json:"routing_hash"`
	Readiness    []Probe `json:"readiness"`
	ProbeSeconds int     `json:"probe_seconds"`
	// Signed bindings are populated by the off-router provenance verifier, not inferred from version strings.
	Provenance map[string]string `json:"provenance"`
}
type State struct {
	Current  string `json:"current"`
	Previous string `json:"previous"`
}
type Journal struct {
	Old   string `json:"old"`
	New   string `json:"new"`
	Phase string `json:"phase"`
}
type Manager struct {
	Store        string
	Key          ed25519.PublicKey
	HostRoot     string
	Architecture string
	Runner       Runner
	Fault        func(string) error
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ErrInterrupted = errors.New("transaction interrupted")

func Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func ReadJSON(path string, value any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return Decode(b, value)
}
func Decode(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("invalid structured record")
	}
	var x any
	if e := d.Decode(&x); e != io.EOF {
		return errors.New("trailing structured data")
	}
	return nil
}
func relative(p string) bool {
	return p != "" && p != "." && !filepath.IsAbs(p) && filepath.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.ContainsAny(p, "\n\r\t")
}
func regular(path string) (os.FileInfo, error) {
	s, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() {
		return nil, errors.New("nonregular file refused")
	}
	return s, nil
}
func noLinks(root, path string) error {
	if !relative(path) {
		return errors.New("unsafe relative path")
	}
	cur := root
	for _, p := range strings.Split(path, "/") {
		cur = filepath.Join(cur, p)
		s, e := os.Lstat(cur)
		if e != nil {
			return e
		}
		if s.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink refused")
		}
	}
	return nil
}
func SyncTree(root string) error {
	var dirs []string
	if e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	}); e != nil {
		return e
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if e := SyncDir(dirs[i]); e != nil {
			return e
		}
	}
	return nil
}
func SyncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func Atomic(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".pending-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return SyncDir(filepath.Dir(path))
}
func put(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return Atomic(path, append(b, '\n'), 0600)
}
func (m *Manager) init() error {
	if !filepath.IsAbs(m.Store) {
		return errors.New("store must be absolute")
	}
	if m.HostRoot == "" {
		m.HostRoot = "/"
	}
	if m.Architecture == "" {
		m.Architecture = runtime.GOARCH
	}
	return os.MkdirAll(filepath.Join(m.Store, "generations"), 0700)
}
func (m *Manager) locked(f func() error) error {
	if e := m.init(); e != nil {
		return e
	}
	p := filepath.Join(m.Store, "lock")
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("another transaction holds the lock")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return f()
}
func (m *Manager) gen(id string) string { return filepath.Join(m.Store, "generations", id) }
func (m *Manager) verify(dir string, host bool) (Manifest, error) {
	var v Manifest
	b, e := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if e != nil {
		return v, e
	}
	sig, e := os.ReadFile(filepath.Join(dir, "review.sig"))
	if e != nil {
		return v, e
	}
	s, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if e != nil || len(m.Key) != ed25519.PublicKeySize || !ed25519.Verify(m.Key, b, s) {
		return v, errors.New("review signature invalid")
	}
	if e = Decode(b, &v); e != nil {
		return v, e
	}
	if v.Schema != 1 || !identifier.MatchString(v.ID) || v.Architecture != m.Architecture || (v.Mode != "native" && v.Mode != "compose") || (v.Transport != "separate" && v.Transport != "shared") || v.ProbeSeconds < 1 || v.ProbeSeconds > 120 {
		return v, errors.New("incompatible manifest")
	}
	if !digest.MatchString(v.DNSHash) || !digest.MatchString(v.RoutingHash) || len(v.HostPins) == 0 || len(v.Readiness) == 0 || v.OpenClash == "" {
		return v, errors.New("incomplete policy")
	}
	seen := map[string]bool{"manifest.json": true, "review.sig": true}
	for _, f := range v.Files {
		if seen[f.Path] || !relative(f.Path) || !digest.MatchString(f.SHA256) || f.Mode&^0755 != 0 || f.Mode&0022 != 0 {
			return v, errors.New("invalid file policy")
		}
		seen[f.Path] = true
		if e = noLinks(dir, f.Path); e != nil {
			return v, e
		}
		p := filepath.Join(dir, f.Path)
		s, e := regular(p)
		if e != nil {
			return v, e
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return v, e
		}
		if Hash(data) != f.SHA256 || uint32(s.Mode().Perm()) != f.Mode {
			return v, fmt.Errorf("file identity differs: %s", f.Path)
		}
	}
	if !seen[v.Core] || !seen[v.Profile] || !seen[v.Adapter] {
		return v, errors.New("missing runtime payload")
	}
	if e = filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		r, _ := filepath.Rel(dir, p)
		if !seen[r] {
			return errors.New("unmanifested payload")
		}
		return nil
	}); e != nil {
		return v, e
	}
	core, e := os.ReadFile(filepath.Join(dir, v.Core))
	if e != nil {
		return v, e
	}
	arch := uint16(62)
	if v.Architecture == "arm64" {
		arch = 183
	} else if v.Architecture != "amd64" {
		return v, errors.New("unsupported architecture")
	}
	if len(core) < 64 || string(core[:6]) != "\x7fELF\x02\x01" || uint16(core[18])|uint16(core[19])<<8 != arch {
		return v, errors.New("wrong ELF machine")
	}
	if len(v.Provenance) < 2 || !digest.MatchString(v.Provenance["core_bundle_sha256"]) || !digest.MatchString(v.Provenance["verification_receipt_sha256"]) {
		return v, errors.New("missing reviewed provenance bindings")
	}
	for _, p := range v.HostPins {
		if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || !digest.MatchString(p.SHA256) {
			return v, errors.New("invalid compatibility pin")
		}
		if host {
			b, e := os.ReadFile(filepath.Join(m.HostRoot, p.Path))
			if e != nil || Hash(b) != p.SHA256 {
				return v, errors.New("installed compatibility pin differs")
			}
		}
	}
	targets := map[string]bool{}
	for _, x := range v.Mounts {
		if !seen[x.Source] || !filepath.IsAbs(x.Target) || filepath.Clean(x.Target) != x.Target || targets[x.Target] || strings.ContainsAny(x.Target, "\n\r\t ") {
			return v, errors.New("invalid protected mount")
		}
		targets[x.Target] = true
	}
	if e = CheckProfile(filepath.Join(dir, v.Profile), v.DNSHash, v.RoutingHash); e != nil {
		return v, e
	}
	return v, nil
}
func (m *Manager) Stage(src string) error {
	return m.locked(func() error {
		v, e := m.verify(src, true)
		if e != nil {
			return e
		}
		dest := m.gen(v.ID)
		if _, e = os.Lstat(dest); !os.IsNotExist(e) {
			return errors.New("generation already exists")
		}
		tmp, e := os.MkdirTemp(filepath.Join(m.Store, "generations"), ".stage-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(tmp)
		for _, f := range append(v.Files, File{Path: "manifest.json", Mode: 0600}, File{Path: "review.sig", Mode: 0600}) {
			b, e := os.ReadFile(filepath.Join(src, f.Path))
			if e != nil {
				return e
			}
			if e = Atomic(filepath.Join(tmp, f.Path), b, os.FileMode(f.Mode)); e != nil {
				return e
			}
		}
		if _, e = m.verify(tmp, true); e != nil {
			return e
		}
		if e = SyncTree(tmp); e != nil {
			return e
		}
		if e = os.Rename(tmp, dest); e != nil {
			return e
		}
		return SyncDir(filepath.Dir(dest))
	})
}
func (m *Manager) State() (State, error) {
	var s State
	e := ReadJSON(filepath.Join(m.Store, "state.json"), &s)
	if os.IsNotExist(e) {
		return s, nil
	}
	if e == nil && ((s.Current != "" && !identifier.MatchString(s.Current)) || (s.Previous != "" && !identifier.MatchString(s.Previous))) {
		e = errors.New("invalid state")
	}
	return s, e
}

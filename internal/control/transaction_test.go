package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type recorder struct {
	calls []string
	fail  string
}

func (r *recorder) Run(_ context.Context, _ string, v Manifest, store, op string) error {
	r.calls = append(r.calls, v.ID+":"+op)
	if r.fail == v.ID+":"+op {
		return errors.New("injected failure")
	}
	return Atomic(filepath.Join(store, "executed"), []byte(strings.Join(r.calls, "\n")), 0600)
}
func setup(t *testing.T) (*Manager, ed25519.PrivateKey, *recorder) {
	t.Helper()
	root := t.TempDir()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	host := filepath.Join(root, "host")
	os.MkdirAll(host, 0700)
	os.WriteFile(filepath.Join(host, "package-db"), []byte("installed 0.48.002"), 0600)
	r := &recorder{}
	m := &Manager{Store: filepath.Join(root, "store"), HostRoot: host, Key: pub, Architecture: "amd64", Runner: r}
	return m, key, r
}
func generation(t *testing.T, m *Manager, key ed25519.PrivateKey, id string) string {
	t.Helper()
	d := t.TempDir()
	elf := make([]byte, 64)
	copy(elf, "\x7fELF\x02\x01")
	elf[18] = 62
	files := map[string][]byte{"bin/core": elf, "config/profile.yaml": []byte("mode: rule\nrules: [MATCH,DIRECT]\nipv6: true\ndns: {enable: true, disable-cache: true}\n"), "runtime/adapter": []byte("fixture adapter, not a router script")}
	v := Manifest{Schema: 1, ID: id, Architecture: "amd64", OpenClash: "0.48.002", Mode: "native", Transport: "separate", Core: "bin/core", Profile: "config/profile.yaml", Adapter: "runtime/adapter", ProbeSeconds: 1, HostPins: []Pin{{Path: "/package-db", SHA256: Hash([]byte("installed 0.48.002"))}}, Readiness: []Probe{{Address: "127.0.0.1:6053", Network: "tcp", Name: "example.org", Type: 1}}, Provenance: map[string]string{"core_bundle_sha256": strings.Repeat("a", 64), "verification_receipt_sha256": strings.Repeat("b", 64)}}
	for p, b := range files {
		if e := Atomic(filepath.Join(d, p), b, 0600); e != nil {
			t.Fatal(e)
		}
		v.Files = append(v.Files, File{Path: p, SHA256: Hash(b), Mode: 0600})
	}
	p, e := Profile(filepath.Join(d, v.Profile))
	if e != nil {
		t.Fatal(e)
	}
	v.DNSHash, v.RoutingHash, e = Fingerprints(p)
	if e != nil {
		t.Fatal(e)
	}
	sign(t, d, v, key)
	return d
}
func sign(t *testing.T, d string, v Manifest, key ed25519.PrivateKey) {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(d, "manifest.json"), b, 0600)
	os.WriteFile(filepath.Join(d, "review.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, b))), 0600)
}
func accept(t *testing.T, m *Manager, k ed25519.PrivateKey, id string) {
	t.Helper()
	if e := m.Stage(generation(t, m, k, id)); e != nil {
		t.Fatal(e)
	}
	if e := m.Promote(id); e != nil {
		t.Fatal(e)
	}
}
func TestWholeGenerationRollback(t *testing.T) {
	m, k, r := setup(t)
	accept(t, m, k, "one")
	accept(t, m, k, "two")
	if e := m.Rollback(); e != nil {
		t.Fatal(e)
	}
	s, _ := m.State()
	if s.Current != "one" || s.Previous != "two" {
		t.Fatal(s)
	}
	if !strings.Contains(strings.Join(r.calls, ","), "two:stop,two:unmount,one:mount,one:start") {
		t.Fatal(r.calls)
	}
}
func TestRejectBeforeStopping(t *testing.T) {
	for _, kind := range []string{"corrupt", "wrong-architecture", "unknown-field", "bad-signature", "extra-file", "symlink", "wrong-package", "unsafe-mode", "routing-change", "missing-provenance"} {
		t.Run(kind, func(t *testing.T) {
			m, k, r := setup(t)
			accept(t, m, k, "one")
			before := len(r.calls)
			d := generation(t, m, k, "two")
			var v Manifest
			ReadJSON(filepath.Join(d, "manifest.json"), &v)
			switch kind {
			case "corrupt":
				os.WriteFile(filepath.Join(d, "bin/core"), []byte("broken"), 0600)
			case "wrong-architecture":
				v.Architecture = "arm64"
				sign(t, d, v, k)
			case "unknown-field":
				b, _ := os.ReadFile(filepath.Join(d, "manifest.json"))
				b = append(b[:len(b)-1], []byte(",\"typo\":true}")...)
				os.WriteFile(filepath.Join(d, "manifest.json"), b, 0600)
				os.WriteFile(filepath.Join(d, "review.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(k, b))), 0600)
			case "bad-signature":
				os.WriteFile(filepath.Join(d, "review.sig"), []byte("invalid"), 0600)
			case "extra-file":
				os.WriteFile(filepath.Join(d, "surprise"), []byte("x"), 0600)
			case "symlink":
				os.Rename(filepath.Join(d, "bin"), filepath.Join(d, "alternate"))
				os.Symlink("alternate", filepath.Join(d, "bin"))
			case "wrong-package":
				os.WriteFile(filepath.Join(m.HostRoot, "package-db"), []byte("unexpected upgrade"), 0600)
			case "unsafe-mode":
				os.Chmod(filepath.Join(d, "bin/core"), 0777)
			case "routing-change":
				v.RoutingHash = strings.Repeat("c", 64)
				sign(t, d, v, k)
			case "missing-provenance":
				v.Provenance = nil
				sign(t, d, v, k)
			}
			if e := m.Stage(d); e == nil {
				t.Fatal("accepted invalid candidate")
			}
			if len(r.calls) != before {
				t.Fatal("ran live operations before verification")
			}
			s, _ := m.State()
			if s.Current != "one" {
				t.Fatal(s)
			}
		})
	}
}
func TestReadinessFailureRestoresGeneration(t *testing.T) {
	m, k, r := setup(t)
	accept(t, m, k, "one")
	m.Stage(generation(t, m, k, "two"))
	r.fail = "two:health"
	if e := m.Promote("two"); e == nil {
		t.Fatal("readiness failure accepted")
	}
	s, _ := m.State()
	if s.Current != "one" {
		t.Fatal(s)
	}
	if _, e := os.Stat(filepath.Join(m.Store, "journal.json")); !os.IsNotExist(e) {
		t.Fatal("recovery journal not resolved")
	}
}
func TestMissingExposedCoreOfflineBoot(t *testing.T) {
	m, k, r := setup(t)
	accept(t, m, k, "one")
	r.calls = nil
	if e := m.Boot(); e != nil {
		t.Fatal(e)
	}
	if strings.Join(r.calls, ",") != "one:preflight,one:protect,one:mount,one:start,one:health" {
		t.Fatal(r.calls)
	}
}
func TestInterruptedEveryPhase(t *testing.T) {
	for _, phase := range []string{"prepared", "protected", "quiesced", "switched", "started", "probation", "committed"} {
		t.Run(phase, func(t *testing.T) {
			m, k, _ := setup(t)
			accept(t, m, k, "one")
			m.Stage(generation(t, m, k, "two"))
			m.Fault = func(p string) error {
				if p == phase {
					return ErrInterrupted
				}
				return nil
			}
			if e := m.Promote("two"); !errors.Is(e, ErrInterrupted) {
				t.Fatal(e)
			}
			m.Fault = nil
			if e := m.Recover(); e != nil {
				t.Fatal(e)
			}
			s, _ := m.State()
			want := "one"
			if phase == "committed" {
				want = "two"
			}
			if s.Current != want {
				t.Fatal(s)
			}
			if e := m.Boot(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestAbruptProcessExit(t *testing.T) {
	m, k, _ := setup(t)
	accept(t, m, k, "one")
	m.Stage(generation(t, m, k, "two"))
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
	cmd.Env = append(os.Environ(), "DNS_CRASH_STORE="+m.Store, "DNS_CRASH_HOST="+m.HostRoot, "DNS_CRASH_KEY="+base64.StdEncoding.EncodeToString(m.Key))
	if e := cmd.Run(); e == nil {
		t.Fatal("child did not stop")
	}
	var j Journal
	if e := ReadJSON(filepath.Join(m.Store, "journal.json"), &j); e != nil || j.Phase != "switched" {
		t.Fatal(j, e)
	}
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
	s, _ := m.State()
	if s.Current != "one" {
		t.Fatal(s)
	}
}
func TestCrashHelper(t *testing.T) {
	s := os.Getenv("DNS_CRASH_STORE")
	if s == "" {
		t.Skip("subprocess only")
	}
	k, _ := base64.StdEncoding.DecodeString(os.Getenv("DNS_CRASH_KEY"))
	m := &Manager{Store: s, HostRoot: os.Getenv("DNS_CRASH_HOST"), Key: k, Architecture: "amd64", Runner: &recorder{}, Fault: func(p string) error {
		if p == "switched" {
			os.Exit(91)
		}
		return nil
	}}
	if e := m.Promote("two"); e != nil {
		t.Fatal(e)
	}
}
func TestRecoveryFailureRetainsJournal(t *testing.T) {
	m, k, r := setup(t)
	accept(t, m, k, "one")
	m.Stage(generation(t, m, k, "two"))
	m.Fault = func(p string) error {
		if p == "started" {
			return ErrInterrupted
		}
		return nil
	}
	m.Promote("two")
	m.Fault = nil
	r.fail = "one:start"
	if e := m.Recover(); e == nil {
		t.Fatal("failed recovery reported success")
	}
	if _, e := os.Stat(filepath.Join(m.Store, "journal.json")); e != nil {
		t.Fatal("lost recovery intent")
	}
	r.fail = ""
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
}
func TestProfileStagingPreservesDNSReportsRouting(t *testing.T) {
	m, k, _ := setup(t)
	d := generation(t, m, k, "one")
	p := filepath.Join(d, "subscription.yaml")
	os.WriteFile(p, []byte("mode: global\nrules: [MATCH,REJECT]\ndns: {enable: false}\n"), 0600)
	out := filepath.Join(t.TempDir(), "candidate.yaml")
	r, e := StageProfile(filepath.Join(d, "config/profile.yaml"), p, out)
	if e != nil {
		t.Fatal(e)
	}
	if r["routing_hash"] == r["previous_routing_hash"] {
		t.Fatal("hidden application routing change")
	}
	if e = CheckProfile(out, r["dns_hash"], r["routing_hash"]); e != nil {
		t.Fatal(e)
	}
	if _, e = StageProfile(p, p, out); e == nil {
		t.Fatal("overwrote candidate")
	}
}
func TestBootCorruptCurrentUsesVerifiedPrevious(t *testing.T) {
	m, k, _ := setup(t)
	accept(t, m, k, "one")
	accept(t, m, k, "two")
	os.WriteFile(filepath.Join(m.gen("two"), "bin/core"), []byte("corrupt"), 0600)
	if e := m.Boot(); e != nil {
		t.Fatal(e)
	}
	s, _ := m.State()
	if s.Current != "one" {
		t.Fatal(s)
	}
}
func TestBootBothGenerationsCorruptRefusesStock(t *testing.T) {
	m, k, r := setup(t)
	accept(t, m, k, "one")
	accept(t, m, k, "two")
	for _, id := range []string{"one", "two"} {
		os.WriteFile(filepath.Join(m.gen(id), "bin/core"), []byte("corrupt"), 0600)
	}
	n := len(r.calls)
	if e := m.Boot(); e == nil {
		t.Fatal("boot accepted corruption")
	}
	if len(r.calls) != n {
		t.Fatal("executed unverified operation")
	}
}
func TestPackageInterruptionAndCorruptBackup(t *testing.T) {
	m, k, _ := setup(t)
	m.init()
	dir := t.TempDir()
	b := []byte("fixture package adapter")
	Atomic(filepath.Join(dir, "adapter"), b, 0700)
	p := PackagePlan{Schema: 1, ID: "fixture-upgrade", Before: []Pin{{Path: "/package-db", SHA256: Hash([]byte("installed 0.48.002"))}}, After: []Pin{{Path: "/package-db", SHA256: Hash([]byte("new package"))}}, WriteSet: []string{"/package-db", "/new-file"}, Adapter: "adapter", Files: []File{{Path: "adapter", SHA256: Hash(b), Mode: 0700}}}
	data := MarshalPackage(p)
	os.WriteFile(filepath.Join(dir, "package.json"), data, 0600)
	os.WriteFile(filepath.Join(dir, "package.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(k, data))), 0600)
	m.Fault = func(s string) error {
		if s == "package-prepared" {
			return ErrInterrupted
		}
		return nil
	}
	if e := m.PackageApply(dir); !errors.Is(e, ErrInterrupted) {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(m.HostRoot, "package-db"), []byte("partially upgraded"), 0600)
	os.WriteFile(filepath.Join(m.HostRoot, "new-file"), []byte("new"), 0600)
	m.Fault = nil
	if e := m.PackageRecover(); e != nil {
		t.Fatal(e)
	}
	x, _ := os.ReadFile(filepath.Join(m.HostRoot, "package-db"))
	if string(x) != "installed 0.48.002" {
		t.Fatal("database not restored")
	}
	if _, e := os.Stat(filepath.Join(m.HostRoot, "new-file")); !os.IsNotExist(e) {
		t.Fatal("new file retained")
	}
}
func TestPackageBridgeIsExactAndTemporary(t *testing.T) {
	m, k, _ := setup(t)
	accept(t, m, k, "one")
	before := Pin{Path: "/package-db", SHA256: Hash([]byte("installed 0.48.002"))}
	after := Pin{Path: "/package-db", SHA256: Hash([]byte("updated"))}
	os.WriteFile(filepath.Join(m.HostRoot, "package-db"), []byte("updated"), 0600)
	if _, e := m.verify(m.gen("one"), true); e == nil {
		t.Fatal("unauthorized package accepted")
	}
	put(filepath.Join(m.Store, "package-journal.json"), PackageJournal{ID: "reviewed", Phase: "applied-awaiting-integration", Before: []Pin{before}, After: []Pin{after}})
	if _, e := m.verify(m.gen("one"), true); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(m.HostRoot, "package-db"), []byte("other update"), 0600)
	if _, e := m.verify(m.gen("one"), true); e == nil {
		t.Fatal("bridge accepted unrelated change")
	}
}

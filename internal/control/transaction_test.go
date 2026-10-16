package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
	m := &Manager{Store: filepath.Join(root, "store"), HostRoot: host, Key: pub, Architecture: runtime.GOARCH, Runner: r}
	return m, key, r
}
func generation(t *testing.T, m *Manager, key ed25519.PrivateKey, id string) string {
	t.Helper()
	d := t.TempDir()
	elf := make([]byte, 64)
	copy(elf, "\x7fELF\x02\x01")
	elf[18] = 62
	if m.Architecture == "arm64" {
		elf[18] = 183
	}
	files := map[string][]byte{"bin/core": elf, "config/profile.yaml": []byte("mode: rule\nrules: [MATCH,DIRECT]\nipv6: true\ndns: {enable: true, disable-cache: true}\n"), "runtime/adapter": []byte("fixture adapter, not a router script")}
	v := Manifest{Schema: 1, ID: id, Architecture: runtime.GOARCH, OpenClash: "0.48.002", Mode: "native", Transport: "separate", Core: "bin/core", Profile: "config/profile.yaml", Adapter: "runtime/adapter", ProbeSeconds: 1, HostPins: []Pin{{Path: "/package-db", SHA256: Hash([]byte("installed 0.48.002"))}}, Readiness: []Probe{{Address: "127.0.0.1:6053", Network: "tcp", Name: "example.org", Type: 1}}, Provenance: map[string]string{"core_bundle_sha256": strings.Repeat("a", 64), "verification_receipt_sha256": strings.Repeat("b", 64)}}
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
				if m.Architecture == "arm64" {
					v.Architecture = "amd64"
				}
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
	m := &Manager{Store: s, HostRoot: os.Getenv("DNS_CRASH_HOST"), Key: k, Architecture: runtime.GOARCH, Runner: &recorder{}, Fault: func(p string) error {
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
func TestKernelReadOnlyMountAndMissingTarget(t *testing.T) {
	if os.Getenv("DNS_KERNEL_TEST") != "1" {
		t.Skip("requires explicitly isolated workstation mount namespace")
	}
	mapping, _ := os.ReadFile("/proc/self/uid_map")
	if !strings.Contains(string(mapping), "1000") {
		t.Fatal("refuse real host root")
	}
	m, k, _ := setup(t)
	d := generation(t, m, k, "mounted")
	var v Manifest
	ReadJSON(filepath.Join(d, "manifest.json"), &v)
	target := filepath.Join(t.TempDir(), "exposed-core")
	v.Mounts = []Mount{{Source: "bin/core", Target: target}}
	sign(t, d, v, k)
	if e := m.Stage(d); e != nil {
		t.Fatal(e)
	}
	defer m.Unmount(v)
	if e := m.Mount(v); e != nil {
		t.Fatal(e)
	}
	if e := m.Protected(v); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(target, []byte("stock replacement"), 0600); e == nil {
		t.Fatal("read-only target overwritten")
	}
	replacement := filepath.Join(filepath.Dir(target), "replacement")
	os.WriteFile(replacement, []byte("stock"), 0600)
	if e := os.Rename(replacement, target); e == nil {
		t.Fatal("mount replaced by rename")
	}
	if e := m.Unmount(v); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(target)
	if e != nil || len(b) != 0 {
		t.Fatal("underlying recovery placeholder changed")
	}
}

func packageFixture(t *testing.T, m *Manager, k ed25519.PrivateKey) string {
	t.Helper()
	d := t.TempDir()
	b := []byte("fixture package adapter")
	Atomic(filepath.Join(d, "adapter"), b, 0700)
	p := PackagePlan{Schema: 1, ID: "package-one", Before: []Pin{{Path: "/package-db", SHA256: Hash([]byte("installed 0.48.002"))}}, After: []Pin{{Path: "/package-db", SHA256: Hash([]byte("updated"))}}, WriteSet: []string{"/package-db", "/new-file"}, Adapter: "adapter", Files: []File{{Path: "adapter", SHA256: Hash(b), Mode: 0700}}}
	b = MarshalPackage(p)
	Atomic(filepath.Join(d, "package.json"), b, 0600)
	Atomic(filepath.Join(d, "package.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(k, b))), 0600)
	return d
}

type packageRunner struct {
	recorder
	host string
}

func (r *packageRunner) Run(ctx context.Context, dir string, v Manifest, store, op string) error {
	if op == "package-apply" {
		if e := Atomic(filepath.Join(r.host, "package-db"), []byte("updated"), 0600); e != nil {
			return e
		}
		if e := Atomic(filepath.Join(r.host, "new-file"), []byte("new"), 0644); e != nil {
			return e
		}
	}
	return r.recorder.Run(ctx, dir, v, store, op)
}
func TestPackagePromotionCommitAndWholeRollback(t *testing.T) {
	m, k, _ := setup(t)
	m.Runner = &packageRunner{host: m.HostRoot}
	accept(t, m, k, "one")
	if e := m.PackageApply(packageFixture(t, m, k)); e != nil {
		t.Fatal(e)
	}
	if e := m.PackageCommit(); e == nil {
		t.Fatal("committed without compatible generation")
	}
	d := generation(t, m, k, "two")
	var v Manifest
	ReadJSON(filepath.Join(d, "manifest.json"), &v)
	v.HostPins[0].SHA256 = Hash([]byte("updated"))
	sign(t, d, v, k)
	if e := m.Stage(d); e != nil {
		t.Fatal(e)
	}
	if e := m.Promote("two"); e != nil {
		t.Fatal(e)
	}
	if e := m.PackageCommit(); e != nil {
		t.Fatal(e)
	}
	if e := m.Rollback(); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(m.HostRoot, "package-db"))
	s, _ := m.State()
	if string(b) != "installed 0.48.002" || s.Current != "one" {
		t.Fatal("whole package rollback failed", s)
	}
	if _, e := os.Stat(filepath.Join(m.HostRoot, "new-file")); !os.IsNotExist(e) {
		t.Fatal("package residue")
	}
}
func TestCorruptPackageBackupChangesNothing(t *testing.T) {
	m, k, _ := setup(t)
	m.init()
	m.Fault = func(p string) error { return ErrInterrupted }
	if e := m.PackageApply(packageFixture(t, m, k)); !errors.Is(e, ErrInterrupted) {
		t.Fatal(e)
	}
	m.Fault = nil
	Atomic(filepath.Join(m.HostRoot, "package-db"), []byte("partly installed"), 0600)
	Atomic(filepath.Join(m.Store, "package-backups/package-one/package-db"), []byte("corrupt"), 0600)
	if e := m.PackageRecover(); e == nil {
		t.Fatal("corrupt backup accepted")
	}
	b, _ := os.ReadFile(filepath.Join(m.HostRoot, "package-db"))
	if string(b) != "partly installed" {
		t.Fatal("modified before validating all backups")
	}
	if _, e := os.Stat(filepath.Join(m.Store, "package-journal.json")); e != nil {
		t.Fatal("lost recovery record")
	}
}
func TestRecoveryUsesVerifiedOldWhenCandidateCorrupt(t *testing.T) {
	m, k, _ := setup(t)
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
	Atomic(filepath.Join(m.gen("two"), "bin/core"), []byte("corrupt"), 0600)
	if e := m.Recover(); e != nil {
		t.Fatal(e)
	}
	s, _ := m.State()
	if s.Current != "one" {
		t.Fatal(s)
	}
}
func TestConcurrentTransactionRefused(t *testing.T) {
	m, _, _ := setup(t)
	e := m.locked(func() error {
		if e := m.locked(func() error { t.Fatal("entered second transaction"); return nil }); e == nil {
			t.Fatal("second lock succeeded")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
func TestFreshManagerRuntimeInitialization(t *testing.T) {
	m, k, _ := setup(t)
	accept(t, m, k, "one")
	m.Architecture = ""
	if _, e := m.Active(); e != nil {
		t.Fatal(e)
	}
}
func TestReadinessGlobalDeadline(t *testing.T) {
	listener, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	if e := WaitProbes(ctx, []Probe{{Address: listener.LocalAddr().String(), Network: "udp", Name: "example.org", Type: 1}}); e == nil {
		t.Fatal("blackhole accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("global readiness deadline exceeded")
	}
}

func TestAdapterTimeoutKillsChildren(t *testing.T) {
	d := t.TempDir()
	adapter := filepath.Join(d, "hook")
	sentinel := filepath.Join(d, "escaped")
	script := "#!/bin/sh\n(sleep 0.4; touch '" + sentinel + "') &\nwait\n"
	if e := Atomic(adapter, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if e := (ExecRunner{}).Run(ctx, d, Manifest{Adapter: "hook"}, d, "test"); e == nil {
		t.Fatal("timeout not enforced")
	}
	time.Sleep(450 * time.Millisecond)
	if _, e := os.Stat(sentinel); !os.IsNotExist(e) {
		t.Fatal("hook child survived cancellation")
	}
}

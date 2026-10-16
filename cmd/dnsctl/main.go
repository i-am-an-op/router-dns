package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/i-am-an-op/router-dns/internal/control"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "development"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "dnsctl:", e)
		os.Exit(78)
	}
}
func run() error {
	store := flag.String("store", "/opt/dns-core", "offline generation store")
	key := flag.String("key", "/etc/dns-core/review.pub", "review public key")
	local := flag.Bool("offline", false, "verification and staging only; no runtime operations")
	flag.Parse()
	a := flag.Args()
	if len(a) == 0 {
		return errors.New("operation required")
	}
	if a[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if a[0] == "probe" && len(a) == 2 {
		var probes []control.Probe
		if e := control.ReadJSON(a[1], &probes); e != nil {
			return e
		}
		if len(probes) == 0 {
			return errors.New("empty readiness set")
		}
		for _, p := range probes {
			if e := control.DNSProbe(p); e != nil {
				return e
			}
		}
		return nil
	}
	if a[0] == "profile-stage" && len(a) == 4 {
		r, e := control.StageProfile(a[1], a[2], a[3])
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r)
	}
	if a[0] == "profile-hash" && len(a) == 2 {
		v, e := control.Profile(a[1])
		if e != nil {
			return e
		}
		d, r, e := control.Fingerprints(v)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"dns_hash": d, "routing_hash": r})
	}
	b, e := os.ReadFile(*key)
	if e != nil {
		return errors.New("review key unavailable")
	}
	k, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if e != nil || len(k) != ed25519.PublicKeySize {
		return errors.New("invalid review key")
	}
	m := &control.Manager{Store: *store, Key: k, Runner: control.ExecRunner{}}
	if !*local {
		if os.Geteuid() != 0 {
			return errors.New("runtime operations require root")
		}
		if e = control.SecureStore(*store, *key); e != nil {
			return e
		}
	}
	if a[0] == "stage" && len(a) == 2 {
		return m.Stage(a[1])
	}
	if a[0] == "status" {
		s, e := m.State()
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(s)
	}
	if *local {
		return errors.New("runtime operations forbidden in offline mode")
	}
	switch a[0] {
	case "package-apply":
		if len(a) != 2 {
			return errors.New("signed package plan required")
		}
		return m.PackageApply(a[1])
	case "package-commit":
		return m.PackageCommit()
	case "package-recover":
		return m.PackageRecover()
	case "promote":
		if len(a) != 2 {
			return errors.New("generation required")
		}
		return m.Promote(a[1])
	case "recover":
		return m.Recover()
	case "rollback":
		return m.Rollback()
	case "boot":
		if e = m.PackageRecover(); e != nil {
			return e
		}
		return m.Boot()
	case "check":
		return m.Check()
	case "watch":
		failures, repairs := 0, 0
		for {
			err := m.Check()
			if err == nil {
				failures = 0
				repairs = 0
			} else {
				failures++
			}
			// Repair DNS only after three consecutive failures, at most three
			// times before operator intervention. Never repair identity drift.
			if failures >= 3 && repairs < 3 {
				v, identity := m.Active()
				if identity == nil {
					identity = m.Protected(v)
				}
				if identity == nil {
					ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
					_ = (control.ExecRunner{}).Run(ctx, filepath.Join(*store, "generations", v.ID), v, *store, "repair-dns")
					cancel()
					repairs++
					failures = 0
				}
			}
			record := map[string]any{"utc": time.Now().UTC(), "healthy": err == nil, "bounded_repairs": repairs}
			if err != nil {
				record["reason"] = "integrity or readiness failure; inspect locally before promotion"
			}
			data, _ := json.Marshal(record)
			if e = control.Atomic(filepath.Join(*store, "health.json"), data, 0600); e != nil {
				return e
			}
			time.Sleep(15 * time.Second)
		}
	case "protect":
		v, e := m.Active()
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return (control.ExecRunner{}).Run(ctx, filepath.Join(*store, "generations", v.ID), v, *store, "protect")
	case "repair-dns":
		v, e := m.Active()
		if e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		return (control.ExecRunner{}).Run(ctx, filepath.Join(*store, "generations", v.ID), v, *store, "repair-dns")
	case "runtime":
		if len(a) != 2 {
			return errors.New("runtime operation required")
		}
		return m.Runtime(a[1])
	case "guard":
		if len(a) < 2 {
			return errors.New("guard operation required")
		}
		v, e := m.Active()
		if e != nil {
			return e
		}
		if a[1] == "path" {
			fmt.Println(filepath.Join(*store, "generations", v.ID, v.Profile))
			return nil
		}
		if e = m.Protected(v); e != nil {
			return e
		}
		switch a[1] {
		case "preflight":
			return nil
		case "config":
			if len(a) != 3 {
				return errors.New("profile required")
			}
			return control.CheckProfile(a[2], v.DNSHash, v.RoutingHash)
		case "exec":
			if os.Getenv("MIHOMO_MANAGED_DNS") != "1" || len(a) != 6 || a[2] != "-d" || a[3] != "/etc/openclash" || a[4] != "-f" {
				return errors.New("unexpected frontend launch")
			}
			if e = control.CheckProfile(a[5], v.DNSHash, v.RoutingHash); e != nil {
				return e
			}
			core := "/etc/openclash/core/clash_meta"
			s, e := os.Stat(core)
			if e != nil {
				return e
			}
			alias, e := os.Stat("/etc/openclash/clash")
			if e != nil || !os.SameFile(s, alias) {
				return errors.New("core alias differs")
			}
			return syscall.Exec(core, append([]string{"/etc/openclash/clash"}, a[2:]...), os.Environ())
		}
		return errors.New("unknown guard operation")
	default:
		return errors.New("unknown operation")
	}
}

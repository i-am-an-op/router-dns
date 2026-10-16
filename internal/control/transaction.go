package control

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type Runner interface {
	Run(context.Context, string, Manifest, string, string) error
}
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, dir string, v Manifest, store, operation string) error {
	cmd := exec.CommandContext(ctx, filepath.Join(dir, v.Adapter), operation)
	// Cancel the entire hook process group, including an APK child, before recovery.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DNS_GENERATION=" + dir, "DNS_STORE=" + store, "DNS_MODE=" + v.Mode, "DNS_TRANSPORT=" + v.Transport, "MIHOMO_MANAGED_DNS=1", "SAFE_PATHS=/usr/share/openclash:/etc/ssl", "SKIP_SYSTEM_IPV6_CHECK=1"}
	// Hooks may handle private subscriptions. Never echo their output to logs.
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("runtime operation %s failed", operation)
	}
	return nil
}
func (m *Manager) run(v Manifest, op string) error {
	return m.runContext(context.Background(), v, op)
}
func (m *Manager) runContext(parent context.Context, v Manifest, op string) error {
	if m.Runner == nil {
		return errors.New("runtime adapter not configured")
	}
	if _, e := m.verify(m.gen(v.ID), true); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(parent, 150*time.Second)
	defer cancel()
	return m.Runner.Run(ctx, m.gen(v.ID), v, m.Store, op)
}
func (m *Manager) phase(j Journal, p string) error {
	j.Phase = p
	if e := put(filepath.Join(m.Store, "journal.json"), j); e != nil {
		return e
	}
	if m.Fault != nil {
		return m.Fault(p)
	}
	return nil
}
func (m *Manager) active(id string) error {
	return put(filepath.Join(m.Store, "active.json"), State{Current: id})
}
func (m *Manager) finish() error {
	p := filepath.Join(m.Store, "journal.json")
	if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
		return e
	}
	return SyncDir(m.Store)
}
func (m *Manager) probation(v Manifest) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(v.ProbeSeconds)*time.Second)
	defer cancel()
	for {
		if e := m.runContext(ctx, v, "health"); e == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("readiness deadline exceeded")
		case <-time.After(time.Second):
		}
	}
}
func (m *Manager) Promote(id string) error {
	return m.locked(func() error {
		if !identifier.MatchString(id) {
			return errors.New("invalid generation")
		}
		if _, e := os.Stat(filepath.Join(m.Store, "journal.json")); !os.IsNotExist(e) {
			return errors.New("recover interrupted transaction first")
		}
		s, e := m.State()
		if e != nil {
			return e
		}
		if id == s.Current {
			return errors.New("already active")
		}
		v, e := m.verify(m.gen(id), true)
		if e != nil {
			return e
		}
		if s.Current != "" {
			old, e := m.verify(m.gen(s.Current), true)
			if e != nil {
				return e
			}
			a := map[string]bool{}
			for _, x := range old.Mounts {
				a[x.Target] = true
			}
			if len(a) != len(v.Mounts) {
				return errors.New("mount topology changed; separate integration migration required")
			}
			for _, x := range v.Mounts {
				if !a[x.Target] {
					return errors.New("mount topology changed")
				}
			}
		}
		// Executable capability and complete configuration checks precede any stop.
		if e = m.run(v, "preflight"); e != nil {
			return e
		}
		j := Journal{Old: s.Current, New: id}
		if e = m.phase(j, "prepared"); e != nil {
			return e
		}
		forward := func() error {
			if e = m.run(v, "protect"); e != nil {
				return e
			}
			if e = m.phase(j, "protected"); e != nil {
				return e
			}
			if s.Current != "" {
				old, e := m.verify(m.gen(s.Current), true)
				if e != nil {
					return e
				}
				if e = m.run(old, "stop"); e != nil {
					return e
				}
				if e = m.run(old, "unmount"); e != nil {
					return e
				}
			}
			if e = m.phase(j, "quiesced"); e != nil {
				return e
			}
			if e = m.active(id); e != nil {
				return e
			}
			if e = m.run(v, "mount"); e != nil {
				return e
			}
			if e = m.phase(j, "switched"); e != nil {
				return e
			}
			if e = m.run(v, "start"); e != nil {
				return e
			}
			if e = m.phase(j, "started"); e != nil {
				return e
			}
			if e = m.probation(v); e != nil {
				return e
			}
			if e = m.phase(j, "probation"); e != nil {
				return e
			}
			if e = put(filepath.Join(m.Store, "state.json"), State{Current: id, Previous: s.Current}); e != nil {
				return e
			}
			if e = m.phase(j, "committed"); e != nil {
				return e
			}
			return m.finish()
		}
		if e = forward(); e != nil {
			if errors.Is(e, ErrInterrupted) {
				return e
			}
			if r := m.restore(j); r != nil {
				return fmt.Errorf("promotion failed; recovery remains pending: %w", r)
			}
			return fmt.Errorf("candidate rejected and previous generation restored: %w", e)
		}
		return nil
	})
}
func (m *Manager) restore(j Journal) error {
	// Persist recovery intent before any reverse action. All reverse operations are
	// idempotent; another power loss repeats them. Never erase the journal on error.
	if e := m.phase(j, "recovering"); e != nil {
		return e
	}
	next, e := m.verify(m.gen(j.New), true)
	if e != nil {
		if j.Old == "" {
			return errors.New("candidate integrity lost; no verified recovery generation")
		}
		next, e = m.verify(m.gen(j.Old), true)
		if e != nil {
			return errors.New("both recovery generations invalid")
		}
		// Mount targets are required to match across generations. A verified old
		// adapter can stop the fixed service/project and unmount those targets
		// without executing corrupted candidate code.
		if e = m.active(j.Old); e != nil {
			return e
		}
	}
	if e = m.run(next, "protect"); e != nil {
		return e
	}
	if e = m.run(next, "stop"); e != nil {
		return e
	}
	if e = m.run(next, "unmount"); e != nil {
		return e
	}
	if j.Old == "" {
		if e = m.active(""); e != nil {
			return e
		}
		return m.finish()
	}
	old, e := m.verify(m.gen(j.Old), true)
	if e != nil {
		return e
	}
	for _, op := range []string{"preflight", "protect"} {
		if e = m.run(old, op); e != nil {
			return e
		}
	}
	if e = m.active(j.Old); e != nil {
		return e
	}
	for _, op := range []string{"mount", "start"} {
		if e = m.run(old, op); e != nil {
			return e
		}
	}
	if e = m.probation(old); e != nil {
		return e
	}
	s, e := m.State()
	if e != nil {
		return e
	}
	previous := s.Previous
	if previous == j.Old || previous == j.New {
		previous = ""
	}
	if e = put(filepath.Join(m.Store, "state.json"), State{Current: j.Old, Previous: previous}); e != nil {
		return e
	}
	return m.finish()
}
func (m *Manager) Recover() error { return m.locked(m.recover) }
func (m *Manager) recover() error {
	var j Journal
	e := ReadJSON(filepath.Join(m.Store, "journal.json"), &j)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !identifier.MatchString(j.New) || (j.Old != "" && !identifier.MatchString(j.Old)) {
		return errors.New("invalid journal")
	}
	s, e := m.State()
	if e != nil {
		return e
	}
	// State publication is the commit point, including a crash just before the
	// final journal update. Boot will still verify, remount and recheck readiness.
	if s.Current == j.New && j.Phase != "recovering" {
		return m.finish()
	}
	return m.restore(j)
}
func (m *Manager) Rollback() error {
	s, e := m.State()
	if e != nil {
		return e
	}
	if s.Previous == "" {
		return errors.New("no accepted previous generation")
	}
	if _, e = m.verify(m.gen(s.Previous), true); e != nil {
		return m.locked(func() error { return m.packageRollbackTo(s.Previous, s.Current) })
	}
	return m.Promote(s.Previous)
}
func (m *Manager) Boot() error {
	return m.locked(func() error {
		if e := m.recover(); e != nil {
			return e
		}
		s, e := m.State()
		if e != nil {
			return e
		}
		if s.Current == "" {
			return errors.New("no accepted offline generation")
		}
		v, e := m.verify(m.gen(s.Current), true)
		if e != nil {
			if s.Previous == "" {
				return errors.New("accepted payload or installed package incompatible; no verified fallback")
			}
			old, err := m.verify(m.gen(s.Previous), true)
			if err != nil {
				if recovery := m.packageRollbackTo(s.Previous, s.Current); recovery == nil {
					return nil
				}
				return errors.New("both offline generations incompatible; refuse stock recovery")
			}
			if err = m.run(old, "preflight"); err != nil {
				return err
			}
			if err = m.run(old, "protect"); err != nil {
				return err
			}
			if err = m.active(old.ID); err != nil {
				return err
			}
			for _, op := range []string{"stop", "unmount", "mount", "start"} {
				if err = m.run(old, op); err != nil {
					return err
				}
			}
			if err = m.probation(old); err != nil {
				return err
			}
			return put(filepath.Join(m.Store, "state.json"), State{Current: old.ID})
		}
		for _, op := range []string{"preflight", "protect"} {
			if e = m.run(v, op); e != nil {
				return e
			}
		}
		if e = m.active(v.ID); e != nil {
			return e
		}
		for _, op := range []string{"mount", "start"} {
			if e = m.run(v, op); e != nil {
				return e
			}
		}
		return m.probation(v)
	})
}
func (m *Manager) Check() error {
	if e := m.init(); e != nil {
		return e
	}
	var s State
	if e := ReadJSON(filepath.Join(m.Store, "active.json"), &s); e != nil {
		return e
	}
	if !identifier.MatchString(s.Current) {
		return errors.New("no active generation")
	}
	v, e := m.verify(m.gen(s.Current), true)
	if e != nil {
		return e
	}
	return m.run(v, "health")
}
func (m *Manager) Active() (Manifest, error) {
	if e := m.init(); e != nil {
		return Manifest{}, e
	}
	var s State
	if e := ReadJSON(filepath.Join(m.Store, "active.json"), &s); e != nil {
		return Manifest{}, e
	}
	if !identifier.MatchString(s.Current) {
		return Manifest{}, errors.New("no active generation")
	}
	return m.verify(m.gen(s.Current), true)
}

// Repair is serialized against promotion/package operations; it preserves the frontend.
func (m *Manager) RepairDNS() error {
	return m.locked(func() error {
		v, e := m.Active()
		if e != nil {
			return e
		}
		if e = m.Protected(v); e != nil {
			return e
		}
		return m.run(v, "repair-dns")
	})
}

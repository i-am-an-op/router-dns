package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProcessToken identifies one process lifetime, avoiding PID-reuse confusion.
type ProcessToken struct {
	PID   int
	Start string
}

func processToken(root string, pid int) (ProcessToken, error) {
	b, e := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if os.IsNotExist(e) {
		return ProcessToken{}, nil
	}
	if e != nil {
		return ProcessToken{}, e
	}
	// comm may contain spaces and parentheses; fields after its final ')' begin
	// with state (field 3). Starttime is field 22, hence index 19 here.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return ProcessToken{}, errors.New("invalid process stat")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return ProcessToken{}, errors.New("short process stat")
	}
	if f[0] == "Z" || f[0] == "X" {
		return ProcessToken{}, nil
	}
	return ProcessToken{pid, f[19]}, nil
}
func WaitProcesses(ctx context.Context, root string, tokens []ProcessToken) error {
	for {
		alive := false
		for _, want := range tokens {
			got, e := processToken(root, want.PID)
			if e != nil {
				return e
			}
			if got == want && got.Start != "" {
				alive = true
			}
		}
		if !alive {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("owned service did not quiesce before deadline")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type ServiceCall func(context.Context, string, ...string) ([]byte, error)

func serviceCall(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.WaitDelay = time.Second
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error {
		if c.Process == nil {
			return nil
		}
		return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
	}
	// Fixed local commands only. Deadline cancellation includes stop-helper
	// children; they must not continue mutating state during recovery.
	b, e := c.Output()
	if len(b) > 1024*1024 {
		return nil, errors.New("service response too large")
	}
	return b, e
}
func StopService(ctx context.Context, name, procRoot string, call ServiceCall) error {
	if name != "dns-evaluation" && name != "openclash" {
		return errors.New("service outside owned set")
	}
	if call == nil {
		call = serviceCall
	}
	query := `{"name":"` + name + `"}`
	b, e := call(ctx, "ubus", "call", "service", "list", query)
	if e != nil {
		return errors.New("cannot inspect owned service")
	}
	type instance struct {
		PID     int  `json:"pid"`
		Running bool `json:"running"`
	}
	type service struct {
		Instances map[string]instance `json:"instances"`
	}
	var services map[string]service
	if e = json.Unmarshal(b, &services); e != nil {
		return errors.New("invalid service response")
	}
	tokens := []ProcessToken{}
	for _, in := range services[name].Instances {
		if in.PID <= 0 {
			if in.Running {
				return errors.New("running service lacks process identity")
			}
			continue
		}
		token, e := processToken(procRoot, in.PID)
		if e != nil {
			return e
		}
		if token.Start != "" {
			tokens = append(tokens, token)
		}
	}
	if name == "openclash" {
		// Preserve its selection backup/firewall cleanup/protected DNS stop hooks.
		_, e = call(ctx, "/etc/init.d/openclash", "stop")
	} else if _, exists := services[name]; exists {
		_, e = call(ctx, "ubus", "call", "service", "delete", query)
	}
	if e != nil {
		return errors.New("owned service stop failed")
	}
	if e = WaitProcesses(ctx, procRoot, tokens); e != nil {
		return e
	}
	// Give procd time to reap an already exited captured PID, but refuse a
	// newly registered process. Service deletion itself is asynchronous.
	for {
		b, e = call(ctx, "ubus", "call", "service", "list", query)
		if e != nil {
			return errors.New("cannot verify stopped service")
		}
		services = nil
		if e = json.Unmarshal(b, &services); e != nil {
			return errors.New("invalid final service response")
		}
		pending := false
		for _, in := range services[name].Instances {
			if !in.Running && in.PID <= 0 {
				continue
			}
			captured := false
			for _, token := range tokens {
				if token.PID == in.PID {
					captured = true
				}
			}
			got, e := processToken(procRoot, in.PID)
			if e != nil {
				return e
			}
			if !captured || got.Start != "" {
				return errors.New("owned service respawned during stop")
			}
			pending = true
		}
		if !pending {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("owned service registration did not clear")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

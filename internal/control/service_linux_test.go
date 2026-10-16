package control

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func procFixture(t *testing.T, root string, pid int, state, start string) {
	t.Helper()
	d := filepath.Join(root, strconv.Itoa(pid))
	if e := os.MkdirAll(d, 0700); e != nil {
		t.Fatal(e)
	}
	fields := append([]string{state}, make([]string, 19)...)
	for i := 1; i < 19; i++ {
		fields[i] = "0"
	}
	fields[19] = start
	if e := os.WriteFile(filepath.Join(d, "stat"), []byte(strconv.Itoa(pid)+" (name with ) spaces) "+strings.Join(fields, " ")), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestServiceQuiescence(t *testing.T) {
	for _, state := range []string{"exited", "pid-reused", "zombie", "stale-registration", "still-alive", "respawn", "stop-failed", "malformed"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			procFixture(t, root, 123, "S", "100")
			calls := 0
			call := func(ctx context.Context, name string, args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte(`{"dns-evaluation":{"instances":{"one":{"pid":123,"running":true}}}}`), nil
				}
				if calls == 2 {
					switch state {
					case "exited", "stale-registration":
						os.Remove(filepath.Join(root, "123/stat"))
					case "pid-reused":
						procFixture(t, root, 123, "S", "101")
					case "zombie":
						procFixture(t, root, 123, "Z", "100")
					case "respawn":
						os.Remove(filepath.Join(root, "123/stat"))
					case "stop-failed":
						return nil, errors.New("failed")
					case "malformed":
						os.WriteFile(filepath.Join(root, "123/stat"), []byte("bad"), 0600)
					}
					return []byte(`{}`), nil
				}
				if state == "respawn" {
					return []byte(`{"dns-evaluation":{"instances":{"one":{"pid":456,"running":true}}}}`), nil
				}
				if state == "stale-registration" && calls == 3 {
					return []byte(`{"dns-evaluation":{"instances":{"one":{"pid":123,"running":true}}}}`), nil
				}
				return []byte(`{}`), nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			err := StopService(ctx, "dns-evaluation", root, call)
			pass := state == "exited" || state == "pid-reused" || state == "zombie" || state == "stale-registration"
			if (err == nil) != pass {
				t.Fatalf("%s: %v", state, err)
			}
		})
	}
}
func TestServiceRejectsUnownedName(t *testing.T) {
	if StopService(context.Background(), "dnsmasq", t.TempDir(), func(context.Context, string, ...string) ([]byte, error) { t.Fatal("executed"); return nil, nil }) == nil {
		t.Fatal("accepted unrelated service")
	}
}
func TestWaitForRealProcessExit(t *testing.T) {
	// This test observes the actual /proc identity of a short child process;
	// no signal is sent and no real service manager is called.
	cmd := exec.Command("sh", "-c", "sleep 0.1")
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer cmd.Wait()
	token, e := processToken("/proc", cmd.Process.Pid)
	if e != nil || token.Start == "" {
		t.Fatalf("token %v %v", token, e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if e = WaitProcesses(ctx, "/proc", []ProcessToken{token}); e != nil {
		t.Fatal(e)
	}
}

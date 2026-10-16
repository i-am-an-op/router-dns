package control

import (
	"encoding/json"
	"errors"
	"go.yaml.in/yaml/v3"
	"io"
	"os"
)

func Profile(path string) (map[string]any, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	d := yaml.NewDecoder(io.LimitReader(f, 16<<20))
	var v map[string]any
	if e = d.Decode(&v); e != nil {
		return nil, errors.New("profile parse refused (private details suppressed)")
	}
	var extra any
	if e = d.Decode(&extra); e != io.EOF {
		return nil, errors.New("multiple YAML documents refused")
	}
	if v == nil {
		return nil, errors.New("empty profile")
	}
	return v, nil
}
func Fingerprints(v map[string]any) (string, string, error) {
	dns, ok := v["dns"].(map[string]any)
	if !ok || dns["enable"] != true || dns["disable-cache"] != true {
		return "", "", errors.New("managed DNS delegation missing")
	}
	p := map[string]any{"dns": dns, "ipv6": v["ipv6"]}
	b, e := json.Marshal(p)
	if e != nil {
		return "", "", errors.New("noncanonical DNS policy")
	}
	// Everything outside the explicit DNS/IPv6 boundary is preserved and reviewed,
	// including rules, provider credentials, groups, TUN, LAN listeners and hooks.
	app := map[string]any{}
	for k, x := range v {
		if k != "dns" && k != "ipv6" {
			app[k] = x
		}
	}
	a, e := json.Marshal(app)
	if e != nil {
		return "", "", errors.New("noncanonical application policy")
	}
	return Hash(b), Hash(a), nil
}
func CheckProfile(path, dns, app string) error {
	v, e := Profile(path)
	if e != nil {
		return e
	}
	d, a, e := Fingerprints(v)
	if e != nil {
		return e
	}
	if d != dns || a != app {
		return errors.New("rendered DNS or application policy differs")
	}
	return nil
}

// StageProfile is offline only: inherit the reviewed DNS/IPv6 fields and report
// application changes for human review. It does not reload OpenClash or sign it.
func StageProfile(base, candidate, out string) (map[string]string, error) {
	b, e := Profile(base)
	if e != nil {
		return nil, e
	}
	c, e := Profile(candidate)
	if e != nil {
		return nil, e
	}
	_, old, e := Fingerprints(b)
	if e != nil {
		return nil, e
	}
	c["dns"] = b["dns"]
	c["ipv6"] = b["ipv6"]
	d, a, e := Fingerprints(c)
	if e != nil {
		return nil, e
	}
	data, e := yaml.Marshal(c)
	if e != nil {
		return nil, errors.New("profile encode failed")
	}
	if _, e = os.Lstat(out); !os.IsNotExist(e) {
		return nil, errors.New("output already exists")
	}
	if e = Atomic(out, data, 0600); e != nil {
		return nil, e
	}
	return map[string]string{"dns_hash": d, "routing_hash": a, "previous_routing_hash": old, "status": "unsigned-review-candidate"}, nil
}

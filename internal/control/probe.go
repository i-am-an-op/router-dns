package control

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// DNSProbe is a bounded readiness check, not a full validating resolver or an
// acceptance/performance test. The identical workload suite tests correctness.
func DNSProbe(p Probe) error {
	if p.Network != "udp" && p.Network != "tcp" {
		return errors.New("invalid DNS probe network")
	}
	host, _, e := net.SplitHostPort(p.Address)
	if e != nil || net.ParseIP(host) == nil {
		return errors.New("probe bootstrap requires numeric address")
	}
	q := make([]byte, 12)
	if _, e = rand.Read(q[:2]); e != nil {
		return e
	}
	binary.BigEndian.PutUint16(q[2:4], 0x100)
	q[5] = 1
	for _, s := range strings.Split(strings.TrimSuffix(p.Name, "."), ".") {
		if len(s) == 0 || len(s) > 63 {
			return errors.New("invalid probe name")
		}
		q = append(q, byte(len(s)))
		q = append(q, s...)
	}
	q = append(q, 0, byte(p.Type>>8), byte(p.Type), 0, 1)
	// EDNS0 with DO; validators decide AD. No CD bypass.
	q[11] = 1
	q = append(q, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0)
	c, e := net.DialTimeout(p.Network, p.Address, time.Second)
	if e != nil {
		return errors.New("probe connect failed")
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	var r []byte
	if p.Network == "tcp" {
		wire := append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
		if _, e = c.Write(wire); e != nil {
			return e
		}
		n := make([]byte, 2)
		if _, e = io.ReadFull(c, n); e != nil {
			return e
		}
		r = make([]byte, binary.BigEndian.Uint16(n))
		_, e = io.ReadFull(c, r)
	} else {
		if _, e = c.Write(q); e != nil {
			return e
		}
		r = make([]byte, 65535)
		var n int
		n, e = c.Read(r)
		r = r[:n]
	}
	if e != nil || len(r) < 12 {
		return errors.New("probe truncated response")
	}
	flags := binary.BigEndian.Uint16(r[2:4])
	if r[0] != q[0] || r[1] != q[1] || flags&0x8000 == 0 || flags&0x200 != 0 || int(flags&15) != p.Rcode || p.AD && flags&0x20 == 0 || int(binary.BigEndian.Uint16(r[6:8])) < p.MinAnswers {
		return errors.New("probe response mismatch")
	}
	return nil
}

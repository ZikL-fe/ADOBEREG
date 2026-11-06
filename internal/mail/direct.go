package mail

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mail stays off the registration proxy and off a local fake-ip tunnel.
// A Meta/Clash TUN answers mail hosts with 198.18.0.0/15, which drags IMAP
// and token refresh into that proxy. When that tunnel is up, lookups and
// sockets go out a physical NIC instead.

var httpClient = &http.Client{
	Timeout: 25 * time.Second,
	Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           dialDirect,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   12 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	},
}

func dialDirect(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	local, bypass := mailRoute()
	if bypass && local != nil {
		d.LocalAddr = &net.TCPAddr{IP: local}
		if host, port, err := net.SplitHostPort(addr); err == nil {
			if ip := resolveDirect(host, local); ip != "" {
				addr = net.JoinHostPort(ip, port)
			}
		}
		network = "tcp4"
	}
	return d.DialContext(ctx, network, addr)
}

func isFakeIP(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 198 && (v4[1] == 18 || v4[1] == 19)
}

type routeSnap struct {
	at     time.Time
	local  net.IP
	bypass bool
}

var routeState struct {
	sync.Mutex
	snap routeSnap
}

func mailRoute() (net.IP, bool) {
	routeState.Lock()
	defer routeState.Unlock()
	if time.Since(routeState.snap.at) < 30*time.Second {
		return routeState.snap.local, routeState.snap.bypass
	}
	snap := routeSnap{at: time.Now(), bypass: tunnelUp()}
	if snap.bypass {
		for _, ip := range physicalIPv4s() {
			got, err := queryA("8.8.8.8", ip, "one.one.one.one")
			if err == nil && len(got) > 0 && !isFakeIP(got[0]) {
				snap.local = ip
				break
			}
		}
	}
	routeState.snap = snap
	return snap.local, snap.bypass
}

func tunnelUp() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipn, ok := addr.(*net.IPNet)
			if ok && isFakeIP(ipn.IP) {
				return true
			}
		}
	}
	return false
}

func physicalIPv4s() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipn, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 == nil || v4.IsLoopback() || isFakeIP(v4) || isLinkLocal(v4) {
				continue
			}
			out = append(out, append(net.IP(nil), v4...))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return ipRank(out[i]) < ipRank(out[j]) })
	return out
}

func isLinkLocal(v4 net.IP) bool {
	return v4[0] == 169 && v4[1] == 254
}

func ipRank(ip net.IP) int {
	v4 := ip.To4()
	switch {
	case v4[0] == 192 && v4[1] == 168:
		return 0
	case v4[0] == 10:
		return 1
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return 2
	default:
		return 3
	}
}

type cachedIP struct {
	ip net.IP
	at time.Time
}

var dnsCache struct {
	sync.Mutex
	m map[string]cachedIP
}

func resolveDirect(host string, local net.IP) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	key := host
	dnsCache.Lock()
	if dnsCache.m == nil {
		dnsCache.m = map[string]cachedIP{}
	}
	if hit, ok := dnsCache.m[key]; ok && time.Since(hit.at) < 2*time.Minute && !isFakeIP(hit.ip) {
		dnsCache.Unlock()
		return hit.ip.String()
	}
	dnsCache.Unlock()
	var found net.IP
	for _, server := range []string{"8.8.8.8", "1.1.1.1", "114.114.114.114"} {
		ips, err := queryA(server, local, host)
		if err != nil || len(ips) == 0 || isFakeIP(ips[0]) {
			continue
		}
		found = ips[0]
		break
	}
	if found == nil {
		return ""
	}
	dnsCache.Lock()
	dnsCache.m[key] = cachedIP{ip: found, at: time.Now()}
	dnsCache.Unlock()
	return found.String()
}

func queryA(server string, local net.IP, host string) ([]net.IP, error) {
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: local}, &net.UDPAddr{IP: net.ParseIP(server), Port: 53})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	id := uint16(time.Now().UnixNano())
	if _, err := conn.Write(dnsQuery(id, host)); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseA(buf[:n], id)
}

func dnsQuery(id uint16, host string) []byte {
	b := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0x00, 0x00, 0x01, 0x00, 0x01)
}

func parseA(msg []byte, id uint16) ([]net.IP, error) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[0:2]) != id {
		return nil, ErrUnreachable
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	i := 12
	for n := 0; n < qd; n++ {
		next, ok := skipName(msg, i)
		if !ok || next+4 > len(msg) {
			return nil, ErrUnreachable
		}
		i = next + 4
	}
	var out []net.IP
	for n := 0; n < an; n++ {
		next, ok := skipName(msg, i)
		if !ok || next+10 > len(msg) {
			return nil, ErrUnreachable
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(msg) {
			return nil, ErrUnreachable
		}
		if typ == 1 && rdlen == 4 {
			out = append(out, net.IP(msg[rdata:rdata+4]))
		}
		i = rdata + rdlen
	}
	if len(out) == 0 {
		return nil, ErrUnreachable
	}
	return out, nil
}

func skipName(msg []byte, i int) (int, bool) {
	for guard := 0; guard < 20; guard++ {
		if i >= len(msg) {
			return 0, false
		}
		if msg[i] == 0 {
			return i + 1, true
		}
		if msg[i]&0xC0 == 0xC0 {
			if i+1 >= len(msg) {
				return 0, false
			}
			return i + 2, true
		}
		i += 1 + int(msg[i])
	}
	return 0, false
}

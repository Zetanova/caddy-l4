package l4proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

type fakeLookup struct {
	ips []net.IP
	err error
}

func (f fakeLookup) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return f.ips, f.err
}

// Ensure dialPeers binds to an explicitly configured local port for TCP.
func TestDialPeersUsesConfiguredLocalPortTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for upstream: %v", err)
	}
	defer ln.Close()

	localPortListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving local port: %v", err)
	}
	localPort := localPortListener.Addr().(*net.TCPAddr).Port
	localPortListener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()

	upstreamAddr := ln.Addr().String()
	localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)

	parsedUpstream, err := caddy.ParseNetworkAddress(upstreamAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewExample()}
	upstream := &Upstream{
		LocalAddrs: []string{localAddr},
		localAddrs: []string{localAddr},
		peers:      []*peer{{address: &parsedUpstream}},
	}

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers: %v", err)
	}
	defer func() {
		for _, c := range upConns {
			c.Close()
		}
		select {
		case conn := <-accepted:
			if conn != nil {
				conn.Close()
			}
		default:
		}
	}()

	localTCPAddr, ok := upConns[0].LocalAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCP local address, got %T", upConns[0].LocalAddr())
	}
	if localTCPAddr.Port != localPort {
		t.Fatalf("expected local port %d, got %d", localPort, localTCPAddr.Port)
	}
}

// Ensure dialPeers binds to an explicitly configured local port for UDP.
func TestDialPeersUsesConfiguredLocalPortUDP(t *testing.T) {
	upstreamPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for upstream (udp): %v", err)
	}
	defer upstreamPC.Close()

	localPortPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving local udp port: %v", err)
	}
	localPort := localPortPC.LocalAddr().(*net.UDPAddr).Port
	localPortPC.Close()

	upstreamAddr := fmt.Sprintf("udp/%s", upstreamPC.LocalAddr().String())
	localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)

	parsedUpstream, err := caddy.ParseNetworkAddress(upstreamAddr)
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewExample()}
	upstream := &Upstream{
		LocalAddrs: []string{localAddr},
		localAddrs: []string{localAddr},
		peers:      []*peer{{address: &parsedUpstream}},
	}

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers udp: %v", err)
	}
	defer func() {
		for _, c := range upConns {
			c.Close()
		}
	}()

	localUDPAddr, ok := upConns[0].LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDP local address, got %T", upConns[0].LocalAddr())
	}
	if localUDPAddr.Port != localPort {
		t.Fatalf("expected local udp port %d, got %d", localPort, localUDPAddr.Port)
	}
}

func TestDialPeersDirectWithoutNetworkProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for upstream: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		if conn, err := ln.Accept(); err == nil {
			accepted <- conn
		}
	}()

	parsedUpstream, err := caddy.ParseNetworkAddress(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing upstream address: %v", err)
	}

	h := &Handler{logger: zap.NewExample()}
	upstream := &Upstream{
		peers: []*peer{{address: &parsedUpstream}},
	}

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers: %v", err)
	}
	defer func() {
		for _, c := range upConns {
			c.Close()
		}
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
	}()

	select {
	case conn := <-accepted:
		conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream did not receive direct connection")
	}
}

func TestDialPeersSOCKS5NetworkProxyReceivesExplicitTarget(t *testing.T) {
	proxyAddr, targetCh, closeProxy := startTestSOCKS5Proxy(t)
	defer closeProxy()

	h := &Handler{logger: zap.NewExample()}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test:443"},
		NetworkProxy: &NetworkProxy{
			From: "socks5",
			Dial: []string{proxyAddr},
		},
	})

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers: %v", err)
	}
	defer closeAll(upConns)

	select {
	case got := <-targetCh:
		if got != "example.test:443" {
			t.Fatalf("SOCKS5 proxy saw target %q, want %q", got, "example.test:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("SOCKS5 proxy did not receive a target")
	}
}

func TestDialPeersHTTPNetworkProxyReceivesExplicitTarget(t *testing.T) {
	proxyURL, targetCh, closeProxy := startTestHTTPConnectProxy(t)
	defer closeProxy()

	h := &Handler{logger: zap.NewExample()}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test:8443"},
		NetworkProxy: &NetworkProxy{
			From: "url",
			URL:  proxyURL,
		},
	})

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers: %v", err)
	}
	defer closeAll(upConns)

	select {
	case got := <-targetCh:
		if got != "example.test:8443" {
			t.Fatalf("HTTP proxy saw target %q, want %q", got, "example.test:8443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("HTTP proxy did not receive a target")
	}
}

func TestDialPeersNetworkProxyInfersHostOnlyTargetPort(t *testing.T) {
	proxyURL, targetCh, closeProxy := startTestHTTPConnectProxy(t)
	defer closeProxy()

	h := &Handler{logger: zap.NewExample()}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test"},
		NetworkProxy: &NetworkProxy{
			From: "url",
			URL:  proxyURL,
		},
	})

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(&localAddrConn{
		Conn:      downServer,
		localAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9443},
	}, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	upConns, err := h.dialPeers(upstream, repl, down)
	if err != nil {
		t.Fatalf("dialPeers: %v", err)
	}
	defer closeAll(upConns)

	select {
	case got := <-targetCh:
		if got != "example.test:9443" {
			t.Fatalf("HTTP proxy saw inferred target %q, want %q", got, "example.test:9443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("HTTP proxy did not receive a target")
	}
}

func TestDialPeersNetworkProxyHostOnlyTargetRequiresInboundPort(t *testing.T) {
	proxyURL, _, closeProxy := startTestHTTPConnectProxy(t)
	defer closeProxy()

	h := &Handler{logger: zap.NewExample()}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test"},
		NetworkProxy: &NetworkProxy{
			From: "url",
			URL:  proxyURL,
		},
	})

	downClient, downServer := net.Pipe()
	defer downClient.Close()
	defer downServer.Close()
	down := layer4.WrapConnection(downServer, nil, h.logger)
	repl := down.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)

	_, err := h.dialPeers(upstream, repl, down)
	if err == nil {
		t.Fatalf("expected host-only target without inbound port to fail")
	}
	if !strings.Contains(err.Error(), "inbound local address") || !strings.Contains(err.Error(), "port") {
		t.Fatalf("expected clear inbound port error, got: %v", err)
	}
}

// Build-local-address selection tests
func TestSelectLocalAddrIPv6TCP(t *testing.T) {
	addrs := buildLocalAddrs([]string{"[2001:db8::1]:4040"}, "tcp6", 6, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	addr := addrs[0]
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected TCPAddr, got %T", addr)
	}
	if tcpAddr.Port != 4040 {
		t.Fatalf("expected port 4040, got %d", tcpAddr.Port)
	}
	if !tcpAddr.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected ip 2001:db8::1, got %s", tcpAddr.IP)
	}
}

func TestSelectLocalAddrIPv6UDP(t *testing.T) {
	addrs := buildLocalAddrs([]string{"[2001:db8::2]:5353"}, "udp6", 6, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	addr := addrs[0]
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected UDPAddr, got %T", addr)
	}
	if udpAddr.Port != 5353 {
		t.Fatalf("expected port 5353, got %d", udpAddr.Port)
	}
	if !udpAddr.IP.Equal(net.ParseIP("2001:db8::2")) {
		t.Fatalf("expected ip 2001:db8::2, got %s", udpAddr.IP)
	}
}

func TestSelectLocalAddrDefaultsToUpstreamFamily(t *testing.T) {
	addrs := buildLocalAddrs([]string{"192.0.2.1:5353"}, "udp", 0, zap.NewNop())
	if len(addrs) != 1 {
		t.Fatalf("expected 1 addr, got %d", len(addrs))
	}
	if _, ok := addrs[0].(*net.UDPAddr); !ok {
		t.Fatalf("expected UDPAddr, got %T", addrs[0])
	}
}

func TestSelectLocalAddrSkipsMismatchedFamilies(t *testing.T) {
	if addrs := buildLocalAddrs([]string{"::1"}, "tcp4", 4, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no addr for ipv6 source with tcp4 upstream")
	}
	if addrs := buildLocalAddrs([]string{"127.0.0.1"}, "tcp6", 6, zap.NewNop()); len(addrs) != 0 {
		t.Fatalf("expected no addr for ipv4 source with tcp6 upstream")
	}
}

func TestSelectLocalAddrChoosesMatchingFromList(t *testing.T) {
	addrs := buildLocalAddrs([]string{"127.0.0.1", "::1"}, "tcp6", 6, zap.NewNop())
	if len(addrs) == 0 {
		t.Fatalf("expected matching addr")
	}
	if tcpAddr, ok := addrs[0].(*net.TCPAddr); !ok || tcpAddr.IP.To4() != nil {
		t.Fatalf("expected ipv6 local addr, got %T %v", addrs[0], addrs[0])
	}

	addrs = buildLocalAddrs([]string{"127.0.0.1", "::1"}, "tcp4", 4, zap.NewNop())
	if len(addrs) == 0 {
		t.Fatalf("expected matching addr")
	}
	if tcpAddr, ok := addrs[0].(*net.TCPAddr); !ok || tcpAddr.IP.To4() == nil {
		t.Fatalf("expected ipv4 local addr, got %T %v", addrs[0], addrs[0])
	}
}

// Known placeholders in local_address should be replaced at provision time,
// while unknown (runtime) placeholders must be preserved for per-connection expansion.
func TestProvisionExpandsKnownPlaceholdersInLocalAddr(t *testing.T) {
	t.Setenv("L4PROXY_TEST_BIND", "192.0.2.77")

	dialAddr := "127.0.0.1:59991"
	t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

	h := &Handler{logger: zap.NewNop()}
	u := &Upstream{
		Dial:       []string{dialAddr},
		LocalAddrs: []string{"{env.L4PROXY_TEST_BIND}", "{l4.conn.local_addr}"},
	}
	if err := u.provision(caddy.Context{}, h); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got, want := len(u.localAddrs), 2; got != want {
		t.Fatalf("provisioned localAddrs: got %d entries, want %d", got, want)
	}
	if got, want := u.localAddrs[0], "192.0.2.77"; got != want {
		t.Fatalf("known placeholder should be resolved: got %q, want %q", got, want)
	}
	if got, want := u.localAddrs[1], "{l4.conn.local_addr}"; got != want {
		t.Fatalf("unknown (per-connection) placeholder should be preserved at provision: got %q, want %q", got, want)
	}
}

func TestResolveDestFamilyWithPreferences(t *testing.T) {
	orig := lookupIP
	t.Cleanup(func() { lookupIP = orig })

	table := []struct {
		name   string
		netw   string
		host   string
		pref   string
		ips    []net.IP
		expect int
		err    bool
	}{
		{name: "literal v4 disallowed by pref", netw: "tcp", host: "192.0.2.1:80", pref: "ipv6_only", ips: nil, err: true},
		{name: "literal v6 disallowed by pref", netw: "tcp", host: "[2001:db8::1]:80", pref: "ipv4_only", ips: nil, err: true},
		{name: "hint tcp4 vs ipv6_only", netw: "tcp4", host: "example.com:80", pref: "ipv6_only", ips: []net.IP{net.ParseIP("2001:db8::1")}, err: true},
		{name: "hint tcp6 vs ipv4_only", netw: "tcp6", host: "example.com:80", pref: "ipv4_only", ips: []net.IP{net.ParseIP("192.0.2.1")}, err: true},
		{name: "pref v4_only with AAAA", netw: "tcp", host: "example.com:80", pref: "ipv4_only", ips: []net.IP{net.ParseIP("2001:db8::1")}, err: true},
		{name: "pref v6_only with AAAA", netw: "tcp", host: "example.com:80", pref: "ipv6_only", ips: []net.IP{net.ParseIP("2001:db8::1")}, expect: 6},
		{name: "pref v6_first with both", netw: "tcp", host: "example.com:80", pref: "ipv6_first", ips: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")}, expect: 6},
		{name: "pref v4_first with both", netw: "tcp", host: "example.com:80", pref: "ipv4_first", ips: []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1")}, expect: 4},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			lookupIP = fakeLookup{ips: tt.ips}.LookupIP
			got, err := resolveDestFamily(tt.netw, tt.host, tt.pref)
			if tt.err {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.expect {
				t.Fatalf("got %d, want %d", got, tt.expect)
			}
		})
	}
}

// resolver_preference must be one of a fixed set of values; provision must reject
// anything else (including typos like "ipv46_only") rather than silently falling
// back to ipv4_first.
func TestProvisionRejectsInvalidResolverPreference(t *testing.T) {
	cases := []struct {
		name string
		pref string
	}{
		{"typo", "ipv46_only"},
		{"garbage", "not-a-preference"},
		{"mixed_case", "IPv4_Only"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := "127.0.0.1:59992"
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				ResolverPreference: tc.pref,
			}
			err := u.provision(caddy.Context{}, h)
			if err == nil {
				t.Fatalf("expected provision to reject resolver_preference=%q", tc.pref)
			}
			if !strings.Contains(err.Error(), "resolver_preference") {
				t.Fatalf("unexpected error for %q: %v", tc.pref, err)
			}
		})
	}
}

// Valid resolver_preference values (including empty string) must provision cleanly.
func TestProvisionAcceptsValidResolverPreference(t *testing.T) {
	valid := []string{"", "ipv4_only", "ipv6_only", "ipv4_first", "ipv6_first"}
	for i, pref := range valid {
		t.Run(pref, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:5999%d", 3+i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				ResolverPreference: pref,
			}
			if err := u.provision(caddy.Context{}, h); err != nil {
				t.Fatalf("provision rejected valid resolver_preference %q: %v", pref, err)
			}
		})
	}
}

// An "_only" resolver_preference paired with a local_address whose family can
// never match must be rejected at provision, otherwise every source would be
// silently skipped and the OS default would silently override the user's intent.
// Only the two contradictory combinations are invalid; mixed-family sources and
// "_first" preferences (which allow cross-family fallback) must continue to pass.
func TestProvisionRejectsIncompatibleLocalAddrAndResolverPreference(t *testing.T) {
	cases := []struct {
		name       string
		localAddrs []string
		preference string
	}{
		{"v4_src_with_ipv6_only", []string{"10.0.0.5"}, "ipv6_only"},
		{"v6_src_with_ipv4_only", []string{"2001:db8::5"}, "ipv4_only"},
		{"v4_src_with_port_with_ipv6_only", []string{"10.0.0.5:5555"}, "ipv6_only"},
		{"v6_src_bracketed_with_ipv4_only", []string{"[2001:db8::5]:5555"}, "ipv4_only"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:6100%d", i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				LocalAddrs:         tc.localAddrs,
				ResolverPreference: tc.preference,
			}
			err := u.provision(caddy.Context{}, h)
			if err == nil {
				t.Fatalf("expected provision to reject local_address=%v with resolver_preference=%q",
					tc.localAddrs, tc.preference)
			}
			if !strings.Contains(err.Error(), "resolver_preference") {
				t.Fatalf("unexpected error for %v + %q: %v", tc.localAddrs, tc.preference, err)
			}
		})
	}
}

// Compatible combinations must provision cleanly: either the preference is not
// "_only", or at least one local_address matches the "_only" family, or an
// unresolved runtime placeholder prevents provision-time validation.
func TestProvisionAcceptsCompatibleLocalAddrAndResolverPreference(t *testing.T) {
	cases := []struct {
		name       string
		localAddrs []string
		preference string
	}{
		{"v4_only_with_v4_src", []string{"10.0.0.5"}, "ipv4_only"},
		{"v6_only_with_v6_src", []string{"2001:db8::5"}, "ipv6_only"},
		{"v4_only_with_mixed_sources", []string{"2001:db8::5", "10.0.0.5"}, "ipv4_only"},
		{"v6_only_with_mixed_sources", []string{"10.0.0.5", "2001:db8::5"}, "ipv6_only"},
		{"ipv4_first_with_v6_src", []string{"2001:db8::5"}, "ipv4_first"},
		{"ipv6_first_with_v4_src", []string{"10.0.0.5"}, "ipv6_first"},
		{"no_preference_with_v6_src", []string{"2001:db8::5"}, ""},
		{"ipv4_only_with_placeholder", []string{"{l4.vars.src}"}, "ipv4_only"},
		{"ipv6_only_with_placeholder", []string{"{l4.vars.src}"}, "ipv6_only"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dialAddr := fmt.Sprintf("127.0.0.1:6200%d", i)
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:               []string{dialAddr},
				LocalAddrs:         tc.localAddrs,
				ResolverPreference: tc.preference,
			}
			if err := u.provision(caddy.Context{}, h); err != nil {
				t.Fatalf("provision rejected compatible config %v + %q: %v", tc.localAddrs, tc.preference, err)
			}
		})
	}
}

// local_address is not supported for Unix upstreams; provision must reject any
// such combination so that the invalid config surfaces early with a clear error.
func TestProvisionRejectsLocalAddrForUnixUpstream(t *testing.T) {
	for _, netw := range []string{"unix", "unixpacket", "unixgram"} {
		t.Run(netw, func(t *testing.T) {
			dialAddr := netw + "//tmp/l4proxy-provision-test-" + netw + ".sock"
			t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })

			h := &Handler{logger: zap.NewNop()}
			u := &Upstream{
				Dial:       []string{dialAddr},
				LocalAddrs: []string{"/tmp/l4proxy-src.sock"},
			}
			err := u.provision(caddy.Context{}, h)
			if err == nil {
				t.Fatalf("expected provision to reject local_address for %s upstream", netw)
			}
			if !strings.Contains(err.Error(), "local_address is not supported for Unix socket upstreams") {
				t.Fatalf("unexpected error for %s upstream: %v", netw, err)
			}
		})
	}
}

// Active health checks should honor local_address when provided.
func TestActiveHealthCheckUsesLocalAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer ln.Close()

	accepted := make(chan *net.TCPAddr, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				accepted <- tcpAddr
			}
			_ = conn.Close()
		}
	}()

	upAddr, err := caddy.ParseNetworkAddress(ln.Addr().String())
	if err != nil {
		t.Fatalf("parse upstream addr: %v", err)
	}

	h := &Handler{
		logger: zap.NewExample(),
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Timeout: caddy.Duration(2 * time.Second),
				logger:  zap.NewExample(),
			},
		},
	}

	upstream := &Upstream{
		LocalAddrs: []string{"127.0.0.1"}, // defaults to tcp with ephemeral port
		localAddrs: []string{"127.0.0.1"},
		peers:      []*peer{{address: &upAddr}},
	}

	if err := h.doActiveHealthCheck(upstream, upstream.peers[0]); err != nil {
		t.Fatalf("active health check: %v", err)
	}

	select {
	case remote := <-accepted:
		if !remote.IP.Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("expected local bind ip 127.0.0.1, got %s", remote.IP)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no health check connection observed")
	}
}

func TestActiveHealthCheckUsesNetworkProxy(t *testing.T) {
	proxyURL, targetCh, closeProxy := startTestHTTPConnectProxy(t)
	defer closeProxy()

	h := &Handler{
		logger: zap.NewExample(),
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Timeout: caddy.Duration(200 * time.Millisecond),
				logger:  zap.NewExample(),
			},
		},
	}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test:443"},
		NetworkProxy: &NetworkProxy{
			From: "url",
			URL:  proxyURL,
		},
	})
	if _, err := upstream.peers[0].setHealthy(false); err != nil {
		t.Fatalf("mark peer unhealthy before check: %v", err)
	}

	if err := h.doActiveHealthCheck(upstream, upstream.peers[0]); err != nil {
		t.Fatalf("active health check: %v", err)
	}

	select {
	case got := <-targetCh:
		if got != "example.test:443" {
			t.Fatalf("HTTP proxy saw health check target %q, want %q", got, "example.test:443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("HTTP proxy did not receive a health check target")
	}
	if !upstream.peers[0].healthy() {
		t.Fatalf("expected proxied active health check to mark peer healthy")
	}
}

func TestActiveHealthCheckNetworkProxyHostOnlyRequiresHealthPort(t *testing.T) {
	proxyURL, _, closeProxy := startTestHTTPConnectProxy(t)
	defer closeProxy()

	h := &Handler{
		logger: zap.NewExample(),
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Timeout: caddy.Duration(200 * time.Millisecond),
				logger:  zap.NewExample(),
			},
		},
	}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test"},
		NetworkProxy: &NetworkProxy{
			From: "url",
			URL:  proxyURL,
		},
	})

	err := h.doActiveHealthCheck(upstream, upstream.peers[0])
	if err == nil {
		t.Fatalf("expected host-only proxied active health check without health_port to fail")
	}
	if !strings.Contains(err.Error(), "health_port") || !strings.Contains(err.Error(), "no inbound connection") {
		t.Fatalf("expected clear health_port error, got: %v", err)
	}
}

func TestActiveHealthCheckNetworkProxyHostOnlyUsesHealthPort(t *testing.T) {
	proxyURL, targetCh, closeProxy := startTestHTTPConnectProxy(t)
	defer closeProxy()

	h := &Handler{
		logger: zap.NewExample(),
		HealthChecks: &HealthChecks{
			Active: &ActiveHealthChecks{
				Port:    8443,
				Timeout: caddy.Duration(200 * time.Millisecond),
				logger:  zap.NewExample(),
			},
		},
	}
	upstream := provisionTestUpstream(t, h, &Upstream{
		Dial: []string{"example.test"},
		NetworkProxy: &NetworkProxy{
			From: "url",
			URL:  proxyURL,
		},
	})

	if err := h.doActiveHealthCheck(upstream, upstream.peers[0]); err != nil {
		t.Fatalf("active health check: %v", err)
	}

	select {
	case got := <-targetCh:
		if got != "example.test:8443" {
			t.Fatalf("HTTP proxy saw health check target %q, want %q", got, "example.test:8443")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("HTTP proxy did not receive a health check target")
	}
}

type localAddrConn struct {
	net.Conn
	localAddr net.Addr
}

func (c *localAddrConn) LocalAddr() net.Addr {
	return c.localAddr
}

func provisionTestUpstream(t *testing.T, h *Handler, u *Upstream) *Upstream {
	t.Helper()
	for _, dialAddr := range u.Dial {
		t.Cleanup(func() { _, _ = peers.Delete(dialAddr) })
	}
	if err := u.provision(caddy.Context{}, h); err != nil {
		t.Fatalf("provision upstream: %v", err)
	}
	return u
}

func closeAll(conns []net.Conn) {
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func startTestHTTPConnectProxy(t *testing.T) (string, <-chan string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen HTTP CONNECT proxy: %v", err)
	}

	targetCh := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		targetCh <- req.Host
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, _ = io.Copy(io.Discard, br)
	}()

	closeProxy := func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	return "http://" + ln.Addr().String(), targetCh, closeProxy
}

func startTestSOCKS5Proxy(t *testing.T) (string, <-chan string, func()) {
	t.Helper()

	socketPath := t.TempDir() + "/socks.sock"
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen SOCKS5 proxy: %v", err)
	}

	targetCh := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		header := make([]byte, 2)
		if _, err := io.ReadFull(br, header); err != nil {
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err := io.ReadFull(br, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return
		}

		request := make([]byte, 4)
		if _, err := io.ReadFull(br, request); err != nil {
			return
		}
		if request[1] != 0x01 {
			return
		}

		host, err := readSOCKS5Host(br, request[3])
		if err != nil {
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(br, portBytes); err != nil {
			return
		}
		targetCh <- net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(portBytes)))

		_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		_, _ = io.Copy(io.Discard, br)
	}()

	closeProxy := func() {
		_ = ln.Close()
		_ = os.Remove(socketPath)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}

	return "unix/" + socketPath, targetCh, closeProxy
}

func readSOCKS5Host(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		ip := make([]byte, net.IPv4len)
		_, err := io.ReadFull(r, ip)
		return net.IP(ip).String(), err
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return "", err
		}
		host := make([]byte, int(length[0]))
		_, err := io.ReadFull(r, host)
		return string(host), err
	case 0x04:
		ip := make([]byte, net.IPv6len)
		_, err := io.ReadFull(r, ip)
		return net.IP(ip).String(), err
	default:
		return "", fmt.Errorf("unknown SOCKS5 address type %d", atyp)
	}
}

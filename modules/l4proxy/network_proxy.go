// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	xproxy "golang.org/x/net/proxy"
)

// NetworkProxy configures an upstream-scoped proxy hop for Layer4 dialing.
type NetworkProxy struct {
	// From selects the proxy type. Supported values are "socks5" and "url".
	From string `json:"from,omitempty"`

	// Dial is the SOCKS5 proxy endpoint network address.
	Dial []string `json:"dial,omitempty"`

	// URL is the HTTP CONNECT proxy URL.
	URL string `json:"url,omitempty"`

	dialAddr string
	proxyURL string
}

func (np *NetworkProxy) provision(repl *caddy.Replacer) error {
	switch np.From {
	case "socks5":
		if np.URL != "" {
			return fmt.Errorf("network_proxy socks5 cannot also set url")
		}
		if len(np.Dial) != 1 {
			return fmt.Errorf("network_proxy socks5 requires exactly one dial address")
		}
		np.dialAddr = repl.ReplaceKnown(np.Dial[0], "")
		if np.dialAddr == "" {
			return fmt.Errorf("network_proxy socks5 dial address is empty")
		}
		if !containsPlaceholders(np.dialAddr) {
			if _, err := parseNetworkProxyDialAddress(np.dialAddr); err != nil {
				return err
			}
		}
	case "url":
		if len(np.Dial) != 0 {
			return fmt.Errorf("network_proxy url cannot also set dial")
		}
		np.proxyURL = repl.ReplaceKnown(np.URL, "")
		if np.proxyURL == "" {
			return fmt.Errorf("network_proxy url is empty")
		}
		if !containsPlaceholders(np.proxyURL) {
			if _, err := parseHTTPConnectProxyURL(np.proxyURL); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("network_proxy: unknown proxy type %q; must be one of: socks5, url", np.From)
	}
	return nil
}

// UnmarshalCaddyfile sets up the network proxy from Caddyfile tokens. Syntax:
//
//	network_proxy socks5 {
//		dial <proxy_address>
//	}
//	network_proxy url <http_proxy_url>
func (np *NetworkProxy) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name

	if !d.NextArg() {
		return d.ArgErr()
	}
	np.From = d.Val()

	switch np.From {
	case "url":
		if d.CountRemainingArgs() != 1 {
			return d.ArgErr()
		}
		_, np.URL = d.NextArg(), d.Val()
		if d.NextBlock(d.Nesting()) {
			return d.Errf("malformed %s url option: blocks are not supported", wrapper)
		}
	case "socks5":
		if d.CountRemainingArgs() > 0 {
			np.Dial = append(np.Dial, d.RemainingArgs()...)
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			optionName := d.Val()
			switch optionName {
			case "dial":
				if d.CountRemainingArgs() != 1 {
					return d.ArgErr()
				}
				_, dialAddr := d.NextArg(), d.Val()
				np.Dial = append(np.Dial, dialAddr)
			default:
				return d.ArgErr()
			}
			if d.NextBlock(nesting + 1) {
				return d.Errf("malformed %s socks5 option '%s': blocks are not supported", wrapper, optionName)
			}
		}
		if len(np.Dial) == 0 {
			return d.Errf("malformed %s socks5 option: dial address is required", wrapper)
		}
	default:
		return d.Errf("malformed %s option: unrecognized network_proxy type '%s'", wrapper, np.From)
	}

	return nil
}

func (np *NetworkProxy) dial(ctx context.Context, repl *caddy.Replacer, localAddrStrings []string, resolverPreference, targetNetwork, targetHostPort string, logger *zap.Logger) (net.Conn, error) {
	if err := requireTCPNetworkProxyTarget(targetNetwork); err != nil {
		return nil, err
	}

	switch np.From {
	case "socks5":
		return np.dialSOCKS5(ctx, repl, localAddrStrings, resolverPreference, targetNetwork, targetHostPort, logger)
	case "url":
		return np.dialHTTPConnect(ctx, repl, localAddrStrings, resolverPreference, targetHostPort, logger)
	default:
		return nil, fmt.Errorf("network_proxy: unknown proxy type %q; must be one of: socks5, url", np.From)
	}
}

func (np *NetworkProxy) dialSOCKS5(ctx context.Context, repl *caddy.Replacer, localAddrStrings []string, resolverPreference, targetNetwork, targetHostPort string, logger *zap.Logger) (net.Conn, error) {
	rawProxyAddr := repl.ReplaceAll(np.dialAddr, "")
	proxyAddr, err := parseNetworkProxyDialAddress(rawProxyAddr)
	if err != nil {
		return nil, err
	}

	proxyNetwork := proxyAddr.Network
	proxyHostPort := proxyAddr.JoinHostPort(0)
	proxyNetwork, localAddrs, err := buildNetworkProxyLocalAddrs(localAddrStrings, resolverPreference, proxyNetwork, proxyHostPort, logger)
	if err != nil {
		return nil, err
	}

	dialer, err := xproxy.SOCKS5(proxyNetwork, proxyHostPort, nil, localAddrDialer{localAddrs: localAddrs})
	if err != nil {
		return nil, err
	}
	if ctxDialer, ok := dialer.(xproxy.ContextDialer); ok {
		return ctxDialer.DialContext(ctx, targetNetwork, targetHostPort)
	}
	return dialer.Dial(targetNetwork, targetHostPort)
}

func (np *NetworkProxy) dialHTTPConnect(ctx context.Context, repl *caddy.Replacer, localAddrStrings []string, resolverPreference, targetHostPort string, logger *zap.Logger) (net.Conn, error) {
	proxyURL, err := parseHTTPConnectProxyURL(repl.ReplaceAll(np.proxyURL, ""))
	if err != nil {
		return nil, err
	}

	proxyNetwork := "tcp"
	proxyHostPort := proxyURLHostPort(proxyURL)
	proxyNetwork, localAddrs, err := buildNetworkProxyLocalAddrs(localAddrStrings, resolverPreference, proxyNetwork, proxyHostPort, logger)
	if err != nil {
		return nil, err
	}

	conn, err := localAddrDialer{localAddrs: localAddrs}.DialContext(ctx, proxyNetwork, proxyHostPort)
	if err != nil {
		return nil, err
	}

	br := bufio.NewReader(conn)
	if err := writeHTTPConnectRequest(conn, proxyURL, targetHostPort); err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("reading HTTP CONNECT response from network_proxy: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = conn.Close()
		return nil, fmt.Errorf("network_proxy HTTP CONNECT to %s failed: %s", targetHostPort, resp.Status)
	}

	return &bufferedConn{Conn: conn, reader: br}, nil
}

func parseNetworkProxyDialAddress(raw string) (*caddy.NetworkAddress, error) {
	addr, err := parseAddress(raw)
	if err != nil {
		return nil, fmt.Errorf("network_proxy socks5 dial: %w", err)
	}
	if !isStreamNetwork(addr.Network) {
		return nil, fmt.Errorf("network_proxy socks5 dial network %q is not supported; use tcp or unix", addr.Network)
	}
	if !caddy.IsUnixNetwork(addr.Network) && networkAddressPortOmitted(raw) {
		return nil, fmt.Errorf("network_proxy socks5 dial address %q requires a port", raw)
	}
	return addr, nil
}

func parseHTTPConnectProxyURL(raw string) (*url.URL, error) {
	proxyURL, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing network_proxy url: %w", err)
	}
	if proxyURL.Scheme != "http" {
		return nil, fmt.Errorf("network_proxy url scheme %q is not supported; use http", proxyURL.Scheme)
	}
	if proxyURL.Host == "" || strings.HasPrefix(proxyURL.Host, ":") {
		return nil, fmt.Errorf("network_proxy url is missing a host")
	}
	return proxyURL, nil
}

func buildNetworkProxyLocalAddrs(localAddrStrings []string, resolverPreference, proxyNetwork, proxyHostPort string, logger *zap.Logger) (string, []net.Addr, error) {
	var destFam int
	if len(localAddrStrings) > 0 || resolverPreference != "" {
		var err error
		destFam, err = resolveDestFamily(proxyNetwork, proxyHostPort, resolverPreference)
		if err != nil {
			return "", nil, err
		}
	}
	proxyNetwork = narrowNetworkForFamily(proxyNetwork, destFam)
	return proxyNetwork, buildLocalAddrs(localAddrStrings, proxyNetwork, destFam, logger), nil
}

func upstreamHostPort(addr *caddy.NetworkAddress, portWasOmitted bool, downLocalAddr net.Addr, inferPort bool) (string, error) {
	if caddy.IsUnixNetwork(addr.Network) || caddy.IsFdNetwork(addr.Network) || !portWasOmitted || !inferPort {
		return addr.JoinHostPort(0), nil
	}
	if downLocalAddr == nil {
		return "", fmt.Errorf("upstream %q is missing a port and inbound local address is nil", addr.Host)
	}

	port, err := portFromAddr(downLocalAddr)
	if err != nil {
		return "", fmt.Errorf("upstream %q is missing a port and inbound local address %q has no usable port: %w", addr.Host, downLocalAddr.String(), err)
	}
	return net.JoinHostPort(addr.Host, strconv.Itoa(port)), nil
}

func portFromAddr(addr net.Addr) (int, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		if a.Port > 0 {
			return a.Port, nil
		}
	case *net.UDPAddr:
		if a.Port > 0 {
			return a.Port, nil
		}
	}

	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	if portInt <= 0 {
		return 0, fmt.Errorf("port must be greater than zero")
	}
	return portInt, nil
}

func networkAddressPortOmitted(raw string) bool {
	network, _, port, err := caddy.SplitNetworkAddress(raw)
	if err != nil || caddy.IsUnixNetwork(network) || caddy.IsFdNetwork(network) {
		return false
	}
	return port == ""
}

func containsPlaceholders(s string) bool {
	return strings.Contains(s, "{") && strings.Contains(s, "}")
}

func requireTCPNetworkProxyTarget(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	default:
		return fmt.Errorf("network_proxy supports only TCP upstream targets, got %q", network)
	}
}

func isStreamNetwork(network string) bool {
	switch network {
	case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
		return true
	default:
		return false
	}
}

func proxyURLHostPort(proxyURL *url.URL) string {
	host := proxyURL.Hostname()
	port := proxyURL.Port()
	if port == "" {
		port = "80"
	}
	return net.JoinHostPort(host, port)
}

func writeHTTPConnectRequest(w io.Writer, proxyURL *url.URL, targetHostPort string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\n", targetHostPort)
	fmt.Fprintf(&b, "Host: %s\r\n", targetHostPort)
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(credentials)))
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

type localAddrDialer struct {
	localAddrs []net.Addr
}

func (d localAddrDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d localAddrDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if len(d.localAddrs) == 0 {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}

	var lastErr error
	for _, localAddr := range d.localAddrs {
		nd := net.Dialer{LocalAddr: localAddr}
		conn, err := nd.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

var _ caddyfile.Unmarshaler = (*NetworkProxy)(nil)

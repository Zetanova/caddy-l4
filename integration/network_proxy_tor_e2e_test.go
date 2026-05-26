package integration

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"

	_ "github.com/mholt/caddy-l4"
)

const (
	torE2EEnv        = "CADDY_L4_TOR_E2E"
	torSOCKSEnv      = "CADDY_L4_TOR_SOCKS"
	defaultTorSOCKS  = "127.0.0.1:9050"
	duckDuckGoOnion  = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443"
	duckDuckGoServer = "duckduckgo.com"
)

var opensslVerifyResultRE = regexp.MustCompile(`(?m)^Verify return code:\s*(\d+)\s*\(([^)]*)\)`)

func TestNetworkProxyTorDuckDuckGoOnionE2E(t *testing.T) {
	if os.Getenv(torE2EEnv) != "1" {
		t.Skipf("set %s=1 to run Tor network_proxy e2e test", torE2EEnv)
	}

	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skipf("openssl is required for this e2e test: %v", err)
	}

	torSOCKS := strings.TrimSpace(os.Getenv(torSOCKSEnv))
	if torSOCKS == "" {
		torSOCKS = defaultTorSOCKS
	}
	preflightTorSOCKS(t, torSOCKS)

	port := reserveLocalTCPPort(t)
	config := adaptCaddyfile(t, torProxyCaddyfile(port, torSOCKS))
	if err := caddy.Load(config, true); err != nil {
		t.Fatalf("loading Caddy Layer4 test config: %v", err)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Logf("stopping Caddy after Tor e2e test: %v", err)
		}
	})

	output, err := runOpenSSLSClient(t, opensslPath, port)
	if err != nil {
		t.Fatalf("openssl s_client failed: %v\n%s", err, tailString(output, 4000))
	}

	certs := parseOpenSSLCertificates(t, output)
	leaf := certs[0]
	if err := leaf.VerifyHostname(duckDuckGoServer); err != nil {
		t.Logf("leaf_hostname_check=%s invalid: %v", duckDuckGoServer, err)
	} else {
		t.Logf("leaf_hostname_check=%s valid", duckDuckGoServer)
	}
	logCertificateChain(t, certs)

	verifyResult, ok := opensslVerifyResult(output)
	if !ok {
		t.Fatalf("openssl output did not contain a verify result:\n%s", tailString(output, 4000))
	}
	t.Logf("openssl_verify_result=%s", verifyResult)
}

func torProxyCaddyfile(port int, torSOCKS string) string {
	return fmt.Sprintf(`{
	admin off
	persist_config off
	layer4 {
		127.0.0.1:%d {
			route {
				proxy {
					upstream %s {
						network_proxy socks5 {
							dial %s
						}
					}
				}
			}
		}
	}
}
`, port, duckDuckGoOnion, torSOCKS)
}

func adaptCaddyfile(t *testing.T, rawConfig string) []byte {
	t.Helper()

	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("caddyfile config adapter is not registered")
	}

	config, warnings, err := adapter.Adapt([]byte(rawConfig), nil)
	for _, warning := range warnings {
		t.Logf("caddyfile warning: line=%d directive=%s message=%s", warning.Line, warning.Directive, warning.Message)
	}
	if err != nil {
		t.Fatalf("adapting Caddyfile config: %v", err)
	}
	return config
}

func preflightTorSOCKS(t *testing.T, rawAddress string) {
	t.Helper()

	network, address, err := torSOCKSDialTarget(rawAddress)
	if err != nil {
		t.Fatalf("invalid %s value %q: %v", torSOCKSEnv, rawAddress, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		t.Skipf("Tor SOCKS proxy is not reachable at %s (%s/%s): %v", rawAddress, network, address, err)
	}
	if err := conn.Close(); err != nil {
		t.Logf("closing Tor SOCKS preflight connection: %v", err)
	}
}

func torSOCKSDialTarget(rawAddress string) (string, string, error) {
	if strings.ContainsAny(rawAddress, " \t\r\n{}") {
		return "", "", errors.New("address must be a single Caddy network address token")
	}

	addr, err := caddy.ParseNetworkAddress(rawAddress)
	if err != nil {
		return "", "", err
	}
	switch addr.Network {
	case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
	default:
		return "", "", fmt.Errorf("network %q is not supported for SOCKS5", addr.Network)
	}
	if !caddy.IsUnixNetwork(addr.Network) && addr.StartPort == 0 {
		return "", "", errors.New("TCP SOCKS5 address requires a port")
	}
	return addr.Network, addr.JoinHostPort(0), nil
}

func reserveLocalTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving local TCP port: %v", err)
	}
	defer ln.Close()

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("reserved listener returned unexpected address type %T", ln.Addr())
	}
	return tcpAddr.Port
}

func runOpenSSLSClient(t *testing.T, opensslPath string, port int) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	connectAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cmd := exec.CommandContext(ctx, opensslPath, "s_client", "-connect", connectAddr, "-servername", duckDuckGoServer, "-showcerts")
	cmd.Stdin = strings.NewReader("")

	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(output), fmt.Errorf("timed out after 45s: %w", ctx.Err())
	}
	return string(output), err
}

func parseOpenSSLCertificates(t *testing.T, output string) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate
	rest := []byte(output)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing certificate from openssl output: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		t.Fatalf("openssl output did not contain certificates:\n%s", tailString(output, 4000))
	}
	return certs
}

func logCertificateChain(t *testing.T, certs []*x509.Certificate) {
	t.Helper()

	for i, cert := range certs {
		t.Logf("certificate[%d] subject=%q issuer=%q sans=%q", i, cert.Subject.String(), cert.Issuer.String(), certificateSANs(cert))
	}
}

func certificateSANs(cert *x509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}
	return sans
}

func opensslVerifyResult(output string) (string, bool) {
	match := opensslVerifyResultRE.FindStringSubmatch(output)
	if match == nil {
		return "", false
	}
	return match[1] + " (" + match[2] + ")", true
}

func tailString(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[len(s)-maxBytes:]
}

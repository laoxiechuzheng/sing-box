package tls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestServerNameAllowlistMatch(t *testing.T) {
	t.Parallel()
	allowlist, err := newServerNameAllowlist([]string{"iosapps.itunes.apple.com", " Apple.COM. ", "*.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	for serverName, want := range map[string]bool{
		"iosapps.itunes.apple.com":  true,
		"IOSAPPS.itunes.apple.com.": true,
		"apple.com":                 true,
		"www.apple.com":             false,
		"itunes.apple.com":          false,
		"a.example.org":             true,
		"a.b.example.org":           true,
		"example.org":               false,
		"badexample.org":            false,
		"":                          false,
	} {
		if got := allowlist.allows(serverName); got != want {
			t.Errorf("allows(%q) = %v, want %v", serverName, got, want)
		}
	}
}

func TestServerNameAllowlistRejectsInvalidEntries(t *testing.T) {
	t.Parallel()
	for _, entry := range []string{"", " ", "*.", "*", "a.*.com", "1.2.3.4", "::1", "a b.com", "a..com", "-a.com", "a.com/x", "a.com:443"} {
		if _, err := newServerNameAllowlist([]string{entry}); err == nil {
			t.Errorf("entry %q was accepted", entry)
		}
	}
	if allowlist, err := newServerNameAllowlist(nil); allowlist != nil || err != nil {
		t.Fatal("an empty allowlist must disable the check")
	}
}

func TestSTDServerServerNameAllowlist(t *testing.T) {
	t.Parallel()
	serverConfig, err := NewSTDServer(context.Background(), log.NewNOPFactory().NewLogger("test"), option.InboundTLSOptions{
		Enabled:             true,
		Insecure:            true,
		ServerNameAllowlist: []string{"iosapps.itunes.apple.com", "www.apple.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for serverName, allowed := range map[string]bool{
		"iosapps.itunes.apple.com": true,
		"www.apple.com":            true,
		"apple.com":                false,
		"evil.example.com":         false,
		"":                         false,
	} {
		err := stdServerHandshake(t, serverConfig, serverName)
		if allowed && err != nil {
			t.Errorf("server name %q was rejected: %v", serverName, err)
		} else if !allowed && err == nil {
			t.Errorf("server name %q completed the handshake", serverName)
		}
	}
}

func TestRealityServerRejectsServerNameAllowlist(t *testing.T) {
	t.Parallel()
	_, err := NewServerWithOptions(ServerOptions{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().NewLogger("test"),
		Options: option.InboundTLSOptions{
			Enabled:             true,
			ServerNameAllowlist: []string{"www.apple.com"},
			Reality:             &option.InboundRealityOptions{Enabled: true},
		},
	})
	if err == nil {
		t.Fatal("reality accepted server_name_allowlist")
	}
}

// stdServerHandshake runs a client that skips certificate verification, like
// a proxy client with skip-cert-verify enabled, against the server config.
func stdServerHandshake(t *testing.T, serverConfig ServerConfig, serverName string) error {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	server, err := serverConfig.Server(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	go func() {
		serverResult <- server.HandshakeContext(context.Background())
		_ = serverConn.Close()
	}()
	client := tls.Client(clientConn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	clientErr := client.HandshakeContext(context.Background())
	serverErr := <-serverResult
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

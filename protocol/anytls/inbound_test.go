package anytls

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
)

const (
	proxyV1IPv4 = "PROXY TCP4 203.0.113.9 198.51.100.8 54321 443\r\n"
	proxyV1IPv6 = "PROXY TCP6 2001:db8::9 2001:db8::8 54321 443\r\n"
	// V2 PROXY/STREAM, source port 54321, destination port 443.
	proxyV2IPv4 = "0d0a0d0a000d0a515549540a2111000ccb007109c6336408d43101bb"
	proxyV2IPv6 = "0d0a0d0a000d0a515549540a2121002420010db800000000000000000000000920010db8000000000000000000000008d43101bb"
)

func TestInboundProxyProtocol(t *testing.T) {
	tests := []struct {
		name           string
		proxyProtocol  bool
		acceptNoHeader bool
		header         []byte
		wantSource     string
	}{
		{name: "flags_off"},
		{name: "require_v1_ipv4", proxyProtocol: true, header: []byte(proxyV1IPv4), wantSource: "203.0.113.9:54321"},
		{name: "require_v1_ipv6", proxyProtocol: true, header: []byte(proxyV1IPv6), wantSource: "[2001:db8::9]:54321"},
		{name: "require_v2_ipv4", proxyProtocol: true, header: decodeProxyHeader(t, proxyV2IPv4), wantSource: "203.0.113.9:54321"},
		{name: "require_v2_ipv6", proxyProtocol: true, header: decodeProxyHeader(t, proxyV2IPv6), wantSource: "[2001:db8::9]:54321"},
		{name: "optional_v1", proxyProtocol: true, acceptNoHeader: true, header: []byte(proxyV1IPv4), wantSource: "203.0.113.9:54321"},
		{name: "optional_v2", proxyProtocol: true, acceptNoHeader: true, header: decodeProxyHeader(t, proxyV2IPv6), wantSource: "[2001:db8::9]:54321"},
		{name: "optional_no_header", proxyProtocol: true, acceptNoHeader: true},
		{name: "accept_no_header_alone", acceptNoHeader: true},
		{name: "accept_no_header_alone_v2", acceptNoHeader: true, header: decodeProxyHeader(t, proxyV2IPv4), wantSource: "203.0.113.9:54321"},
		{name: "v1_unknown", proxyProtocol: true, header: []byte("PROXY UNKNOWN\r\n")},
		{name: "v2_local", proxyProtocol: true, header: decodeProxyHeader(t, "0d0a0d0a000d0a515549540a20000000")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			inbound, router := newTestInbound(t, test.proxyProtocol, test.acceptNoHeader)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var peerSource string
			client, err := anytls.NewClient(ctx, anytls.ClientConfig{
				Password: "test-password",
				Logger:   log.NewNOPFactory().Logger(),
				DialOut: func(ctx context.Context) (net.Conn, error) {
					conn, err := dialTestTLS(ctx, inbound, test.header, &peerSource)
					return conn, err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			stream, err := client.CreateProxy(ctx, M.ParseSocksaddr("example.org:443"))
			if err != nil {
				t.Fatalf("authenticate AnyTLS and open stream: %v", err)
			}
			defer stream.Close()
			if err = stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err = stream.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var response [4]byte
			if _, err = io.ReadFull(stream, response[:]); err != nil {
				t.Fatalf("read AnyTLS echo: %v", err)
			}
			if string(response[:]) != "ping" {
				t.Fatalf("echo = %q, want ping", response)
			}
			select {
			case connection := <-router.connections:
				wantSource := test.wantSource
				if wantSource == "" {
					wantSource = peerSource
				}
				if got := connection.metadata.Source.String(); got != wantSource {
					t.Errorf("router source = %s, want %s", got, wantSource)
				}
				if got := connection.contextSource.String(); got != wantSource {
					t.Errorf("context source = %s, want %s", got, wantSource)
				}
				if connection.metadata.User != "test-user" || connection.metadata.Destination.String() != "example.org:443" {
					t.Errorf("unexpected authenticated route metadata: %+v", connection.metadata)
				}
			case <-ctx.Done():
				t.Fatal("AnyTLS stream did not reach router")
			}
		})
	}
}

func TestInboundProxyProtocolRejectsTLS(t *testing.T) {
	tests := []struct {
		name           string
		proxyProtocol  bool
		acceptNoHeader bool
		header         []byte
	}{
		{name: "required_header_missing", proxyProtocol: true},
		{name: "flags_off_v1", header: []byte(proxyV1IPv4)},
		{name: "flags_off_v2", header: decodeProxyHeader(t, proxyV2IPv4)},
		{name: "malformed_v1_address", proxyProtocol: true, acceptNoHeader: true, header: []byte("PROXY TCP4 invalid 198.51.100.8 54321 443\r\n")},
		{name: "malformed_v1_port", proxyProtocol: true, acceptNoHeader: true, header: []byte("PROXY TCP4 203.0.113.9 198.51.100.8 65536 443\r\n")},
		{name: "malformed_v2_version", proxyProtocol: true, acceptNoHeader: true, header: decodeProxyHeader(t, "0d0a0d0a000d0a515549540a3111000ccb007109c6336408d43101bb")},
		{name: "malformed_v2_length", proxyProtocol: true, acceptNoHeader: true, header: decodeProxyHeader(t, "0d0a0d0a000d0a515549540a21110000")},
		{name: "malformed_v2_transport", proxyProtocol: true, acceptNoHeader: true, header: decodeProxyHeader(t, "0d0a0d0a000d0a515549540a2113000ccb007109c6336408d43101bb")},
		{name: "unsupported_v2_datagram", proxyProtocol: true, acceptNoHeader: true, header: decodeProxyHeader(t, "0d0a0d0a000d0a515549540a2112000ccb007109c6336408d43101bb")},
		{name: "unsupported_v2_unspecified", proxyProtocol: true, acceptNoHeader: true, header: decodeProxyHeader(t, "0d0a0d0a000d0a515549540a21000000")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			inbound, router := newTestInbound(t, test.proxyProtocol, test.acceptNoHeader)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialTestTLS(ctx, inbound, test.header, nil)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("TLS handshake accepted a forbidden or malformed PROXY header")
			}
			if ctx.Err() != nil {
				t.Fatalf("server did not reject the connection promptly: %v", err)
			}
			assertNoTestRoute(t, router)
		})
	}
}

func TestInboundProxyProtocolTruncated(t *testing.T) {
	for name, header := range map[string][]byte{
		"v1": []byte("PROXY TCP4 203.0.113.9"),
		"v2": decodeProxyHeader(t, "0d0a0d0a000d0a515549540a2111000ccb007109"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inbound, router := newTestInbound(t, true, true)
			conn := dialTestTCP(t, inbound, 5*time.Second)
			if _, err := conn.Write(header); err != nil {
				t.Fatal(err)
			}
			if err := conn.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			assertTestConnectionClosed(t, conn)
			assertNoTestRoute(t, router)
		})
	}
}

func TestInboundProxyProtocolHeaderTimeout(t *testing.T) {
	for name, header := range map[string][]byte{
		"idle":       nil,
		"partial_v1": []byte("PROXY TCP4 203.0.113.9"),
		"partial_v2": decodeProxyHeader(t, "0d0a0d0a000d0a515549540a2111000ccb007109"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inbound, router := newTestInbound(t, true, true)
			// The server must close at its 10s header deadline, not this client deadline.
			conn := dialTestTCP(t, inbound, 13*time.Second)
			if _, err := conn.Write(header); err != nil {
				t.Fatal(err)
			}
			assertTestConnectionClosed(t, conn)
			assertNoTestRoute(t, router)
		})
	}
}

func TestOtherListenersStillRejectProxyProtocol(t *testing.T) {
	for _, options := range []option.ListenOptions{
		{ProxyProtocol: true},
		{ProxyProtocolAcceptNoHeader: true},
	} {
		inboundListener := listener.New(listener.Options{
			Context: context.Background(),
			Logger:  log.NewNOPFactory().Logger(),
			Listen:  options,
		})
		if _, err := inboundListener.ListenTCP(); err == nil {
			inboundListener.Close()
			t.Fatal("generic listener unexpectedly accepted PROXY protocol")
		}
	}
}

type testRoutedConnection struct {
	metadata      adapter.InboundContext
	contextSource M.Socksaddr
}

type testRouter struct {
	adapter.Router
	connections chan testRoutedConnection
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	var contextSource M.Socksaddr
	if contextMetadata := adapter.ContextFrom(ctx); contextMetadata != nil {
		contextSource = contextMetadata.Source
	}
	r.connections <- testRoutedConnection{metadata: metadata, contextSource: contextSource}
	var payload [4]byte
	if _, err := io.ReadFull(conn, payload[:]); err == nil {
		conn.Write(payload[:])
	}
	if onClose != nil {
		onClose(nil)
	}
}

func newTestInbound(t *testing.T, proxyProtocol, acceptNoHeader bool) (*Inbound, *testRouter) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	router := &testRouter{connections: make(chan testRoutedConnection, 1)}
	instance, err := NewInbound(ctx, router, log.NewNOPFactory().Logger(), "anytls-in", option.AnyTLSInboundOptions{
		ListenOptions: option.ListenOptions{ProxyProtocol: proxyProtocol, ProxyProtocolAcceptNoHeader: acceptNoHeader},
		Users:         []option.AnyTLSUser{{Name: "test-user", Password: "test-password"}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true, Insecure: true},
		},
	})
	if err != nil {
		t.Fatalf("construct AnyTLS inbound: %v", err)
	}
	inbound := instance.(*Inbound)
	t.Cleanup(func() { inbound.Close() })
	if err = inbound.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("start AnyTLS inbound: %v", err)
	}
	return inbound, router
}

func dialTestTLS(ctx context.Context, inbound *Inbound, header []byte, peerSource *string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", inbound.listener.TCPListener().Addr().String())
	if err != nil {
		return nil, err
	}
	if peerSource != nil {
		*peerSource = conn.LocalAddr().String()
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if len(header) > 0 {
		if _, err = conn.Write(header); err != nil {
			conn.Close()
			return nil, err
		}
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "anytls.test"})
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func dialTestTCP(t *testing.T, inbound *Inbound, timeout time.Duration) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", inbound.listener.TCPListener().Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	return conn.(*net.TCPConn)
}

func assertTestConnectionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	var payload [1]byte
	n, err := conn.Read(payload[:])
	if n != 0 || err == nil {
		t.Fatalf("server did not close rejected connection: n=%d err=%v", n, err)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatalf("client timed out instead of server closing: %v", err)
	}
}

func assertNoTestRoute(t *testing.T, router *testRouter) {
	t.Helper()
	select {
	case connection := <-router.connections:
		t.Fatalf("rejected connection reached router: %+v", connection.metadata)
	default:
	}
}

func decodeProxyHeader(t *testing.T, header string) []byte {
	t.Helper()
	bytes, err := hex.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

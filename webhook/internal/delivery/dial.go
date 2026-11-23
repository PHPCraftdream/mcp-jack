package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/PHPCraftdream/mcp-jack/webhook/internal/ipaddr"
)

// Resolver resolves a name at delivery time.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(ctx context.Context, host string) ([]string, error)

func (f ResolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

// Dialer opens a TCP connection to one literal address.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialerFunc adapts a function to Dialer.
type DialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f DialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type dialKey struct{}

type dialTarget struct {
	decision  CheckResult
	host      string
	port      int
	connectBy time.Time
}

type pinnedDialer struct{ dialer Dialer }

func (d pinnedDialer) dial(ctx context.Context, network, authority string) (net.Conn, error) {
	target, ok := ctx.Value(dialKey{}).(dialTarget)
	port := strconv.Itoa(target.port)
	if !ok || network != "tcp" || authority != net.JoinHostPort(target.host, port) {
		return nil, &Error{Code: "connection_refused", Err: errors.New("dial target was not validated")}
	}
	ctx, cancel := context.WithDeadline(ctx, target.connectBy)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, networkError("connection_refused", err)
	}
	address := target.decision.Address
	conn, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(address, port))
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, networkError("connection_refused", err)
	}
	if conn == nil {
		return nil, &Error{Code: "connection_refused", Err: errors.New("dialer returned no connection")}
	}
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, networkError("connection_refused", err)
	}
	if !peerMatches(conn.RemoteAddr(), address) {
		_ = conn.Close()
		return nil, &Error{Code: "dns_rebinding", Reason: "peer_mismatch"}
	}
	return conn, nil
}

func peerMatches(peer net.Addr, address string) bool {
	expected, ok := ipaddr.ParseAddress(address)
	if !ok || peer == nil {
		return false
	}
	// The socket may report an IPv4-mapped address as plain IPv4.
	if tcp, ok := peer.(*net.TCPAddr); ok {
		return tcp != nil && tcp.IP.Equal(net.IP(expected.Bytes))
	}
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		return false
	}
	actual, ok := ipaddr.ParseAddress(host)
	return ok && net.IP(actual.Bytes).Equal(net.IP(expected.Bytes))
}

func (d pinnedDialer) dialTLS(ctx context.Context, network, authority string) (net.Conn, error) {
	conn, err := d.dial(ctx, network, authority)
	if err != nil {
		return nil, err
	}
	target := ctx.Value(dialKey{}).(dialTarget)
	// Go requires ServerName for automatic certificate verification, including
	// IP SANs. A literal ServerName is used for verification but never sent as SNI.
	serverName := target.decision.SNI
	if !target.decision.UsesSNI {
		serverName = target.decision.Address
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
	ctx, cancel := context.WithDeadline(ctx, target.connectBy)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, networkError("tls_error", err)
	}
	return tlsConn, nil
}

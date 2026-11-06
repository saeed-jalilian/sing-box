//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// realityHelloRecorder records the groups offered by the ClientHellos that reached the
// handshake target
type realityHelloRecorder struct {
	groups chan []tls.CurveID
}

func startRealityTarget(t *testing.T) (string, *realityHelloRecorder) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	recorder := &realityHelloRecorder{groups: make(chan []tls.CurveID, 16)}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			recorder.groups <- hello.SupportedCurves
			return nil, nil
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()
	return listener.Addr().String(), recorder
}

// A REALITY client offering the hybrid key share still completes the handshake and authenticates
// (the auth key comes from the X25519 share), and the ClientHello reaches the handshake target
// with X25519MLKEM768 offered.
func TestRealityClientHandshakeWithHybridKeyShare(t *testing.T) {
	privateKey := make([]byte, 32)
	_, err := rand.Read(privateKey)
	require.NoError(t, err)
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	require.NoError(t, err)

	for _, fingerprint := range []string{"chrome", "firefox", "safari", "ios", "edge"} {
		t.Run(fingerprint, func(t *testing.T) {
			target, recorder := startRealityTarget(t)
			serverConfig := &utls.RealityConfig{
				Type:        "tcp",
				Dest:        target,
				ServerNames: map[string]bool{"example.com": true},
				PrivateKey:  privateKey,
				ShortIds:    map[[8]byte]bool{{1, 2, 3, 4, 5, 6, 7, 8}: true},
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			}
			serverConfig.SessionTicketsDisabled = true
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer conn.Close()
				tlsConn, err := utls.RealityServer(context.Background(), conn, serverConfig)
				if err != nil {
					serverDone <- err
					return
				}
				_, err = io.Copy(tlsConn, tlsConn)
				_ = err
				serverDone <- nil
			}()

			clientConfig, err := NewRealityClient(context.Background(), nil, "example.com", option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
				UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
					ShortID:   "0102030405060708",
				},
			})
			require.NoError(t, err)
			raw, err := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, err)
			defer raw.Close()
			conn, err := clientConfig.(*RealityClientConfig).ClientHandshake(context.Background(), raw)
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.Write([]byte("hello"))
			require.NoError(t, err)
			buffer := make([]byte, 5)
			_, err = io.ReadFull(conn, buffer)
			require.NoError(t, err)
			require.Equal(t, "hello", string(buffer))
			conn.Close()
			select {
			case groups := <-recorder.groups:
				require.Contains(t, groups, tls.X25519MLKEM768)
			case <-time.After(5 * time.Second):
				t.Fatal("the handshake target saw no ClientHello")
			}
		})
	}
}

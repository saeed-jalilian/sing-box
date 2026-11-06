//go:build with_utls

package tls

import (
	"net"
	"testing"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// fingerprints with a TLS 1.3 X25519 key share; REALITY cannot use the others (360, Android OkHttp, ...)
func realityTestHelloIDs() []utls.ClientHelloID {
	return []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloSafari_Auto,
		utls.HelloIOS_Auto,
		utls.HelloEdge_Auto,
	}
}

// the X25519MLKEM768 key share comes before X25519 (Xray-core v26.9.8+ rejects any other hello)
// and the share of X25519, which the auth key is derived from, is still there with its key
func TestRealityHelloOffersHybridKeyShare(t *testing.T) {
	for _, id := range realityTestHelloIDs() {
		t.Run(id.Str(), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			uConn, err := newRealityUClient(client, &utls.Config{ServerName: "example.com"}, id)
			require.NoError(t, err)
			require.NoError(t, uConn.BuildHandshakeState())

			var hybrid, x25519 = -1, -1
			var curveHybrid, curveX25519 = -1, -1
			for _, extension := range uConn.Extensions {
				switch extension := extension.(type) {
				case *utls.KeyShareExtension:
					for index, share := range extension.KeyShares {
						switch share.Group {
						case utls.X25519MLKEM768:
							hybrid = index
							require.Len(t, share.Data, 1184+32)
						case utls.X25519:
							x25519 = index
							require.Len(t, share.Data, 32)
						}
					}
				case *utls.SupportedCurvesExtension:
					for index, curve := range extension.Curves {
						switch curve {
						case utls.X25519MLKEM768:
							curveHybrid = index
						case utls.X25519:
							curveX25519 = index
						}
					}
				}
			}
			require.NotEqual(t, -1, x25519, "no X25519 key share")
			require.NotEqual(t, -1, hybrid, "no X25519MLKEM768 key share")
			require.Less(t, hybrid, x25519)
			require.NotEqual(t, -1, curveX25519, "no X25519 supported group")
			require.NotEqual(t, -1, curveHybrid, "no X25519MLKEM768 supported group")
			require.Less(t, curveHybrid, curveX25519)

			keys := uConn.HandshakeState.State13.KeyShareKeys
			require.NotNil(t, keys)
			require.NotNil(t, keys.Ecdhe, "no X25519 key for the REALITY auth key")
		})
	}
}

func TestRealityHelloRandomized(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	uConn, err := newRealityUClient(client, &utls.Config{ServerName: "example.com"}, utls.HelloRandomized)
	require.NoError(t, err)
	require.NoError(t, uConn.BuildHandshakeState())
}

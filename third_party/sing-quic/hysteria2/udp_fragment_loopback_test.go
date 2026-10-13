package hysteria2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/tls"
)

const loopbackUDPMTU = 1200 - 3

const loopbackPacketSize = 1300

func loopbackServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{certificate}}
}

func loopbackPayloadByte(round uint32, sequence uint16, index int) byte {
	return byte(int(round)*31 + int(sequence)*7 + index)
}

type burstServer struct{}

func (burstServer) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return errors.New("unexpected TCP request")
}

func (burstServer) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	defer conn.Close()
	for {
		request := buf.NewPacket()
		destination, err := conn.ReadPacket(request)
		if err != nil {
			request.Release()
			return err
		}
		if request.Len() < 6 {
			request.Release()
			continue
		}
		round := binary.BigEndian.Uint32(request.Bytes())
		burst := binary.BigEndian.Uint16(request.Bytes()[4:])
		request.Release()
		for sequence := uint16(0); sequence < burst; sequence++ {
			reply := buf.NewSize(loopbackPacketSize)
			payload := reply.Extend(loopbackPacketSize)
			binary.BigEndian.PutUint32(payload, round)
			binary.BigEndian.PutUint16(payload[4:], sequence)
			for i := 6; i < len(payload); i++ {
				payload[i] = loopbackPayloadByte(round, sequence, i)
			}
			if err := conn.WritePacket(reply, destination); err != nil {
				return err
			}
		}
	}
}

func TestFragmentedUDPCrossesTheTunnelWholeAndInOrder(t *testing.T) {
	const (
		rounds = 200
		burst  = 16
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService[string](ServiceOptions{
		Context:    ctx,
		Logger:     logger.NOP(),
		TLSConfig:  loopbackServerTLS(t),
		Handler:    burstServer{},
		UDPTimeout: time.Minute,
		UdpMTU:     loopbackUDPMTU,
	})
	if err != nil {
		t.Fatal(err)
	}
	service.UpdateUsers([]string{"user"}, []string{"password"})
	if err := service.Start(listener); err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	client, err := NewClient(ClientOptions{
		Context:       ctx,
		Logger:        logger.NOP(),
		ServerAddress: M.SocksaddrFromNet(listener.LocalAddr()),
		Password:      "password",
		TLSConfig:     &tls.Config{ServerName: "localhost", InsecureSkipVerify: true},
		UdpMTU:        loopbackUDPMTU,
		PacketListener: qtls.PacketDialerFunc(func(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
			return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}),
		QuicDialer: qtls.QuicDialerFunc(func(ctx context.Context, addr string, packetDialer qtls.PacketDialer, tlsConfig *tls.Config, quicConfig *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
			serverAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, nil, err
			}
			packetConn, err := packetDialer.ListenPacket(ctx, "udp", addr, serverAddr.AddrPort())
			if err != nil {
				return nil, nil, err
			}
			var quicConn *quic.Conn
			if early {
				quicConn, err = quic.DialEarly(ctx, packetConn, serverAddr, tlsConfig, quicConfig)
			} else {
				quicConn, err = quic.Dial(ctx, packetConn, serverAddr, tlsConfig, quicConfig)
			}
			if err != nil {
				packetConn.Close()
				return nil, nil, err
			}
			return packetConn, quicConn, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(errors.New("test finished"))

	packetConn, err := client.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	request := make([]byte, loopbackPacketSize)
	reply := make([]byte, loopbackPacketSize*2)
	for round := uint32(0); round < rounds; round++ {
		binary.BigEndian.PutUint32(request, round)
		binary.BigEndian.PutUint16(request[4:], burst)
		if _, err := packetConn.WriteTo(request, target); err != nil {
			t.Fatalf("round %d: send request: %v", round, err)
		}
		for sequence := uint16(0); sequence < burst; sequence++ {
			if err := packetConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			n, _, err := packetConn.ReadFrom(reply)
			if err != nil {
				t.Fatalf("round %d: received %d of %d packets: %v", round, sequence, burst, err)
			}
			if n != loopbackPacketSize {
				t.Fatalf("round %d packet %d: %d bytes, want %d", round, sequence, n, loopbackPacketSize)
			}
			gotRound := binary.BigEndian.Uint32(reply)
			gotSequence := binary.BigEndian.Uint16(reply[4:])
			if gotRound != round || gotSequence != sequence {
				t.Fatalf("round %d: packet %d arrived as round %d packet %d; packets were lost or reordered", round, sequence, gotRound, gotSequence)
			}
			for i := 6; i < n; i++ {
				if reply[i] != loopbackPayloadByte(round, sequence, i) {
					t.Fatalf("round %d packet %d: byte %d corrupted", round, sequence, i)
				}
			}
		}
	}
}

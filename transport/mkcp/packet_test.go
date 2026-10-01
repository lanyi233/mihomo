package mkcp

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"io"
	"testing"
)

func packetTestSecurity(t testing.TB, mode string) cipher.AEAD {
	t.Helper()
	if mode == "plain" {
		return nil
	}
	cfg := Config{}
	if mode == "aes" {
		cfg.Seed = "packet-test"
	}
	security, err := cfg.security()
	if err != nil {
		t.Fatal(err)
	}
	return security
}

func TestPacketWriterSecurityAndHeaders(t *testing.T) {
	for _, mode := range []string{"plain", "simple", "aes"} {
		for _, header := range []string{"", "srtp", "utp", "wechat-video", "dtls", "wireguard"} {
			t.Run(mode+"/"+header, func(t *testing.T) {
				security := packetTestSecurity(t, mode)
				var wire bytes.Buffer
				writer := packetWriter{security: security, header: newPacketHeader(header), writer: &wire}
				reader := packetReader{security: security, header: newPacketHeader(header)}
				for _, size := range []int{0, 1, 2, 3, 4, 1200, 8192} {
					wire.Reset()
					payload := bytes.Repeat([]byte{byte(size)}, size)
					seg := &dataSegment{conv: 7, timestamp: 8, number: 9, sendingNext: 10, payload: payload}
					if err := writer.writeSegment(seg); err != nil {
						t.Fatal(err)
					}
					decoded := reader.read(wire.Bytes())
					if len(decoded) != 1 {
						t.Fatalf("size %d: decoded %d segments", size, len(decoded))
					}
					got, ok := decoded[0].(*dataSegment)
					if !ok || got.conv != seg.conv || got.timestamp != seg.timestamp || got.number != seg.number || got.sendingNext != seg.sendingNext || !bytes.Equal(got.payload, payload) {
						t.Fatalf("size %d: segment round trip changed data", size)
					}
				}
			})
		}
	}
}

func BenchmarkPacketWriter(b *testing.B) {
	for _, mode := range []string{"plain", "simple", "aes"} {
		for _, size := range []int{16, 1200} {
			b.Run(fmt.Sprintf("%s/%d", mode, size), func(b *testing.B) {
				writer := packetWriter{security: packetTestSecurity(b, mode), writer: io.Discard}
				seg := &dataSegment{conv: 1, payload: make([]byte, size)}
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if err := writer.writeSegment(seg); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

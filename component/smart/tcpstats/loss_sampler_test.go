package tcpstats

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLossSamplerConsumesEachSocketWindowOnce(t *testing.T) {
	s := NewLossSampler()
	require.Nil(t, s.Consume(1, &Stats{SegsOut: 32, RetransSegs: 4}))
	require.Equal(t, &Stats{SegsOut: 64, RetransSegs: 8}, s.Consume(1, &Stats{SegsOut: 64, RetransSegs: 8}))
	// Multiple logical connections sharing one socket must not confirm the same loss twice.
	require.Nil(t, s.Consume(1, &Stats{SegsOut: 64, RetransSegs: 8}))
	require.Nil(t, s.Consume(1, &Stats{SegsOut: 96, RetransSegs: 12}))
	require.Equal(t, &Stats{SegsOut: 64, RetransSegs: 8}, s.Consume(1, &Stats{SegsOut: 128, RetransSegs: 16}))
	// Another socket has an independent window; a recycled socket starts fresh.
	require.Equal(t, &Stats{SegsOut: 64, RetransSegs: 8}, s.Consume(2, &Stats{SegsOut: 64, RetransSegs: 8}))
	require.Equal(t, &Stats{SegsOut: 64, RetransSegs: 2}, s.Consume(1, &Stats{SegsOut: 64, RetransSegs: 2}))
}

func TestLossSamplerAccumulatesByteCounters(t *testing.T) {
	s := NewLossSampler()
	require.Nil(t, s.Consume(1, &Stats{BytesSent: 32 << 10, BytesRetrans: 1024}))
	require.Equal(t, &Stats{BytesSent: 64 << 10, BytesRetrans: 2048}, s.Consume(1, &Stats{BytesSent: 64 << 10, BytesRetrans: 2048}))
	require.Nil(t, s.Consume(1, &Stats{BytesSent: 64 << 10, BytesRetrans: 2048}))
}

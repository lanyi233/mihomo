package memory

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryInfoInvalidPID(t *testing.T) {
	info, err := GetMemoryInfo(-1)
	require.Error(t, err)
	require.Nil(t, info)
}

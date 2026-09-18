//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func countMapEntries(fd int, keySize uintptr, maxEntries uint32) (uint32, error) {
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return 0, err
	}
	mapInstance, err := CiliumEBPF.NewMapFromFD(dupFD)
	if err != nil {
		return 0, err
	}
	defer mapInstance.Close()
	if keySize == 0 || keySize > uintptr(^uint(0)>>1) {
		return 0, errors.New("invalid BPF map key size")
	}
	var key any
	var count uint32
	for {
		// NextKeyBytes treats "start of iteration" as a literal nil `any`
		// interface value. A nil []byte boxed into that parameter is not the
		// same thing -- a typed nil is a non-nil interface in Go -- so passing
		// key directly on the first call makes the library try to marshal an
		// empty key instead of starting the iteration, failing with "doesn't
		// marshal to N bytes" before a single key is read.
		var next []byte
		var nextErr error
		if key == nil {
			next, nextErr = mapInstance.NextKeyBytes(nil)
		} else {
			next, nextErr = mapInstance.NextKeyBytes(key)
		}
		// End of iteration is reported either as ENOENT or as a nil key with
		// no error, depending on the map type.
		if errors.Is(nextErr, unix.ENOENT) || (nextErr == nil && next == nil) {
			return count, nil
		}
		if nextErr != nil {
			return 0, nextErr
		}
		if uintptr(len(next)) != keySize {
			return 0, errors.New("BPF map returned an unexpected key size")
		}
		count++
		if count > maxEntries {
			return count, nil
		}
		key = next
	}
}

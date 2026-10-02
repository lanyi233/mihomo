package tcpstats

import (
	"net"
	"reflect"
	"syscall"
)

// GetTCPStats unwraps the connection wrappers until a socket is found; nil means the
// counters are not available for this connection.
func GetTCPStats(conn net.Conn) *Stats {
	// one slot per unwrap step, the range is bounded by the array so a cycle cannot spin
	var seen [32]uintptr
outer:
	for depth := 0; depth < len(seen); depth++ {
		if rv := reflect.ValueOf(conn); rv.Kind() == reflect.Ptr {
			ptr := rv.Pointer()
			for i := 0; i < depth; i++ {
				if seen[i] == ptr {
					return nil
				}
			}
			seen[depth] = ptr
		}

		if sc, ok := conn.(interface {
			SyscallConn() (syscall.RawConn, error)
		}); ok {
			rawConn, err := sc.SyscallConn()
			if err != nil {
				return nil
			}
			return readTCPStats(rawConn)
		}
		if u, ok := conn.(interface{ Upstream() any }); ok {
			if next, ok2 := u.Upstream().(net.Conn); ok2 {
				conn = next
				continue outer
			}
			// fall through to other unwrap methods
		}
		if nc, ok := conn.(interface{ NetConn() net.Conn }); ok {
			conn = nc.NetConn()
			continue outer
		}
		{
			v := reflect.ValueOf(conn)
			if v.Kind() == reflect.Ptr {
				v = v.Elem()
			}
			if v.Kind() == reflect.Struct {
				t := v.Type()
				for i := 0; i < v.NumField(); i++ {
					f := v.Field(i)
					if !t.Field(i).IsExported() || !f.CanInterface() {
						continue
					}
					if inner, ok := f.Interface().(net.Conn); ok {
						conn = inner
						continue outer
					}
				}
			}
		}
		return nil
	}
	return nil
}

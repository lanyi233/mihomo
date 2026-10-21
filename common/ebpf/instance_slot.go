//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Several sing-ebpf instances, in one process or in several, may share an
// interface, a cgroup or the policy-routing database. Kernel state that has to
// be told apart per instance (clsact filter names and handles, policy-routing
// identifiers, cgroup program names) is keyed by a slot number, and a slot is
// owned by holding an abstract unix socket bound to the slot's name.
//
// The kernel releases the binding when the owner exits, however it exits, so
// holding a slot is also the proof that state an earlier holder left under the
// slot's names is stale and may be reclaimed. Abstract socket names belong to a
// network namespace, which is the scope of every interface, route, rule and
// sysctl coordinated this way.
const MaxInstanceSlots = 16

// ErrInstanceSlotsExhausted reports that every slot of a shared resource is
// held by a live sing-ebpf instance.
var ErrInstanceSlotsExhausted = errors.New("every sing-ebpf instance slot is in use")

// InstanceSlot is one held slot of a shared resource.
type InstanceSlot struct {
	connection *net.UnixConn
	index      int
}

// Index is the slot number, which keys this instance's kernel state on the
// shared resource. Slot 0 keeps the names and identifiers that sing-ebpf used
// before multi-instance attachment, so it also excludes older builds.
func (s *InstanceSlot) Index() int {
	if s == nil {
		return 0
	}
	return s.index
}

func (s *InstanceSlot) Close() error {
	if s == nil || s.connection == nil {
		return nil
	}
	if err := s.connection.Close(); err != nil {
		return err
	}
	s.connection = nil
	return nil
}

// AcquireInstanceSlot binds the first free slot name. name(0) must be the name
// older builds used for their exclusive lock on the same resource.
func AcquireInstanceSlot(name func(slot int) string) (*InstanceSlot, error) {
	for slot := range MaxInstanceSlots {
		connection, err := bindAbstractSocket(name(slot))
		if err == nil {
			return &InstanceSlot{connection: connection, index: slot}, nil
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			return nil, err
		}
	}
	return nil, ErrInstanceSlotsExhausted
}

// InstanceSlotName returns base for slot 0 and base/slot otherwise.
func InstanceSlotName(base string, slot int) string {
	if slot == 0 {
		return base
	}
	return base + "/" + strconv.Itoa(slot)
}

// instanceMutexRetry is the interval between attempts to take a busy mutex.
const instanceMutexRetry = 5 * time.Millisecond

// DefaultInstanceMutexTimeout bounds how long a short critical section shared
// with other instances may be waited for. The holders only run a few netlink
// or sysctl operations, and a holder that dies releases the mutex with it.
const DefaultInstanceMutexTimeout = 5 * time.Second

// AcquireInstanceMutex serializes a short critical section across every
// sing-ebpf instance in the network namespace.
func AcquireInstanceMutex(name string, timeout time.Duration) (io.Closer, error) {
	deadline := time.Now().Add(timeout)
	for {
		connection, err := bindAbstractSocket("@sing-ebpf-mutex/" + name)
		if err == nil {
			return connection, nil
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			return nil, E.Cause(err, "lock sing-ebpf ", name)
		}
		if !time.Now().Before(deadline) {
			return nil, E.Cause(err, "lock sing-ebpf ", name, ": held by another instance for more than ", timeout)
		}
		time.Sleep(instanceMutexRetry)
	}
}

// InstanceLease is a named claim that other instances can enumerate. Leases
// carry the information a later holder needs once the instance that recorded
// it has gone, for example the value a shared sysctl has to be restored to.
type InstanceLease struct {
	connection *net.UnixConn
	value      string
}

func (l *InstanceLease) Value() string {
	if l == nil {
		return ""
	}
	return l.value
}

func (l *InstanceLease) Close() error {
	if l == nil || l.connection == nil {
		return nil
	}
	if err := l.connection.Close(); err != nil {
		return err
	}
	l.connection = nil
	return nil
}

func instanceLeasePrefix(key string) string {
	return "@sing-ebpf-lease/" + key + "/"
}

// AcquireInstanceLease publishes a claim on key carrying value. value must not
// contain '/'.
func AcquireInstanceLease(key string, value string) (*InstanceLease, error) {
	if strings.Contains(value, "/") || value == "" {
		return nil, E.New("invalid sing-ebpf lease value ", strconv.Quote(value))
	}
	// A process ID is not unique across PID namespaces that share a network
	// namespace, so the name carries a random nonce.
	var connection *net.UnixConn
	var err error
	for range 4 {
		var nonce [8]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, E.Cause(err, "publish sing-ebpf lease ", key)
		}
		connection, err = bindAbstractSocket(instanceLeasePrefix(key) + value + "/" + hex.EncodeToString(nonce[:]))
		if !errors.Is(err, unix.EADDRINUSE) {
			break
		}
	}
	if err != nil {
		return nil, E.Cause(err, "publish sing-ebpf lease ", key)
	}
	return &InstanceLease{connection: connection, value: value}, nil
}

// InstanceLeaseValues lists the values of the live leases on key, excluding
// own. The caller must hold the key's instance mutex for the answer to stay
// true while it acts on it.
func InstanceLeaseValues(key string, own *InstanceLease) ([]string, error) {
	var ownName string
	if own != nil && own.connection != nil {
		if address, loaded := own.connection.LocalAddr().(*net.UnixAddr); loaded {
			ownName = abstractSocketDisplayName(address.Name)
		}
	}
	names, err := listAbstractSocketNames(instanceLeasePrefix(key))
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(names))
	for _, name := range names {
		if name == ownName {
			continue
		}
		rest := strings.TrimPrefix(name, instanceLeasePrefix(key))
		value, _, found := strings.Cut(rest, "/")
		if !found || value == "" {
			continue
		}
		values = append(values, value)
	}
	return values, nil
}

func bindAbstractSocket(name string) (*net.UnixConn, error) {
	return net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
}

// abstractSocketDisplayName converts a Go abstract address, which starts with
// '@' or NUL depending on where it came from, to the form /proc/net/unix uses.
func abstractSocketDisplayName(name string) string {
	if strings.HasPrefix(name, "\x00") {
		return "@" + name[1:]
	}
	return name
}

// procNetUnixPaths puts the calling thread's view first. /proc/net follows the
// thread group leader, whose network namespace differs from the caller's when
// only the calling thread entered another one; thread-self needs Linux 3.17.
var procNetUnixPaths = []string{"/proc/thread-self/net/unix", "/proc/net/unix"}

// listAbstractSocketNames returns the bound abstract socket names in the
// caller's network namespace that start with prefix, in /proc/net/unix form.
func listAbstractSocketNames(prefix string) ([]string, error) {
	var openErr error
	for _, path := range procNetUnixPaths {
		file, err := os.Open(path)
		if err != nil {
			openErr = E.Errors(openErr, err)
			continue
		}
		defer file.Close()
		return parseAbstractSocketNames(file, prefix)
	}
	return nil, E.Cause(openErr, "list sing-ebpf instance leases")
}

func parseAbstractSocketNames(reader io.Reader, prefix string) ([]string, error) {
	var names []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	header := true
	for scanner.Scan() {
		if header {
			header = false
			continue
		}
		// Num RefCount Protocol Flags Type St Inode [Path]. Every listed name
		// was written by sing-ebpf and contains no whitespace.
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		name := fields[7]
		if !strings.HasPrefix(name, prefix) || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	if err := scanner.Err(); err != nil {
		return nil, E.Cause(err, "list sing-ebpf instance leases")
	}
	return names, nil
}

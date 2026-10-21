//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// requireOwnerMarkingHelper skips where cgroup programs of programType cannot
// call bpf_get_current_pid_tgid, as on Linux 4.19 and 5.4. The
// marking hooks then do not load and AttachCgroup keeps userspace
// registration, which TestSelfBypassFallsBackWhenHooksMarkNothing covers.
func requireOwnerMarkingHelper(t *testing.T, programType CiliumEBPF.ProgramType) {
	t.Helper()
	if err := features.HaveProgramHelper(programType, asm.FnGetCurrentPidTgid); err != nil {
		t.Skipf("%s programs cannot read the current thread group: %v", programType, err)
	}
}

const selfBypassHelperEnv = "SING_EBPF_SELF_BYPASS_HELPER"

// The marking programs compare initial-namespace TGIDs. Tests may run in a
// nested PID namespace (including WSL), so read the kernel id solely for the
// fixture; production must still fall back when that namespace is detected.
func integrationSelfBypassOwner(t *testing.T) uint32 {
	t.Helper()
	if owner, err := selfBypassOwnerTGID(); err == nil {
		return owner
	}
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Type:    CiliumEBPF.SocketFilter,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.FnGetCurrentPidTgid.Call(),
			asm.RSh.Imm(asm.R0, 32),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	owner, _, err := program.Test(make([]byte, 14))
	if err != nil || owner == 0 || owner > math.MaxInt32 {
		t.Fatalf("read kernel TGID for fixture: owner=%d error=%v", owner, err)
	}
	return owner
}

func overrideSelfBypassOwner(t *testing.T, owner func() (uint32, error)) {
	t.Helper()
	previous := selfBypassOwner
	selfBypassOwner = owner
	t.Cleanup(func() { selfBypassOwner = previous })
}

// TestSelfBypassHelperProcess is the child process of the self-bypass
// integration tests, not a test of its own. For every input line it creates a
// UDP socket, connects it to the loopback discard port when the line is
// "connect", and prints the socket cookie. Sockets stay open until exit.
func TestSelfBypassHelperProcess(t *testing.T) {
	if os.Getenv(selfBypassHelperEnv) != "1" {
		return
	}
	var sockets []int
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		cookie, fd, err := selfBypassTestSocket(scanner.Text() == "connect")
		if err == nil && scanner.Text() == "sendmsg" {
			err = unix.Sendto(fd, nil, 0, &unix.SockaddrInet4{Port: selfBypassProbePort, Addr: [4]byte{127, 0, 0, 1}})
		}
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		sockets = append(sockets, fd)
		fmt.Println(cookie)
	}
	for _, fd := range sockets {
		_ = unix.Close(fd)
	}
	os.Exit(0)
}

func selfBypassTestSocket(connect bool) (uint64, int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, -1, err
	}
	if connect {
		err = unix.Connect(fd, &unix.SockaddrInet4{Port: selfBypassProbePort, Addr: [4]byte{127, 0, 0, 1}})
	}
	var cookie uint64
	if err == nil {
		cookie, err = unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	}
	if err != nil {
		_ = unix.Close(fd)
		return 0, -1, err
	}
	return cookie, fd, nil
}

type selfBypassTestHelper struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

// startSelfBypassTestHelper starts a child process that inherits the cgroup
// of the test process, like the sessions of an SSH server embedded in the
// consumer.
func startSelfBypassTestHelper(t *testing.T) *selfBypassTestHelper {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestSelfBypassHelperProcess$")
	command.Env = append(os.Environ(), selfBypassHelperEnv+"=1")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	helper := &selfBypassTestHelper{command: command, input: input, output: bufio.NewScanner(output)}
	t.Cleanup(func() {
		_ = helper.input.Close()
		_ = helper.command.Wait()
	})
	return helper
}

func (h *selfBypassTestHelper) cookie(t *testing.T, action string) uint64 {
	t.Helper()
	request := action + "\n"
	if _, err := io.WriteString(h.input, request); err != nil {
		t.Fatal(err)
	}
	if !h.output.Scan() {
		t.Fatalf("self-bypass helper exited: %v", h.output.Err())
	}
	line := strings.TrimSpace(h.output.Text())
	cookie, err := strconv.ParseUint(line, 10, 64)
	if err != nil {
		t.Fatalf("self-bypass helper: %s", line)
	}
	return cookie
}

func selfBypassMarked(t *testing.T, bypass *SelfBypass, cookie uint64) bool {
	t.Helper()
	var metadata uint32
	if err := bypass.sockets.Lookup(&cookie, &metadata); err != nil {
		if !errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
			t.Fatal(err)
		}
		return false
	}
	return metadata&SocketMetadataSelfBypass != 0
}

// TestSelfBypassCgroupMarksOnlyOwnerProcess reproduces a consumer that owns
// an exclusive cgroup and later starts child processes there. The hooks must
// keep excluding the consumer's own sockets while the children's sockets stay
// unmarked, so local interception still applies to them.
func TestSelfBypassCgroupMarksOnlyOwnerProcess(t *testing.T) {
	requireEBPFIntegration(t, "attach self-bypass hooks to an exclusive process cgroup")
	requireOwnerMarkingHelper(t, CiliumEBPF.CGroupSock)
	requireOwnerMarkingHelper(t, CiliumEBPF.CGroupSockAddr)
	owner := integrationSelfBypassOwner(t)
	overrideSelfBypassOwner(t, func() (uint32, error) { return owner, nil })
	enterDedicatedSelfBypassCgroup(t, 300)

	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	attachErr := bypass.AttachCgroup(SelfBypassCgroupConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true})
	if !bypass.CgroupAttached() {
		t.Fatalf("self-bypass hooks were not attached to the exclusive cgroup (mode %s): %v", bypass.Mode(), attachErr)
	}

	ownCookie, ownFD, err := selfBypassTestSocket(true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ownFD)
	if !selfBypassMarked(t, bypass, ownCookie) {
		t.Fatalf("socket of the owner process was not marked (mode %s)", bypass.Mode())
	}

	helper := startSelfBypassTestHelper(t)
	for _, action := range []string{"socket", "connect", "sendmsg"} {
		if cookie := helper.cookie(t, action); selfBypassMarked(t, bypass, cookie) {
			t.Fatalf("socket of a child process in the owner cgroup was marked (mode %s, action %s)", bypass.Mode(), action)
		}
	}
}

// TestSelfBypassSocketAddrHooksMarkOnlyOwnerProcess covers the connect/sendmsg
// fallback used on kernels without socket create/release hooks.
func TestSelfBypassSocketAddrHooksMarkOnlyOwnerProcess(t *testing.T) {
	requireEBPFIntegration(t, "attach self-bypass socket-address hooks")
	requireOwnerMarkingHelper(t, CiliumEBPF.CGroupSockAddr)
	owner := integrationSelfBypassOwner(t)
	path := enterDedicatedSelfBypassCgroup(t, 301)
	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	if err = bypass.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, config := range []SelfBypassCgroupConfig{
		{EnableTCP: true, EnableUDP: true, EnableIPv6: true},
		{EnableUDP: true},
	} {
		if err = bypass.attachCgroupSocketAddr(path, config, owner); err != nil {
			t.Fatalf("attach socket-address hooks %+v: %v", config, err)
		}
		if err = bypass.verifyOwnerMarking(true, config); err != nil {
			t.Fatalf("socket-address hooks %+v did not mark the owner: %v", config, err)
		}
		helper := startSelfBypassTestHelper(t)
		if config.EnableTCP {
			if cookie := helper.cookie(t, "connect"); selfBypassMarked(t, bypass, cookie) {
				t.Fatalf("connect of a child process was marked with %+v", config)
			}
		}
		if cookie := helper.cookie(t, "sendmsg"); selfBypassMarked(t, bypass, cookie) {
			t.Fatalf("sendmsg of a child process was marked with %+v", config)
		}
		if err = bypass.closeHooks(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSelfBypassFallsBackWhenHooksMarkNothing forces the owner check to
// reject this process. Hooks that would leave the consumer's own sockets
// unmarked must be removed so that userspace registration takes over.
func TestSelfBypassFallsBackWhenHooksMarkNothing(t *testing.T) {
	requireEBPFIntegration(t, "verify the self-bypass probe fallback")
	owner := integrationSelfBypassOwner(t)
	enterDedicatedSelfBypassCgroup(t, 302)
	overrideSelfBypassOwner(t, func() (uint32, error) { return owner + 1, nil })

	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	attachErr := bypass.AttachCgroup(SelfBypassCgroupConfig{EnableTCP: true, EnableUDP: true})
	// A successful release-only fallback returns no error, like any other
	// unavailable marking path; the effective mode is the diagnostic.
	if mode := bypass.Mode(); bypass.CgroupAttached() || (mode != SelfBypassUserspaceRelease && mode != SelfBypassUserspace) {
		t.Fatalf("hooks that mark nothing were kept (mode %s): %v", mode, attachErr)
	}
	cookie, fd, err := selfBypassTestSocket(true)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if selfBypassMarked(t, bypass, cookie) {
		t.Fatal("a removed hook still marked a socket")
	}
}

func TestSelfBypassUserspaceFallbackRegistersSocket(t *testing.T) {
	requireEBPFIntegration(t, "verify self-bypass registration without a safe owner TGID")
	enterDedicatedSelfBypassCgroup(t, 303)
	overrideSelfBypassOwner(t, func() (uint32, error) { return 0, errors.New("unsafe PID namespace") })
	bypass, err := NewSelfBypassWithCapacity(8)
	if err != nil {
		t.Fatal(err)
	}
	defer bypass.Close()
	attachErr := bypass.AttachCgroup(SelfBypassCgroupConfig{EnableTCP: true, EnableUDP: true})
	if bypass.CgroupAttached() {
		t.Fatalf("unsafe TGID enabled marking: %v", attachErr)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var cookie uint64
	var cookieErr error
	if err = raw.Control(func(fd uintptr) {
		cookie, cookieErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
	}); err != nil || cookieErr != nil {
		t.Fatalf("read socket cookie: %v, %v", err, cookieErr)
	}
	if selfBypassMarked(t, bypass, cookie) {
		t.Fatal("fallback socket was marked before registration")
	}
	if err = bypass.RegisterSocket(raw); err != nil || !selfBypassMarked(t, bypass, cookie) {
		t.Fatalf("userspace fallback failed to register socket: %v", err)
	}
}

func enterDedicatedSelfBypassCgroup(t *testing.T, index int) string {
	t.Helper()
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	original, err := DetectProcessCgroup2Path()
	if err != nil {
		t.Skipf("process cgroup v2 path is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, index)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	moveCurrentProcessToCgroup(t, path, original)
	return path
}

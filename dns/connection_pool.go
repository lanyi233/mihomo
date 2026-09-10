package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	D "github.com/miekg/dns"
)

const (
	dnsMaxOpenConnections = 32

	dnsStreamIdleTimeout = 90 * time.Second
	dnsStreamMaxLifetime = 10 * time.Minute

	dnsUDPIdleTimeout = 10 * time.Second
	dnsUDPMaxLifetime = 30 * time.Second
	dnsUDPMaxUses     = 32
)

var errInvalidDNSResponse = errors.New("invalid DNS response")

var newDNSQueryID = D.Id

type dnsConnectionPoolOptions struct {
	maxOpen     int
	maxIdle     int
	idleTimeout time.Duration
	maxLifetime time.Duration
	maxUses     uint32
}

type dnsConnectionPool struct {
	options dnsConnectionPoolOptions

	mu         sync.Mutex
	closed     bool
	state      *dnsConnectionPoolState
	timer      *time.Timer
	timerEpoch uint64
}

type dnsConnectionPoolState struct {
	ctx     context.Context
	cancel  context.CancelCauseFunc
	all     map[*dnsPooledConnection]struct{}
	idle    []*dnsPooledConnection
	dialing int
	waiters int
	notify  chan struct{}
}

type dnsPooledConnection struct {
	conn      net.Conn
	createdAt time.Time
	idleSince time.Time
	uses      uint32
}

type dnsConnectionLease struct {
	state      *dnsConnectionPoolState
	connection *dnsPooledConnection
	reused     bool
	released   atomic.Bool
}

func newDNSConnectionPool(options dnsConnectionPoolOptions) *dnsConnectionPool {
	return &dnsConnectionPool{
		options: options,
		state:   newDNSConnectionPoolState(),
	}
}

func newDNSConnectionPoolState() *dnsConnectionPoolState {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &dnsConnectionPoolState{
		ctx:    ctx,
		cancel: cancel,
		all:    make(map[*dnsPooledConnection]struct{}),
		notify: make(chan struct{}),
	}
}

func (p *dnsConnectionPool) acquire(ctx context.Context, dial func(context.Context) (net.Conn, error)) (*dnsConnectionLease, error) {
	return p.acquireInternal(ctx, dial, false)
}

func (p *dnsConnectionPool) acquireFresh(ctx context.Context, dial func(context.Context) (net.Conn, error)) (*dnsConnectionLease, error) {
	return p.acquireInternal(ctx, dial, true)
}

func (p *dnsConnectionPool) acquireInternal(ctx context.Context, dial func(context.Context) (net.Conn, error), fresh bool) (*dnsConnectionLease, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		state := p.state
		idleLen := len(state.idle)
		if !fresh && idleLen > 0 {
			connection := state.idle[idleLen-1]
			state.idle[idleLen-1] = nil
			state.idle = state.idle[:idleLen-1]
			if p.canReuseLocked(connection, time.Now()) {
				p.mu.Unlock()
				return &dnsConnectionLease{state: state, connection: connection, reused: true}, nil
			}
			delete(state.all, connection)
			p.mu.Unlock()
			_ = connection.conn.Close()
			continue
		}
		if fresh && idleLen > 0 && p.options.maxOpen > 0 && len(state.all)+state.dialing >= p.options.maxOpen {
			connection := state.idle[0]
			copy(state.idle, state.idle[1:])
			state.idle[len(state.idle)-1] = nil
			state.idle = state.idle[:len(state.idle)-1]
			delete(state.all, connection)
			p.signalLocked(state)
			p.mu.Unlock()
			_ = connection.conn.Close()
			continue
		}
		if p.options.maxOpen > 0 && len(state.all)+state.dialing >= p.options.maxOpen {
			notify := state.notify
			stateCtx := state.ctx
			state.waiters++
			p.mu.Unlock()
			var waitErr error
			select {
			case <-ctx.Done():
				waitErr = ctx.Err()
			case <-stateCtx.Done():
			case <-notify:
			}
			p.mu.Lock()
			state.waiters--
			p.mu.Unlock()
			if waitErr != nil {
				return nil, waitErr
			}
			continue
		}
		state.dialing++
		p.mu.Unlock()

		conn, err := p.dial(ctx, state, dial)
		if err != nil {
			p.mu.Lock()
			state.dialing--
			p.signalLocked(state)
			p.mu.Unlock()
			return nil, err
		}
		connection := &dnsPooledConnection{conn: conn, createdAt: time.Now()}

		p.mu.Lock()
		state.dialing--
		if p.closed || p.state != state {
			p.signalLocked(state)
			p.mu.Unlock()
			_ = conn.Close()
			return nil, net.ErrClosed
		}
		state.all[connection] = struct{}{}
		p.mu.Unlock()
		return &dnsConnectionLease{state: state, connection: connection}, nil
	}
}

func (p *dnsConnectionPool) dial(ctx context.Context, state *dnsConnectionPoolState, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	dialCtx, cancel := context.WithCancel(ctx)
	stopStateCancel := context.AfterFunc(state.ctx, cancel)
	conn, err := dial(dialCtx)
	stateCancelStopped := stopStateCancel()
	dialCtxErr := dialCtx.Err()
	cancel()
	if err == nil && dialCtxErr != nil {
		_ = conn.Close()
		err = dialCtxErr
	}
	if err == nil && !stateCancelStopped {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if cause := context.Cause(state.ctx); cause != nil {
			return nil, cause
		}
		return nil, err
	}
	return conn, nil
}

func (p *dnsConnectionPool) release(lease *dnsConnectionLease, reuse bool) {
	if lease == nil || lease.released.Swap(true) {
		return
	}
	connection := lease.connection
	now := time.Now()
	var closeConnections []*dnsPooledConnection

	p.mu.Lock()
	state := lease.state
	_, tracked := state.all[connection]
	if !tracked {
		p.mu.Unlock()
		return
	}
	connection.uses++
	if p.closed || p.state != state || !reuse || p.options.maxIdle <= 0 || !p.canReuseLocked(connection, now) {
		delete(state.all, connection)
		p.signalLocked(state)
		closeConnections = append(closeConnections, connection)
	} else {
		connection.idleSince = now
		state.idle = append(state.idle, connection)
		p.signalLocked(state)
		if len(state.idle) > p.options.maxIdle {
			evicted := state.idle[0]
			copy(state.idle, state.idle[1:])
			state.idle[len(state.idle)-1] = nil
			state.idle = state.idle[:len(state.idle)-1]
			delete(state.all, evicted)
			closeConnections = append(closeConnections, evicted)
		}
		p.scheduleTimerLocked(now)
	}
	p.mu.Unlock()

	for _, pooled := range closeConnections {
		_ = pooled.conn.Close()
	}
}

func (p *dnsConnectionPool) discard(lease *dnsConnectionLease) {
	p.release(lease, false)
}

func (p *dnsConnectionPool) canReuseLocked(connection *dnsPooledConnection, now time.Time) bool {
	if p.options.maxUses > 0 && connection.uses >= p.options.maxUses {
		return false
	}
	if p.options.maxLifetime > 0 && now.Sub(connection.createdAt) >= p.options.maxLifetime {
		return false
	}
	if !connection.idleSince.IsZero() && p.options.idleTimeout > 0 && now.Sub(connection.idleSince) >= p.options.idleTimeout {
		return false
	}
	return true
}

func (p *dnsConnectionPool) reset() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	oldState := p.state
	p.state = newDNSConnectionPoolState()
	p.stopTimerLocked()
	connections := make([]*dnsPooledConnection, 0, len(oldState.all))
	for connection := range oldState.all {
		connections = append(connections, connection)
	}
	p.mu.Unlock()

	oldState.cancel(net.ErrClosed)
	for _, connection := range connections {
		_ = connection.conn.Close()
	}
}

func (p *dnsConnectionPool) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	oldState := p.state
	p.state = nil
	p.stopTimerLocked()
	connections := make([]*dnsPooledConnection, 0, len(oldState.all))
	for connection := range oldState.all {
		connections = append(connections, connection)
	}
	p.mu.Unlock()

	oldState.cancel(net.ErrClosed)
	for _, connection := range connections {
		_ = connection.conn.Close()
	}
	return nil
}

func (p *dnsConnectionPool) idleCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == nil {
		return 0
	}
	return len(p.state.idle)
}

func (p *dnsConnectionPool) scheduleTimerLocked(now time.Time) {
	if p.timer != nil || p.state == nil || len(p.state.idle) == 0 {
		return
	}
	var delay time.Duration
	hasDeadline := false
	for _, connection := range p.state.idle {
		if p.options.idleTimeout > 0 {
			idleDelay := p.options.idleTimeout - now.Sub(connection.idleSince)
			if !hasDeadline || idleDelay < delay {
				delay = idleDelay
				hasDeadline = true
			}
		}
		if p.options.maxLifetime > 0 {
			lifetimeDelay := p.options.maxLifetime - now.Sub(connection.createdAt)
			if !hasDeadline || lifetimeDelay < delay {
				delay = lifetimeDelay
				hasDeadline = true
			}
		}
	}
	if !hasDeadline {
		return
	}
	if delay < 0 {
		delay = 0
	}
	p.timerEpoch++
	epoch := p.timerEpoch
	p.timer = time.AfterFunc(delay, func() { p.expireIdle(epoch) })
}

func (p *dnsConnectionPool) expireIdle(epoch uint64) {
	now := time.Now()
	var expired []*dnsPooledConnection
	p.mu.Lock()
	if p.timerEpoch != epoch || p.closed || p.state == nil {
		p.mu.Unlock()
		return
	}
	p.timer = nil
	state := p.state
	kept := state.idle[:0]
	for _, connection := range state.idle {
		if p.canReuseLocked(connection, now) {
			kept = append(kept, connection)
			continue
		}
		delete(state.all, connection)
		expired = append(expired, connection)
	}
	for index := len(kept); index < len(state.idle); index++ {
		state.idle[index] = nil
	}
	state.idle = kept
	if len(expired) > 0 {
		p.signalLocked(state)
	}
	p.scheduleTimerLocked(now)
	p.mu.Unlock()

	for _, connection := range expired {
		_ = connection.conn.Close()
	}
}

func (p *dnsConnectionPool) stopTimerLocked() {
	p.timerEpoch++
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

func (p *dnsConnectionPool) signalLocked(state *dnsConnectionPoolState) {
	if state.waiters == 0 {
		return
	}
	close(state.notify)
	state.notify = make(chan struct{})
}

func exchangeDNSConnection(ctx context.Context, request *D.Msg, lease *dnsConnectionLease) (*D.Msg, error) {
	conn := lease.connection.conn
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	client := &D.Client{UDPSize: 4096, Timeout: 5 * time.Second}
	dnsConn := &D.Conn{Conn: conn, UDPSize: client.UDPSize}
	response, _, err := client.ExchangeWithConnContext(ctx, request, dnsConn)
	stopped := stopCancel()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if !stopped {
		return nil, net.ErrClosed
	}
	if err != nil {
		return nil, err
	}
	if err = validateDNSResponse(request, response); err != nil {
		return nil, err
	}
	return response, nil
}

func exchangeDNSWithPool(
	ctx context.Context,
	request *D.Msg,
	pool *dnsConnectionPool,
	dial func(context.Context) (net.Conn, error),
	randomizeID bool,
) (*D.Msg, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var lease *dnsConnectionLease
		var err error
		if attempt == 0 {
			lease, err = pool.acquire(ctx, dial)
		} else {
			lease, err = pool.acquireFresh(ctx, dial)
		}
		if err != nil {
			return nil, err
		}
		wireRequest := request
		if randomizeID {
			wireCopy := *request
			wireRequest = &wireCopy
			if request.IsTsig() != nil {
				wireRequest = request.Copy()
			}
			wireRequest.Id = newDNSQueryID()
		}
		response, err := exchangeDNSConnection(ctx, wireRequest, lease)
		pool.release(lease, err == nil)
		if err == nil {
			response.Id = request.Id
			return response, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if !lease.reused {
			return nil, err
		}
	}
	return nil, net.ErrClosed
}

func validateDNSResponse(request, response *D.Msg) error {
	if request == nil || response == nil || !response.Response || response.Id != request.Id || response.Opcode != request.Opcode || len(response.Question) != len(request.Question) {
		return errInvalidDNSResponse
	}
	for index := range request.Question {
		requestQuestion := request.Question[index]
		responseQuestion := response.Question[index]
		if requestQuestion.Qtype != responseQuestion.Qtype || requestQuestion.Qclass != responseQuestion.Qclass || !equalDNSName(requestQuestion.Name, responseQuestion.Name) {
			return errInvalidDNSResponse
		}
	}
	return nil
}

func equalDNSName(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range len(left) {
		leftByte := left[index]
		rightByte := right[index]
		if leftByte >= 'A' && leftByte <= 'Z' {
			leftByte += 'a' - 'A'
		}
		if rightByte >= 'A' && rightByte <= 'Z' {
			rightByte += 'a' - 'A'
		}
		if leftByte != rightByte {
			return false
		}
	}
	return true
}

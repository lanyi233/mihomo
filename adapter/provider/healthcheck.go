package provider

import (
	"context"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/power"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/sync/errgroup"
)

type HealthCheckOption struct {
	URL      string
	Interval uint
}

var healthCheckClockStart = time.Now()

type extraOption struct {
	expectedStatus utils.IntRanges[uint16]
	filters        map[string]struct{}
}

type HealthCheck struct {
	ctx            context.Context
	ctxCancel      context.CancelFunc
	url            string
	extra          map[string]*extraOption
	extraTasks     []healthCheckTask
	mu             sync.RWMutex
	proxies        []C.Proxy
	proxyVersion   uint64
	interval       time.Duration
	lazy           bool
	expectedStatus utils.IntRanges[uint16]
	lastTouch      atomic.Int64
	singleDo       *singledo.Single[struct{}]
	coalesceWindow time.Duration
	timeout        time.Duration
	wake           chan struct{}
	trigger        chan struct{}
	automaticDone  chan uint64
	startMu        sync.Mutex
	started        bool
	closeOnce      sync.Once
	workMu         sync.Mutex
	workClosing    bool
	workWG         sync.WaitGroup
}

func (hc *HealthCheck) process() {
	interval := hc.checkInterval()
	if interval <= 0 {
		return
	}

	hc.startMu.Lock()
	if hc.started {
		hc.startMu.Unlock()
		return
	}
	hc.started = true
	hc.startMu.Unlock()

	if !hc.beginWork() {
		return
	}
	defer hc.finishWork()

	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	resetTimer := func(delay time.Duration) {
		if delay <= 0 {
			delay = time.Millisecond
		}
		stopTimer()
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		timerC = timer.C
	}
	defer stopTimer()

	paused, backgroundChanged := power.BackgroundState()
	startupPending := true
	forceLazyCheck := false
	forceAutomaticCheck := false
	automaticRunning := false
	var lastAutomaticDone time.Time

	reconcileBackground := func() (resumed bool) {
		wasPaused := paused
		paused, backgroundChanged = power.BackgroundState()
		if paused {
			stopTimer()
			return false
		}
		if !wasPaused {
			return false
		}

		if startupPending || forceAutomaticCheck || !hc.lazy || forceLazyCheck || hc.sinceLastTouch() < interval {
			resetTimer(healthCheckResumeDelay(interval))
		}
		return true
	}
	launchAutomatic := func() bool {
		if automaticRunning {
			return false
		}
		automaticRunning = true
		version := hc.currentProxyVersion()
		go func() {
			hc.check()
			select {
			case hc.automaticDone <- version:
			case <-hc.ctx.Done():
			}
		}()
		return true
	}
	coalesceDelay := func() time.Duration {
		if lastAutomaticDone.IsZero() {
			return 0
		}
		remaining := hc.coalesceWindow - time.Since(lastAutomaticDone)
		if remaining > 0 {
			return remaining
		}
		return 0
	}
	resetAfterCheck := func() {
		if !hc.lazy {
			resetTimer(interval)
		} else if forceLazyCheck || hc.sinceLastTouch() < interval {
			resetTimer(interval)
		}
	}

	if !paused {
		launchAutomatic()
		startupPending = false
		resetTimer(interval)
	}

	for {
		select {
		case <-hc.ctx.Done():
			return
		case <-hc.wake:
			if !hc.lazy {
				continue
			}
			forceLazyCheck = true
			resumed := reconcileBackground()
			if resumed {
				continue
			}
			if !paused && timerC == nil {
				resetTimer(interval)
			}
		case <-hc.trigger:
			forceAutomaticCheck = true
			resumed := reconcileBackground()
			if paused || resumed || automaticRunning {
				continue
			}
			if delay := coalesceDelay(); delay > 0 {
				resetTimer(delay)
				continue
			}
			if !launchAutomatic() {
				continue
			}
			forceAutomaticCheck = false
			if startupPending {
				startupPending = false
				resetTimer(interval)
			}
		case <-backgroundChanged:
			reconcileBackground()
		case version := <-hc.automaticDone:
			automaticRunning = false
			lastAutomaticDone = time.Now()
			forceAutomaticCheck = hc.currentProxyVersion() > version
			resumed := reconcileBackground()
			if forceAutomaticCheck && !paused && !resumed {
				resetTimer(coalesceDelay())
			} else if !paused && !resumed && timerC == nil {
				resetAfterCheck()
			}
		case <-timerC:
			timerC = nil
			resumed := reconcileBackground()
			if paused || resumed {
				continue
			}
			if startupPending {
				if launchAutomatic() {
					startupPending = false
					forceAutomaticCheck = false
				}
				resetAfterCheck()
				continue
			}
			if forceAutomaticCheck {
				if automaticRunning {
					continue
				}
				if delay := coalesceDelay(); delay > 0 {
					resetTimer(delay)
					continue
				}
				if launchAutomatic() {
					forceAutomaticCheck = false
				}
				resetAfterCheck()
				continue
			}
			if !hc.lazy {
				launchAutomatic()
				resetTimer(interval)
				continue
			}

			since := hc.sinceLastTouch()
			if !forceLazyCheck && since >= interval {
				log.Debugln("Stop health check timer because the provider is idle")
				continue
			}
			launchAutomatic()
			forceLazyCheck = false
			if since < interval {
				resetTimer(interval)
			}
		}
	}
}

func (hc *HealthCheck) setProxies(proxies []C.Proxy) {
	hc.mu.Lock()
	hc.proxies = append([]C.Proxy(nil), proxies...)
	hc.proxyVersion++
	hc.mu.Unlock()
}

func (hc *HealthCheck) registerHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	url = strings.TrimSpace(url)
	if len(url) == 0 || url == hc.url {
		log.Debugln("ignore invalid health check url: %s", url)
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	// if the provider has not set up health checks, then modify it to be the same as the group's interval
	if hc.interval == 0 {
		hc.interval = time.Duration(interval) * time.Second
	}

	if hc.extra == nil {
		hc.extra = make(map[string]*extraOption)
	}

	// prioritize the use of previously registered configurations, especially those from provider
	if existing, ok := hc.extra[url]; ok {
		// provider default health check does not set filter
		if url != hc.url && len(filter) != 0 {
			option := &extraOption{
				expectedStatus: existing.expectedStatus,
				filters:        make(map[string]struct{}, len(existing.filters)),
			}
			for existingFilter := range existing.filters {
				option.filters[existingFilter] = struct{}{}
			}
			splitAndAddFiltersToExtra(filter, option)
			hc.extra[url] = option
			hc.rebuildExtraTasksLocked()
		}

		log.Debugln("health check url: %s exists", url)
		return
	}

	option := &extraOption{
		filters:        map[string]struct{}{},
		expectedStatus: append(utils.IntRanges[uint16](nil), expectedStatus...),
	}
	splitAndAddFiltersToExtra(filter, option)
	hc.extra[url] = option
	hc.rebuildExtraTasksLocked()
}

func (hc *HealthCheck) rebuildExtraTasksLocked() {
	tasks := make([]healthCheckTask, 0, len(hc.extra))
	for url, option := range hc.extra {
		tasks = append(tasks, healthCheckTask{url: url, option: option})
	}
	hc.extraTasks = tasks
}

func splitAndAddFiltersToExtra(filter string, option *extraOption) {
	filter = strings.TrimSpace(filter)
	if len(filter) != 0 {
		for _, regex := range strings.Split(filter, "`") {
			regex = strings.TrimSpace(regex)
			if len(regex) != 0 {
				option.filters[regex] = struct{}{}
			}
		}
	}
}

func (hc *HealthCheck) auto() bool {
	return hc.checkInterval() != 0
}

func (hc *HealthCheck) touch() {
	if !hc.lazy {
		return
	}
	hc.lastTouch.Store(time.Since(healthCheckClockStart).Nanoseconds())
	select {
	case hc.wake <- struct{}{}:
	default:
	}
}

func (hc *HealthCheck) scheduleCheck() {
	select {
	case hc.trigger <- struct{}{}:
	default:
	}
}

func (hc *HealthCheck) check() {
	if !hc.beginWork() {
		return
	}
	defer hc.finishWork()
	proxies, tasks := hc.snapshotTasks()
	if len(proxies) == 0 {
		return
	}

	_, _, _ = hc.singleDo.Do(func() (struct{}, error) {
		id := utils.NewUUIDV4().String()
		log.Debugln("Start New Health Checking {%s}", id)
		b := new(errgroup.Group)
		b.SetLimit(10)

		// execute default health check
		option := &extraOption{filters: nil, expectedStatus: hc.expectedStatus}
		hc.execute(b, proxies, hc.url, id, option)

		// execute extra health check
		for _, task := range tasks {
			hc.execute(b, proxies, task.url, id, task.option)
		}
		_ = b.Wait()
		log.Debugln("Finish A Health Checking {%s}", id)
		return struct{}{}, nil
	})
}

type healthCheckTask struct {
	url    string
	option *extraOption
}

func (hc *HealthCheck) snapshotTasks() ([]C.Proxy, []healthCheckTask) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	// Both slices and the task options are replaced instead of mutated, so the
	// immutable snapshot remains valid after releasing the lock.
	return hc.proxies, hc.extraTasks
}

func (hc *HealthCheck) execute(b *errgroup.Group, proxies []C.Proxy, url, uid string, option *extraOption) {
	url = strings.TrimSpace(url)
	if len(url) == 0 {
		log.Debugln("Health Check has been skipped due to testUrl is empty, {%s}", uid)
		return
	}

	var filterReg *regexp2.Regexp
	var expectedStatus utils.IntRanges[uint16]
	if option != nil {
		expectedStatus = option.expectedStatus
		if len(option.filters) != 0 {
			filters := make([]string, 0, len(option.filters))
			for filter := range option.filters {
				filters = append(filters, filter)
			}

			filterReg = regexp2.MustCompile(strings.Join(filters, "|"), regexp2.None)
		}
	}

	for _, proxy := range proxies {
		// skip proxies that do not require health check
		if filterReg != nil {
			if match, _ := filterReg.MatchString(proxy.Name()); !match {
				continue
			}
		}

		p := proxy
		b.Go(func() error {
			ctx, cancel := context.WithTimeout(hc.ctx, hc.timeout)
			defer cancel()
			log.Debugln("Health Checking, proxy: %s, url: %s, id: {%s}", p.Name(), url, uid)
			_, _ = p.URLTest(ctx, url, expectedStatus)
			log.Debugln("Health Checked, proxy: %s, url: %s, alive: %t, delay: %d ms uid: {%s}", p.Name(), url, p.AliveForTestUrl(url), p.LastDelayForTestUrl(url), uid)
			return nil
		})
	}
}

func (hc *HealthCheck) close() {
	hc.closeOnce.Do(func() {
		hc.workMu.Lock()
		hc.workClosing = true
		hc.ctxCancel()
		hc.workMu.Unlock()
		hc.workWG.Wait()
	})
}

func (hc *HealthCheck) beginWork() bool {
	hc.workMu.Lock()
	defer hc.workMu.Unlock()
	if hc.workClosing {
		return false
	}
	hc.workWG.Add(1)
	return true
}

func (hc *HealthCheck) finishWork() {
	hc.workWG.Done()
}

func (hc *HealthCheck) checkInterval() time.Duration {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.interval
}

func (hc *HealthCheck) currentProxyVersion() uint64 {
	hc.mu.RLock()
	defer hc.mu.RUnlock()
	return hc.proxyVersion
}

func (hc *HealthCheck) sinceLastTouch() time.Duration {
	lastTouch := hc.lastTouch.Load()
	if lastTouch == 0 {
		return time.Duration(1<<63 - 1)
	}
	return time.Since(healthCheckClockStart) - time.Duration(lastTouch)
}

func healthCheckResumeDelay(interval time.Duration) time.Duration {
	spread := min(interval/5, 30*time.Second)
	if spread <= 0 {
		return interval
	}
	return interval - spread/2 + time.Duration(rand.Int64N(int64(spread)+1))
}

func NewHealthCheck(proxies []C.Proxy, url string, timeout uint, interval uint, lazy bool, expectedStatus utils.IntRanges[uint16]) *HealthCheck {
	if url == "" {
		expectedStatus = nil
		interval = 0
	}
	if timeout == 0 {
		timeout = 5000
	}
	ctx, cancel := context.WithCancel(context.Background())

	return &HealthCheck{
		ctx:            ctx,
		ctxCancel:      cancel,
		proxies:        append([]C.Proxy(nil), proxies...),
		url:            url,
		timeout:        time.Duration(timeout) * time.Millisecond,
		extra:          map[string]*extraOption{},
		interval:       time.Duration(interval) * time.Second,
		lazy:           lazy,
		expectedStatus: append(utils.IntRanges[uint16](nil), expectedStatus...),
		singleDo:       singledo.NewSingle[struct{}](time.Second),
		coalesceWindow: time.Second,
		wake:           make(chan struct{}, 1),
		trigger:        make(chan struct{}, 1),
		automaticDone:  make(chan uint64, 1),
	}
}

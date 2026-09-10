package outboundgroup

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/component/smart"
	"github.com/metacubex/mihomo/component/smart/lightgbm"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

const smartTaskReadyPollInterval = time.Second

type smartScheduledTask struct {
	initialDelay time.Duration
	interval     time.Duration
	name         string
	run          func()
	runOnce      bool
}

type smartScheduledTaskState struct {
	smartScheduledTask
	next     time.Time
	period   time.Duration
	running  bool
	finished bool
}

// runSmartTaskSchedule uses one timer for all maintenance jobs. Jobs run in
// short-lived goroutines so a slow network probe cannot delay unrelated cache
// maintenance; the running bit prevents a slow job from accumulating copies.
func runSmartTaskSchedule(
	ctx context.Context,
	tasks []smartScheduledTask,
	isRunning func() bool,
	readyPoll time.Duration,
	jitter func() time.Duration,
) {
	if len(tasks) == 0 {
		return
	}
	if readyPoll <= 0 {
		readyPoll = smartTaskReadyPollInterval
	}

	readyTimer := time.NewTimer(readyPoll)
	defer readyTimer.Stop()
	for !isRunning() {
		paused, changed := power.BackgroundState()
		if paused {
			readyTimer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-changed:
				readyTimer.Reset(readyPoll)
			}
			continue
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return
		case <-readyTimer.C:
			readyTimer.Reset(readyPoll)
		}
	}

	now := time.Now()
	states := make([]smartScheduledTaskState, len(tasks))
	spread := jitter()
	for i, task := range tasks {
		period := task.interval
		if period <= 0 {
			period = time.Nanosecond
		}
		states[i] = smartScheduledTaskState{
			smartScheduledTask: task,
			next:               now.Add(task.initialDelay + spread),
			period:             period,
		}
	}

	done := make(chan int, len(states))
	var taskWG sync.WaitGroup
	timer := time.NewTimer(time.Hour)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		taskWG.Wait()
	}()

	wasPaused := false
	for {
		paused, changed := power.BackgroundState()
		if paused {
			wasPaused = true
			timer.Stop()
			select {
			case <-ctx.Done():
				return
			case idx := <-done:
				states[idx].running = false
			case <-changed:
			}
			continue
		}
		if wasPaused {
			now = time.Now()
			for idx := range states {
				state := &states[idx]
				if !state.finished && !state.next.After(now) {
					delay := state.period
					if state.runOnce {
						delay = max(state.initialDelay, time.Millisecond)
					}
					state.next = now.Add(delay + spread)
				}
			}
			wasPaused = false
		}
		var earliest time.Time
		unfinished := 0
		for i := range states {
			if states[i].finished {
				continue
			}
			unfinished++
			if earliest.IsZero() || states[i].next.Before(earliest) {
				earliest = states[i].next
			}
		}
		if unfinished == 0 {
			return
		}

		wait := time.Until(earliest)
		if wait < 0 {
			wait = 0
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		select {
		case <-ctx.Done():
			return
		case <-changed:
			continue
		case idx := <-done:
			states[idx].running = false
		case now = <-timer.C:
			if ctx.Err() != nil {
				return
			}
			if paused, _ := power.BackgroundState(); paused {
				continue
			}
			for i := range states {
				state := &states[i]
				if state.finished || state.next.After(now) {
					continue
				}
				missed := now.Sub(state.next)/state.period + 1
				state.next = state.next.Add(missed * state.period)
				if state.running || !isRunning() {
					continue
				}

				state.running = true
				if state.runOnce {
					state.finished = true
				}
				taskWG.Add(1)
				go func(idx int, task smartScheduledTask) {
					defer taskWG.Done()
					task.run()
					if task.runOnce {
						log.Debugln("[Smart] Task [%s] completed", task.name)
					}
					done <- idx
				}(i, state.smartScheduledTask)
			}
		}
	}
}

func smartTaskJitter() time.Duration {
	return time.Duration(rand.Float64() * 30 * float64(time.Second))
}

type smartGlobalTaskRun struct {
	ctx    context.Context
	cancel context.CancelFunc
	store  *smart.Store

	groupsMu sync.Mutex
	groups   map[*Smart]struct{}
	wg       sync.WaitGroup
}

func newSmartGlobalTaskRun(store *smart.Store) *smartGlobalTaskRun {
	ctx, cancel := context.WithCancel(context.Background())
	return &smartGlobalTaskRun{
		ctx:    ctx,
		cancel: cancel,
		store:  store,
		groups: make(map[*Smart]struct{}),
	}
}

func (r *smartGlobalTaskRun) add(s *Smart) {
	r.groupsMu.Lock()
	r.groups[s] = struct{}{}
	r.groupsMu.Unlock()
}

func (r *smartGlobalTaskRun) remove(s *Smart) bool {
	r.groupsMu.Lock()
	delete(r.groups, s)
	empty := len(r.groups) == 0
	r.groupsMu.Unlock()
	return empty
}

func (r *smartGlobalTaskRun) snapshotGroupsByConfig() []*Smart {
	r.groupsMu.Lock()
	defer r.groupsMu.Unlock()

	byConfig := make(map[string]*Smart, len(r.groups))
	for group := range r.groups {
		if _, exists := byConfig[group.configName]; !exists {
			byConfig[group.configName] = group
		}
	}
	result := make([]*Smart, 0, len(byConfig))
	for _, group := range byConfig {
		result = append(result, group)
	}
	return result
}

func (r *smartGlobalTaskRun) cleanupOrphanedGroups() {
	for _, group := range r.snapshotGroupsByConfig() {
		if !group.beginBackgroundWork() {
			continue
		}
		group.cleanupOrphanedGroups()
		group.finishBackgroundWork()
	}
}

func (r *smartGlobalTaskRun) start() {
	tasks := []smartScheduledTask{
		{5 * time.Minute, cleanupInterval, "Global orphaned groups clean up", r.cleanupOrphanedGroups, false},
		{5 * time.Second, cacheParamAdjustInterval, "Global cache parameters adjustment", r.store.AdjustCacheParameters, false},
		{5 * time.Minute, flushQueueInterval, "Global queues flush", func() { r.store.FlushQueue(true) }, false},
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		runSmartTaskSchedule(r.ctx, tasks, func() bool { return tunnel.Status() == tunnel.Running }, smartTaskReadyPollInterval, smartTaskJitter)
	}()
}

func (r *smartGlobalTaskRun) stop() {
	r.cancel()
	r.wg.Wait()
	r.store.FlushQueue(true)
	lightgbm.CloseAllCollectors()
}

type smartGlobalTaskRegistry struct {
	mu  sync.Mutex
	run *smartGlobalTaskRun
}

func (r *smartGlobalTaskRegistry) acquire(s *Smart) *smartGlobalTaskRun {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.run == nil {
		r.run = newSmartGlobalTaskRun(s.store)
		r.run.add(s)
		r.run.start()
		return r.run
	}
	r.run.add(s)
	return r.run
}

func (r *smartGlobalTaskRegistry) release(s *Smart, run *smartGlobalTaskRun) {
	if run == nil {
		return
	}

	r.mu.Lock()
	last := run.remove(s)
	if last && r.run == run {
		r.run = nil
	}
	if last {
		run.stop()
	}
	r.mu.Unlock()
}

var globalSmartTasks smartGlobalTaskRegistry

func (s *Smart) startGroupTasks() {
	tasks := []smartScheduledTask{
		{10 * time.Minute, cleanupInterval, "Group orphaned nodes clean up", s.cleanupOrphanedNodeCache, true},
		{5 * time.Minute, prefetchInterval, "Group targets prefetch", s.runPrefetch, false},
		{5 * time.Minute, checkInterval, "Group nodes stable check", s.checkNodesStable, false},
		{5 * time.Minute, rankingInterval, "Group nodes ranking", s.updateNodeRanking, false},
		{5 * time.Minute, recoveryCheckInterval, "Group nodes recovery check", s.checkBlockedNodes, false},
		{15 * time.Minute, hostStatusCheckInterval, "Group host status check", s.checkHostStatus, false},
		{time.Minute, prefetchInterval, "Group hostFailLimit refresh", s.applyHostFailLimit, false},
		{10 * time.Minute, cleanupInterval, "Group old records clean up", func() { s.store.CleanupOldRecords(s.Name(), s.configName) }, false},
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		runSmartTaskSchedule(s.ctx, tasks, func() bool { return tunnel.Status() == tunnel.Running }, smartTaskReadyPollInterval, smartTaskJitter)
	}()
}

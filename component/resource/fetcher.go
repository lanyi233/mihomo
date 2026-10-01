package resource

import (
	"context"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/component/slowdown"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/fswatch"
	"github.com/samber/lo"
)

type Parser[V any] func([]byte) (V, error)
type BundleFile func() (fs.File, error)

type Fetcher[V any] struct {
	ctx          context.Context
	ctxCancel    context.CancelFunc
	resourceType string
	name         string
	vehicle      P.Vehicle
	bundleFile   BundleFile
	updatedAt    time.Time
	hash         utils.HashType
	parser       Parser[V]
	interval     time.Duration
	onUpdate     func(V)
	watcher      *fswatch.Watcher
	loadBufMutex sync.Mutex
	stateMu      sync.RWMutex
	backoff      slowdown.Backoff
}

func (f *Fetcher[V]) Name() string {
	return f.name
}

func (f *Fetcher[V]) Vehicle() P.Vehicle {
	return f.vehicle
}

func (f *Fetcher[V]) VehicleType() P.VehicleType {
	return f.vehicle.Type()
}

func (f *Fetcher[V]) UpdatedAt() time.Time {
	f.stateMu.RLock()
	defer f.stateMu.RUnlock()
	return f.updatedAt
}

func (f *Fetcher[V]) setUpdatedAt(updatedAt time.Time) {
	f.stateMu.Lock()
	f.updatedAt = updatedAt
	f.stateMu.Unlock()
}

func (f *Fetcher[V]) Initial() (V, error) {
	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		// local file exists, use it first
		buf, err := os.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), false)
		f.setUpdatedAt(modTime) // reset updatedAt to file's modTime

		if err == nil {
			err = f.startPullLoop(time.Since(modTime) > f.interval)
			if err != nil {
				return lo.Empty[V](), err
			}
			return contents, nil
		}
	}

	// parse local file error, fallback to bundle file
	if f.bundleFile != nil {
		// bundle file exists, use it first
		if file, fErr := f.bundleFile(); fErr == nil {
			defer file.Close()
			buf, err := io.ReadAll(file)
			var modTime time.Time
			if stat, sErr := file.Stat(); sErr == nil {
				modTime = stat.ModTime()
			}
			contents, _, err := f.loadBuf(buf, utils.MakeHash(buf), true)
			f.setUpdatedAt(modTime) // reset updatedAt to file's modTime

			if err == nil {
				log.Infoln("[Provider] %s extract successful from bundle file", f.Name())
				err = f.startPullLoop(time.Since(modTime) > f.interval)
				if err != nil {
					return lo.Empty[V](), err
				}
				return contents, nil
			}
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), err.Error())
		} else {
			log.Warnln("[Provider] %s read bundle file error: %s", f.Name(), fErr.Error())
		}
	}

	// parse local file error, fallback to remote
	contents, _, updateErr := f.Update()

	// start the pull loop even if f.Update() failed
	err := f.startPullLoop(false)
	if err != nil {
		return lo.Empty[V](), err
	}

	if updateErr != nil {
		return lo.Empty[V](), updateErr
	}

	return contents, nil
}

func (f *Fetcher[V]) Update() (V, bool, error) {
	f.stateMu.RLock()
	oldHash := f.hash
	f.stateMu.RUnlock()
	buf, hash, err := f.vehicle.Read(f.ctx, oldHash)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	return f.loadBuf(buf, hash, f.vehicle.Type() != P.File)
}

func (f *Fetcher[V]) SideUpdate(buf []byte) (V, bool, error) {
	return f.loadBuf(buf, utils.MakeHash(buf), true)
}

func (f *Fetcher[V]) loadBuf(buf []byte, hash utils.HashType, updateFile bool) (V, bool, error) {
	f.loadBufMutex.Lock()
	defer f.loadBufMutex.Unlock()

	now := time.Now()
	if f.hash.Equal(hash) {
		if updateFile {
			_ = os.Chtimes(f.vehicle.Path(), now, now)
		}
		f.setUpdatedAt(now)
		f.backoff.Reset() // no error, reset backoff
		return lo.Empty[V](), true, nil
	}

	if buf == nil { // f.hash has been changed between f.vehicle.Read but should not happen (cause by concurrent)
		return lo.Empty[V](), true, nil
	}

	contents, err := f.parser(buf)
	if err != nil {
		f.backoff.AddAttempt() // add a failed attempt to backoff
		return lo.Empty[V](), false, err
	}
	f.backoff.Reset() // no error, reset backoff

	if updateFile {
		if err = f.vehicle.Write(buf); err != nil {
			return lo.Empty[V](), false, err
		}
	}
	f.stateMu.Lock()
	f.updatedAt = now
	f.hash = hash
	f.stateMu.Unlock()

	if f.onUpdate != nil {
		f.onUpdate(contents)
	}

	return contents, false, nil
}

func (f *Fetcher[V]) Close() error {
	f.ctxCancel()
	if f.watcher != nil {
		_ = f.watcher.Close()
	}
	return nil
}

func (f *Fetcher[V]) pullLoop(forceUpdate bool) {
	initialInterval := min(f.interval, f.interval-time.Since(f.UpdatedAt()))
	if forceUpdate {
		initialInterval = 0
	} else if f.backoff.Attempt() > 0 {
		// A failed initial read has no updatedAt. Honor retry backoff instead
		// of interpreting the zero timestamp as an immediately due refresh.
		initialInterval = f.nextPullInterval()
	}

	next := time.Now().Add(initialInterval)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	wasPaused := false
	for {
		if f.ctx.Err() != nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		paused, changed := power.BackgroundState()
		if paused {
			wasPaused = true
			select {
			case <-changed:
				continue
			case <-f.ctx.Done():
				return
			}
		}
		if wasPaused {
			if !next.After(time.Now()) {
				// Give the network time to settle and spread overdue providers
				// across the resume window rather than downloading all at once.
				delay := min(f.interval, 30*time.Second)
				delay = delay/2 + time.Duration(rand.Int64N(int64(delay-delay/2)+1))
				next = time.Now().Add(delay)
			}
			wasPaused = false
		}
		timer.Reset(time.Until(next))
		select {
		case <-timer.C:
			if paused, _ := power.BackgroundState(); paused || f.ctx.Err() != nil {
				continue
			}
			if forceUpdate {
				log.Warnln("[Provider] %s not updated for a long time, force refresh", f.Name())
				forceUpdate = false
			}
			f.updateWithLog()
			next = time.Now().Add(f.nextPullInterval())
		case <-changed:
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *Fetcher[V]) nextPullInterval() time.Duration {
	if attempt := f.backoff.Attempt(); attempt > 0 {
		return min(f.interval, f.backoff.ForAttempt(attempt))
	}
	return f.interval
}

func (f *Fetcher[V]) startPullLoop(forceUpdate bool) (err error) {
	// pull contents automatically
	if f.vehicle.Type() == P.File {
		f.watcher, err = fswatch.NewWatcher(fswatch.Options{
			Path:     []string{f.vehicle.Path()},
			Callback: f.updateCallback,
		})
		if err != nil {
			return err
		}
		err = f.watcher.Start()
		if err != nil {
			return err
		}
	} else if f.interval > 0 {
		go f.pullLoop(forceUpdate)
	}
	return
}

func (f *Fetcher[V]) updateCallback(path string) {
	f.updateWithLog()
}

func (f *Fetcher[V]) updateWithLog() {
	_, same, err := f.Update()
	if err != nil {
		log.Errorln("[Provider] %s pull error: %s", f.Name(), err.Error())
		return
	}

	if same {
		log.Debugln("[Provider] %s's content doesn't change", f.Name())
		return
	}

	log.Infoln("[Provider] %s's content update", f.Name())
	return
}

func NewFetcher[V any](name string, interval time.Duration, vehicle P.Vehicle, bundleFile BundleFile, parser Parser[V], onUpdate func(V)) *Fetcher[V] {
	ctx, cancel := context.WithCancel(context.Background())
	minBackoff := 10 * time.Second
	if interval < minBackoff {
		minBackoff = interval
	}
	return &Fetcher[V]{
		ctx:        ctx,
		ctxCancel:  cancel,
		name:       name,
		bundleFile: bundleFile,
		vehicle:    vehicle,
		parser:     parser,
		onUpdate:   onUpdate,
		interval:   interval,
		backoff: slowdown.Backoff{
			Factor: 2,
			Jitter: false,
			Min:    minBackoff,
			Max:    interval,
		},
	}
}

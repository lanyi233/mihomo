package updater

import (
	"context"
	"io"
	"math/rand/v2"
	"os"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/power"

	"github.com/metacubex/http"
)

const defaultHttpTimeout = time.Second * 90

// runPeriodicUpdates never polls while suspended/offline. On an overdue
// resume, independently jitter GEO and model downloads over a settle window.
func runPeriodicUpdates(ctx context.Context, interval time.Duration, overdue bool, update func()) {
	next := time.Now().Add(interval)
	if overdue {
		next = time.Now()
	}
	for {
		settle := min(interval, 30*time.Second)
		settle = settle/2 + time.Duration(rand.Int64N(int64(settle-settle/2)+1))
		if !power.WaitUntil(ctx, next, settle) {
			return
		}
		update()
		next = time.Now().Add(interval)
	}
}

func downloadForBytes(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHttpTimeout)
	defer cancel()
	resp, err := mihomoHttp.HttpRequest(ctx, url, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

func saveFile(bytes []byte, path string) error {
	return os.WriteFile(path, bytes, 0o644)
}

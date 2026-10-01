package smart

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/bbolt"
	"github.com/stretchr/testify/require"
)

func openScanTestDB(tb testing.TB, count int) *bbolt.DB {
	tb.Helper()
	testDB, err := bbolt.Open(filepath.Join(tb.TempDir(), "scan.db"), 0600, nil)
	if err != nil {
		tb.Fatal(err)
	}
	previousDB := db
	db = testDB
	tb.Cleanup(func() {
		db = previousDB
		testDB.Close()
	})
	err = testDB.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucket(bucketSmartStats)
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			key := fmt.Sprintf("smart/stats/config/group/%05d", i)
			if err := bucket.Put([]byte(key), bytes.Repeat([]byte(key), 8)); err != nil {
				return err
			}
		}
		return bucket.Put([]byte("smart/stats/config/group-extra/key"), []byte("excluded"))
	})
	if err != nil {
		tb.Fatal(err)
	}
	return testDB
}

func TestDBViewPrefixScanOwnsSample(t *testing.T) {
	testDB := openScanTestDB(t, 100)
	store := &Store{}
	for _, limit := range []int{-1, 0, 1, 10, 200} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			result, err := store.DBViewPrefixScan("smart/stats/config/group", limit, true)
			require.NoError(t, err)
			want := limit
			if limit < 0 || limit > 100 {
				want = 100
			}
			require.Len(t, result, want)
			for key, value := range result {
				require.True(t, strings.HasPrefix(key, "smart/stats/config/group/"))
				require.Equal(t, bytes.Repeat([]byte(key), 8), value)
				// Returned values must be writable without modifying bbolt's mmap.
				value[0] = 'X'
				require.NoError(t, testDB.View(func(tx *bbolt.Tx) error {
					require.Equal(t, byte('s'), tx.Bucket(bucketSmartStats).Get([]byte(key))[0])
					return nil
				}))
			}
		})
	}
}

func BenchmarkDBViewPrefixScanSample(b *testing.B) {
	openScanTestDB(b, 10000)
	store := &Store{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.DBViewPrefixScan("smart/stats/config/group", 100, true); err != nil {
			b.Fatal(err)
		}
	}
}

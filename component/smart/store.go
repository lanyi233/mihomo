package smart

import (
	"bytes"
	"encoding/json"
	"errors"
	"hash/crc32"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/log"
)

const (
	OpSaveNodeState = iota
	OpSaveStats
	OpSavePrefetch
	OpSaveRanking
	OpSaveHostFailures
	OpDeleteData
)

const (
	KeyTypePrefetch     = "prefetch"
	KeyTypeNode         = "node"
	KeyTypeStats        = "stats"
	KeyTypeRanking      = "ranking"
	KeyTypeHostFailures = "failures"

	WeightTypeTCP = "tcp"
	WeightTypeUDP = "udp"
)

const (
	// initialScanCap keeps a scan that usually sees a handful of records from reserving room
	// for the whole limit; the map and the reservoir grow on demand.
	initialScanCap = 64
	// initialQueueCap keeps a re-created write queue from reserving room for a whole batch.
	initialQueueCap = 64
	// maxCachedViewBytes bounds one cached view: a group that big is scanned again when it is
	// asked for instead of being held in memory.
	maxCachedViewBytes = 256 << 10
)

var db *bbolt.DB

var bucketSmartStats = []byte("smart_stats")

var globalOperationQueue operationQueue

// nodeStateLocks stripe the read-modify-write of one node's state, so a writer that only
// changes its own fields keeps the fields another writer set in between.
var nodeStateLocks [64]sync.Mutex

type Store struct{}

type StoreOperation struct {
	Type    int
	KeyType string // used by OpDeleteData to identify the target key type
	Group   string
	Config  string
	Target  string
	Node    string
	Data    []byte
}

// operationQueue is the set of writes waiting to be flushed: a map for
// deduplication and a slice for order, so an append costs O(1).
//
// It was a slice inside an atomic value, rebuilt in full on every append -- a
// fresh map over every pending entry, a formatOperationKey (with its string
// build) for each, then a fresh slice. Filling the queue to its flush threshold
// therefore cost O(threshold^2) key formats and allocations, and
// AdjustCacheParameters raises that threshold when memory is free, so a machine
// with more RAM paid quadratically more for it. Under a burst of closes the CAS
// loop degenerated into a spin lock around an O(n) critical section.
//
// Deduplication stays. BatchSave would dedupe again at flush time, but dropping
// it here would make the threshold count raw appends instead of distinct keys,
// so the queue would flush more often -- and every flush is a bbolt commit with
// an fsync, which on the flash storage these run on is the expensive part.
type operationQueue struct {
	access   sync.Mutex
	position map[string]int
	ops      []StoreOperation
}

func NewStore(newdb *bbolt.DB) *Store {
	db = newdb
	InitCache()
	globalOperationQueue.reset()
	return &Store{}
}

func FormatDBKey(parts ...string) string {
	size := 5
	for _, part := range parts {
		if part != "" {
			size += 1 + len(part)
		}
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString("smart")
	for _, part := range parts {
		if part != "" {
			b.WriteByte('/')
			b.WriteString(part)
		}
	}
	return b.String()
}

func formatOperationKey(op *StoreOperation) string {
	switch op.Type {
	case OpSaveNodeState:
		return FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)
	case OpSaveStats:
		return FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)
	case OpSavePrefetch:
		return FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)
	case OpSaveRanking:
		return FormatDBKey(KeyTypeRanking, op.Config, op.Group)
	case OpSaveHostFailures:
		return FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)
	case OpDeleteData:
		kt := op.KeyType
		if kt == "" {
			if op.Target != "" {
				kt = KeyTypeHostFailures
			} else if op.Node != "" {
				kt = KeyTypeNode
			} else {
				kt = KeyTypeRanking
			}
		}
		switch kt {
		case KeyTypeNode:
			return FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)
		case KeyTypeStats:
			return FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)
		case KeyTypePrefetch:
			return FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)
		case KeyTypeRanking:
			return FormatDBKey(KeyTypeRanking, op.Config, op.Group)
		default:
			return FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)
		}
	default:
		return ""
	}
}

func (q *operationQueue) reset() {
	q.access.Lock()
	defer q.access.Unlock()
	q.takeLocked()
}

// minQueueCap keeps the initial queue allocations small on purpose: they are re-created after
// every flush and only rarely hold as many operations as one batch allows.
func minQueueCap() int {
	threshold := GetBatchSaveThreshold()
	if threshold > initialQueueCap {
		return initialQueueCap
	}
	return threshold
}

func (q *operationQueue) get(key string) (StoreOperation, bool) {
	q.access.Lock()
	defer q.access.Unlock()
	pos, found := q.position[key]
	if !found {
		return StoreOperation{}, false
	}
	return q.ops[pos], true
}

// snapshot copies the pending operations, for readers that answer a query from
// the queue before it reaches the store.
func (q *operationQueue) snapshot() []StoreOperation {
	q.access.Lock()
	defer q.access.Unlock()
	return slices.Clone(q.ops)
}

// drain returns the pending batch, emptying the queue, when it has reached the
// threshold or the caller insists.
func (q *operationQueue) drain(force bool) []StoreOperation {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.ops) == 0 || (!force && len(q.ops) < GetBatchSaveThreshold()) {
		return nil
	}
	return q.takeLocked()
}

func (s *Store) AppendToGlobalQueue(operations ...StoreOperation) {
	if len(operations) == 0 {
		return
	}
	snapshot := globalOperationQueue.add(operations)
	if len(snapshot) == 0 {
		return
	}
	go func() {
		if err := s.BatchSave(snapshot); err == nil {
			log.Debugln("[SmartStore] Queue datas saved, operations: [%d]", len(snapshot))
		}
	}()
}

func (s *Store) ClearFloodRecordsByGroup(group, config string) {
	globalOperationQueue.retain(func(op StoreOperation) bool {
		if op.Group == group && op.Config == config {
			switch op.Type {
			case OpSaveStats, OpSaveHostFailures, OpSaveNodeState:
				return false
			}
		}
		return true
	})

	blockedNodesCache.Delete(FormatDBKey(config, group))
	hostStatusCache.RemoveByKeyPrefix(FormatDBKey(KeyTypeHostFailures, config, group) + "/")
}

func removeNodesFromQueue(group, config string, nodes []string) {
	nodeSet := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = struct{}{}
	}
	globalOperationQueue.retain(func(op StoreOperation) bool {
		if op.Group == group && op.Config == config {
			_, dropped := nodeSet[op.Node]
			return !dropped
		}
		return true
	})
}

// 按级别刷新缓存
func (s *Store) FlushByLevel(level string, config string, group string) error {
	if level == "" {
		return errors.New("flush level cannot be empty")
	}

	if level == "all" {
		InitQueue()
	} else if level == "config" {
		globalOperationQueue.retain(func(op StoreOperation) bool { return op.Config != config })
	} else if level == "group" {
		globalOperationQueue.retain(func(op StoreOperation) bool {
			return op.Group != group || op.Config != config
		})
	}

	s.clearCache(level, config, group)

	if level == "all" {
		s.DBBatchDeletePrefix([]string{"smart"}, false)
	} else if level == "config" {
		s.DBBatchDeletePrefix([]string{
			FormatDBKey(KeyTypeStats, config),
			FormatDBKey(KeyTypeNode, config),
			FormatDBKey(KeyTypeRanking, config),
			FormatDBKey(KeyTypePrefetch, config),
			FormatDBKey(KeyTypeHostFailures, config),
		}, false)
	} else if level == "group" {
		s.DBBatchDeletePrefix([]string{
			FormatDBKey(KeyTypeStats, config, group),
			FormatDBKey(KeyTypeNode, config, group),
			FormatDBKey(KeyTypeRanking, config, group),
			FormatDBKey(KeyTypePrefetch, config, group),
			FormatDBKey(KeyTypeHostFailures, config, group),
		}, false)
	}

	return nil
}

// 清空所有缓存
func (s *Store) FlushAll() error {
	log.Debugln("[SmartStore] Starting FlushAll, current queue length: %d", globalOperationQueue.length())
	err := s.FlushByLevel("all", "", "")
	if err == nil {
		log.Debugln("[SmartStore] All Smart data cleared")
	}
	return err
}

func (s *Store) FlushByConfig(config string) error {
	err := s.FlushByLevel("config", config, "")
	if err == nil {
		log.Debugln("[SmartStore] All data for config [%s] cleared", config)
	}
	return err
}

func (s *Store) FlushByGroup(group, config string) error {
	err := s.FlushByLevel("group", config, group)
	if err == nil {
		log.Debugln("[SmartStore] All data for group [%s] config [%s] cleared", group, config)
	}
	return err
}

func nodeStateLock(group, config, node string) *sync.Mutex {
	index := crc32.ChecksumIEEE([]byte(group+"\x00"+config+"\x00"+node)) % uint32(len(nodeStateLocks))
	return &nodeStateLocks[index]
}

// NodeStateBytes reads a node's queued write first, so an unflushed state stays visible;
// the key is read exactly: a group scan samples and may miss the node in a big group.
func (s *Store) NodeStateBytes(group, config, node string) ([]byte, bool) {
	if node == "" {
		return nil, false
	}
	key := FormatDBKey(KeyTypeNode, config, group, node)
	if op, found := globalOperationQueue.get(key); found {
		if op.Type == OpDeleteData {
			return nil, false
		}
		return op.Data, true
	}
	data, err := s.DBViewGetItem(key)
	if err != nil {
		return nil, false
	}
	return data, true
}

// UpdateNodeState merges one node's state under its per-node lock, reading queued writes.
func (s *Store) UpdateNodeState(group, config, node string, update func(*NodeState)) {
	if node == "" {
		return
	}

	mu := nodeStateLock(group, config, node)
	mu.Lock()
	defer mu.Unlock()

	var state NodeState
	if raw, ok := s.NodeStateBytes(group, config, node); ok {
		_ = json.Unmarshal(raw, &state)
	}
	state.Name = node
	update(&state)
	data, err := json.Marshal(&state)
	if err != nil {
		return
	}
	s.AppendToGlobalQueue(StoreOperation{
		Type:   OpSaveNodeState,
		Group:  group,
		Config: config,
		Node:   node,
		Data:   data,
	})
}

func (s *Store) GetNodeStates(group, config string) (map[string][]byte, error) {
	pathPrefix := FormatDBKey(KeyTypeNode, config, group)
	result := make(map[string][]byte)

	rawResult, err := s.GetSubBytesByPath(pathPrefix)
	if err != nil {
		return nil, err
	}

	for fullPath, data := range rawResult {
		nodeName := fullPath[strings.LastIndexByte(fullPath, '/')+1:]
		result[nodeName] = data
	}

	return result, nil
}

func (s *Store) BatchSave(operations []StoreOperation) error {
	if len(operations) == 0 {
		return nil
	}
	if db == nil {
		return errors.New("DB Cache file load failed")
	}

	type writeEntry struct {
		key  string
		data []byte
	}

	var deleteKeys []string
	deleteKeyIdx := make(map[string]int)

	writeIndex := make(map[string]int, len(operations))
	entries := make([]writeEntry, 0, len(operations))

	for i := range operations {
		key := formatOperationKey(&operations[i])
		if key == "" {
			continue
		}

		if operations[i].Type == OpDeleteData {
			deleteKeyIdx[key] = len(deleteKeys)
			deleteKeys = append(deleteKeys, key)
			if idx, ok := writeIndex[key]; ok {
				entries[idx].data = nil
				delete(writeIndex, key)
			}
			continue
		}

		if didx, ok := deleteKeyIdx[key]; ok {
			deleteKeys[didx] = ""
			delete(deleteKeyIdx, key)
		}

		if idx, ok := writeIndex[key]; ok {
			entries[idx].data = operations[i].Data
			continue
		}
		writeIndex[key] = len(entries)
		entries = append(entries, writeEntry{key: key, data: operations[i].Data})
	}

	n := 0
	for _, e := range entries {
		if e.data != nil {
			entries[n] = e
			n++
		}
	}
	entries = entries[:n]

	m := 0
	for _, k := range deleteKeys {
		if k != "" {
			deleteKeys[m] = k
			m++
		}
	}
	deleteKeys = deleteKeys[:m]

	if len(entries) == 0 && len(deleteKeys) == 0 {
		return nil
	}

	err := db.Batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			var err error
			bucket, err = tx.CreateBucketIfNotExists(bucketSmartStats)
			if err != nil {
				return err
			}
		}

		for _, key := range deleteKeys {
			if err := bucket.Delete([]byte(key)); err != nil {
				return err
			}
		}

		for _, entry := range entries {
			if err := bucket.Put([]byte(entry.key), entry.data); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		log.Debugln("[SmartStore] Batch save operation failed: %v", err)
	}

	return err
}

func (s *Store) FlushQueue(force bool) {
	ops := globalOperationQueue.drain(force)
	if len(ops) == 0 {
		return
	}
	s.BatchSave(ops)
	log.Debugln("[SmartStore] Queue datas saved, operations: [%d]", len(ops))
}

// cacheView stores a scanned view unless it is too big to hold in memory.
func cacheView(key string, view map[string][]byte) {
	total := 0
	for k, v := range view {
		total += len(k) + len(v)
	}
	if total > maxCachedViewBytes {
		return
	}
	dbResultCache.Set(key, view)
}

func mergeIntoByPrefix(from, into map[string][]byte, queryPrefix string, strict bool) int {
	merged := 0
	for k, v := range from {
		if !strings.HasPrefix(k, queryPrefix) {
			continue
		}
		if strict && len(k) > len(queryPrefix) && k[len(queryPrefix)] != '/' {
			continue
		}
		if _, exists := into[k]; exists {
			continue
		}
		into[k] = v
		merged++
	}
	return merged
}

// 根据路径获取缓存数据
func (s *Store) GetSubBytesByPath(prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)

	globalCacheParams.mutex.RLock()
	maxTargets := globalCacheParams.MaxTargets
	globalCacheParams.mutex.RUnlock()

	configMaxTargets := maxTargets / 2

	depth := strings.Count(prefix, "/") + 1
	if depth < 3 || !strings.HasPrefix(prefix, "smart/") {
		return result, nil
	}
	if depth <= 4 && maxTargets > 1 {
		configMaxTargets = maxTargets * 2
	}
	rest := prefix[6:] // skip "smart/"
	var keyType, config, group, seg4, seg5 string
	keyType, rest, _ = strings.Cut(rest, "/")
	config, rest, _ = strings.Cut(rest, "/")
	if depth >= 4 {
		group, rest, _ = strings.Cut(rest, "/")
	}
	if depth >= 5 {
		seg4, rest, _ = strings.Cut(rest, "/")
	}
	if depth >= 6 {
		seg5, _, _ = strings.Cut(rest, "/")
	}

	strict := false
	switch keyType {
	case KeyTypeNode, KeyTypePrefetch, KeyTypeHostFailures:
		if depth == 5 {
			strict = true
		}
	case KeyTypeRanking:
		if depth == 4 {
			strict = true
		}
	case KeyTypeStats:
		if depth == 6 {
			strict = true
		}
	}

	// 从队列获取结果
	ops := globalOperationQueue.snapshot()
	for _, op := range ops {
		if op.Config != config {
			continue
		}
		if depth >= 4 && op.Group != group {
			continue
		}

		if op.Type == OpDeleteData {
			deleteKey := formatOperationKey(&op)
			if deleteKey != "" {
				delete(result, deleteKey)
			}
			continue
		}

		switch keyType {
		case KeyTypeNode:
			if op.Type == OpSaveNodeState && op.Node != "" {
				if depth >= 5 && seg4 != op.Node {
					continue
				}
				result[FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)] = op.Data
			}
		case KeyTypeStats:
			if op.Type == OpSaveStats && op.Target != "" && op.Node != "" {
				if depth >= 5 && seg4 != op.Target {
					continue
				}
				if depth >= 6 && seg5 != op.Node {
					continue
				}
				result[FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)] = op.Data
			}
		case KeyTypePrefetch:
			if op.Type == OpSavePrefetch && op.Target != "" {
				if depth >= 5 && seg4 != op.Target {
					continue
				}
				result[FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)] = op.Data
			}
		case KeyTypeRanking:
			if op.Type == OpSaveRanking {
				result[FormatDBKey(KeyTypeRanking, op.Config, op.Group)] = op.Data
			}
		case KeyTypeHostFailures:
			if op.Type == OpSaveHostFailures && op.Target != "" {
				if depth >= 5 && seg4 != op.Target {
					continue
				}
				result[FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)] = op.Data
			}
		}
	}

	if strict && len(result) > 0 {
		return result, nil
	}

	maxResults := -1
	if configMaxTargets > 1 {
		maxResults = configMaxTargets
	}

	hasGroupLevel := false
	var groupPrefix string

	switch keyType {
	case KeyTypeStats, KeyTypeNode, KeyTypePrefetch, KeyTypeHostFailures, KeyTypeRanking:
		if depth >= 4 {
			hasGroupLevel = true
			groupPrefix = FormatDBKey(keyType, config, group)
		}
	}

	if hasGroupLevel && maxResults > 0 {
		if cachedGroup, expireTime, ok := dbResultCache.GetWithExpire(groupPrefix); ok {
			isStale := expireTime.Before(time.Now())
			merged := mergeIntoByPrefix(cachedGroup, result, prefix, strict)

			if isStale {
				if _, loading := dbResultRefreshFlags.LoadOrStore(groupPrefix, true); !loading {
					go func() {
						defer dbResultRefreshFlags.Delete(groupPrefix)
						if groupResult, err := s.DBViewPrefixScan(groupPrefix, maxResults, false); err == nil {
							cacheView(groupPrefix, groupResult)
						}
					}()
				}
			}

			if depth == 4 || merged > 0 {
				return result, nil
			}
			if strict {
				groupResult, err := s.DBViewPrefixScan(groupPrefix, maxResults, false)
				if err == nil {
					cacheView(groupPrefix, groupResult)
					_ = mergeIntoByPrefix(groupResult, result, prefix, strict)
				}
			}
		} else {
			groupResult, err := s.DBViewPrefixScan(groupPrefix, maxResults, false)
			if err == nil {
				cacheView(groupPrefix, groupResult)
				_ = mergeIntoByPrefix(groupResult, result, prefix, strict)
			}
		}
		return result, nil
	}

	if cached, expireTime, ok := dbResultCache.GetWithExpire(prefix); ok && maxResults > 0 {
		isStale := expireTime.Before(time.Now())
		for k, v := range cached {
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}

		if isStale && !hasGroupLevel {
			if keyType != KeyTypeStats && keyType != KeyTypeHostFailures {
				if _, loading := dbResultRefreshFlags.LoadOrStore(prefix, true); !loading {
					go func() {
						defer dbResultRefreshFlags.Delete(prefix)
						if dbResult, err := s.DBViewPrefixScan(prefix, maxResults, strict); err == nil {
							cacheView(prefix, dbResult)
						}
					}()
				}
			}
		}
	} else {
		dbResult, err := s.DBViewPrefixScan(prefix, maxResults, strict)
		if err != nil {
			return result, nil
		}
		if maxResults > 0 && !hasGroupLevel {
			if keyType != KeyTypeStats && keyType != KeyTypeHostFailures {
				cacheView(prefix, dbResult)
			}
		}
		for k, v := range dbResult {
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	}

	return result, nil
}

func (s *Store) DBViewGetItem(key string) ([]byte, error) {
	if db == nil {
		return nil, errors.New("DB Cache file load failed")
	}
	keyBytes := []byte(key)

	var data []byte
	err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return errors.New("bucket not found")
		}

		value := bucket.Get(keyBytes)
		if value == nil {
			return errors.New("item not found")
		}

		data = append(data[:0], value...)
		return nil
	})
	return data, err
}

func (s *Store) DBBatchPutItem(key string, value []byte) error {
	if db == nil {
		return errors.New("DB Cache file load failed")
	}
	keyBytes := []byte(key)

	return db.Batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			var err error
			bucket, err = tx.CreateBucketIfNotExists(bucketSmartStats)
			if err != nil {
				return err
			}
		}
		return bucket.Put(keyBytes, value)
	})
}

// DBViewPrefixScan answers a prefix holding more records than maxResults with a uniform
// random sample of them; maxResults < 0 returns every record.
func (s *Store) DBViewPrefixScan(prefix string, maxResults int, strict bool) (map[string][]byte, error) {
	if db == nil {
		return nil, errors.New("DB Cache file load failed")
	}

	resultCap := 0
	if maxResults > 0 && maxResults < initialScanCap {
		resultCap = maxResults
	}
	result := make(map[string][]byte, resultCap)

	if maxResults == 0 {
		return result, nil
	}

	type kv struct {
		key []byte
		val []byte
	}

	var reservoir []kv
	seen := 0

	err := db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		prefixBytes := []byte(prefix)

		if maxResults < 0 {
			for k, v := cursor.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); k, v = cursor.Next() {
				if strict && len(k) > len(prefixBytes) && k[len(prefixBytes)] != '/' {
					continue
				}
				keyCopy := string(k)
				dataCopy := make([]byte, len(v))
				copy(dataCopy, v)
				result[keyCopy] = dataCopy
			}
			return nil
		}

		reservoir = make([]kv, 0, resultCap)
		for k, v := cursor.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); k, v = cursor.Next() {
			if strict && len(k) > len(prefixBytes) && k[len(prefixBytes)] != '/' {
				continue
			}

			if len(reservoir) < maxResults {
				reservoir = append(reservoir, kv{key: k, val: v})
				seen++
				continue
			}

			seen++
			j := rand.Intn(seen)
			if j < maxResults {
				reservoir[j] = kv{key: k, val: v}
			}
		}
		// Cursor slices remain valid for the transaction. Copy only the final
		// sample, before closing it, rather than every candidate later evicted.
		for _, item := range reservoir {
			dataCopy := make([]byte, len(item.val))
			copy(dataCopy, item.val)
			result[string(item.key)] = dataCopy
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if maxResults > 0 && seen > maxResults {
		log.Debugln("[SmartStore] Prefix [%s] scan hit the record limit: found [%d] records, kept [%d]...", prefix, seen, maxResults)
	}

	return result, nil
}

func (s *Store) DBBatchDeletePrefix(prefixes []string, strict bool) error {
	if db == nil {
		return errors.New("DB Cache file load failed")
	}

	return db.Batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketSmartStats)
		if bucket == nil {
			return nil
		}

		cursor := bucket.Cursor()
		for _, prefix := range prefixes {
			prefixBytes := []byte(prefix)
			for k, _ := cursor.Seek(prefixBytes); k != nil && bytes.HasPrefix(k, prefixBytes); {
				if strict && len(k) > len(prefixBytes) && k[len(prefixBytes)] != '/' {
					k, _ = cursor.Next()
					continue
				}
				if err := cursor.Delete(); err != nil {
					return err
				}
				k, _ = cursor.Next()
			}
		}
		return nil
	})
}

// add records the operations and returns a batch to flush when the queue has
// reached the threshold, or nil.
func (q *operationQueue) add(operations []StoreOperation) []StoreOperation {
	q.access.Lock()
	defer q.access.Unlock()
	for i := range operations {
		key := formatOperationKey(&operations[i])
		if key == "" {
			continue
		}
		if at, seen := q.position[key]; seen {
			// Last write wins, in the place the key already holds: there is
			// only ever one entry per key, so position carries no meaning
			// beyond keeping the flush order stable.
			q.ops[at] = operations[i]
			continue
		}
		if q.position == nil {
			q.position = make(map[string]int)
		}
		q.position[key] = len(q.ops)
		q.ops = append(q.ops, operations[i])
	}
	if len(q.ops) < GetBatchSaveThreshold() {
		return nil
	}
	return q.takeLocked()
}

func (q *operationQueue) takeLocked() []StoreOperation {
	ops := q.ops
	q.ops = make([]StoreOperation, 0, minQueueCap())
	q.position = make(map[string]int, minQueueCap())
	return ops
}

// retain drops every operation the predicate rejects, rebuilding the index.
// Only the flood suppressor and config teardown do this, so the O(n) rebuild
// is not on any hot path.
func (q *operationQueue) retain(keep func(StoreOperation) bool) {
	q.access.Lock()
	defer q.access.Unlock()
	kept := make([]StoreOperation, 0, len(q.ops))
	position := make(map[string]int, len(q.ops))
	for _, op := range q.ops {
		if !keep(op) {
			continue
		}
		if key := formatOperationKey(&op); key != "" {
			position[key] = len(kept)
		}
		kept = append(kept, op)
	}
	q.ops = kept
	q.position = position
}

func (q *operationQueue) length() int {
	q.access.Lock()
	defer q.access.Unlock()
	return len(q.ops)
}

func InitQueue() {
	globalOperationQueue.reset()
}

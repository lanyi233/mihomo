package smart

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/lru"
	"github.com/metacubex/mihomo/common/xsync"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	MaxTargetsLimit     = 5000
	MinTargetsLimit     = 500
	MaxBatchThreshLimit = 300
	MinBatchThreshLimit = 50
)

var targetCache *lru.LruCache[string, string]

var unwrapCache *lru.LruCache[string, UnwrapMap]

var recordCache *lru.LruCache[string, *AtomicStatsRecord]

var dbResultCache *lru.LruCache[string, map[string][]byte]

var blockedNodesCache *lru.LruCache[string, map[string]bool]

var hostStatusCache *lru.LruCache[string, *HostStatus]

var globalCacheParams struct {
	BatchSaveThreshold int
	MaxTargets         int
	LastMemoryUsage    float64
	mutex              sync.RWMutex
}

var dbResultRefreshFlags xsync.Map[string, bool]

var blockedNodesRefreshFlags xsync.Map[string, bool]

type UnwrapMap struct {
	Proxies []string `json:"proxies,omitempty"`
	Ref     string   `json:"ref,omitempty"`
}

type NodesWithWeights struct {
	Nodes   []string  `json:"nodes"`
	Weights []float64 `json:"weights"`
}

type NodeWithWeight struct {
	Node   string
	Weight float64
}

type PrefetchMap struct {
	TCP         NodesWithWeights `json:"tcp,omitempty"`
	UDP         NodesWithWeights `json:"udp,omitempty"`
	UpdatedTime int64            `json:"updated_time,omitempty"`
}

func InitCache() {
	globalCacheParams.mutex.Lock()
	defer globalCacheParams.mutex.Unlock()

	if unwrapCache != nil {
		return
	}

	globalCacheParams.BatchSaveThreshold = MinBatchThreshLimit
	globalCacheParams.MaxTargets = MinTargetsLimit

	targetCache = lru.New[string, string](
		lru.WithSize[string, string](globalCacheParams.MaxTargets/3),
		lru.WithAge[string, string](300),
		lru.WithStale[string, string](true),
	)

	unwrapCache = lru.New[string, UnwrapMap](
		lru.WithSize[string, UnwrapMap](globalCacheParams.MaxTargets/3),
		lru.WithAge[string, UnwrapMap](600),
		lru.WithStale[string, UnwrapMap](true),
	)

	recordCache = lru.New[string, *AtomicStatsRecord](
		lru.WithSize[string, *AtomicStatsRecord](globalCacheParams.MaxTargets/3),
		lru.WithAge[string, *AtomicStatsRecord](300),
		lru.WithStale[string, *AtomicStatsRecord](true),
	)

	dbResultCache = lru.New[string, map[string][]byte](
		lru.WithSize[string, map[string][]byte](globalCacheParams.MaxTargets/3),
		lru.WithAge[string, map[string][]byte](300),
		lru.WithStale[string, map[string][]byte](true),
	)

	blockedNodesCache = lru.New[string, map[string]bool](
		lru.WithSize[string, map[string]bool](globalCacheParams.MaxTargets/3),
		lru.WithAge[string, map[string]bool](300),
		lru.WithStale[string, map[string]bool](true),
	)

	hostStatusCache = lru.New[string, *HostStatus](
		lru.WithSize[string, *HostStatus](globalCacheParams.MaxTargets/3),
		lru.WithAge[string, *HostStatus](300),
		lru.WithStale[string, *HostStatus](true),
	)
}

func (s *Store) StorePrefetchResult(group, config string, target string, isUDP bool, proxyNames []string, weights []float64) {
	if target == "" || len(proxyNames) == 0 {
		return
	}

	var pm PrefetchMap
	nodeWeight := NodesWithWeights{Nodes: proxyNames, Weights: weights}

	if isUDP {
		pm.UDP = nodeWeight
	} else {
		pm.TCP = nodeWeight
	}
	pm.UpdatedTime = time.Now().Unix()

	data, err := json.Marshal(pm)
	if err != nil {
		return
	}

	s.AppendToGlobalQueue(StoreOperation{
		Type:   OpSavePrefetch,
		Group:  group,
		Config: config,
		Target: target,
		Data:   data,
	})
}

func (s *Store) GetPrefetchResult(group, config string, target string, isUDP bool) ([]string, []float64) {
	if target == "" {
		return nil, nil
	}

	loadPM := func(pathPrefix string) (PrefetchMap, bool) {
		rawResult, err := s.GetSubBytesByPath(pathPrefix)
		if err != nil {
			return PrefetchMap{}, false
		}
		for _, data := range rawResult {
			var pm PrefetchMap
			if json.Unmarshal(data, &pm) == nil {
				return pm, true
			}
		}
		return PrefetchMap{}, false
	}

	pick := func(pm PrefetchMap) ([]string, []float64) {
		var res NodesWithWeights
		if isUDP {
			res = pm.UDP
		} else {
			res = pm.TCP
		}
		if len(res.Nodes) > 0 && len(res.Weights) == len(res.Nodes) {
			return res.Nodes, res.Weights
		}
		return nil, nil
	}

	if pm, ok := loadPM(FormatDBKey(KeyTypePrefetch, config, group, target)); ok {
		if nodes, weights := pick(pm); nodes != nil {
			return nodes, weights
		}
	}

	return nil, nil
}

func (s *Store) StoreUnwrapResult(group, config string, target string, proxies []C.Proxy) {
	if target == "" || len(proxies) == 0 {
		return
	}

	targetKey := FormatDBKey(config, group, target)
	if existing, expireTime, found := unwrapCache.GetWithExpire(targetKey); !found || len(existing.Proxies) == 0 || expireTime.Before(time.Now()) {
		names := make([]string, len(proxies))
		for i, p := range proxies {
			names[i] = p.Name()
		}
		unwrapCache.Set(targetKey, UnwrapMap{Proxies: names})
	}
}

func (s *Store) GetUnwrapResult(group, config, target string) (proxies []string, expired bool) {
	if target == "" {
		return nil, false
	}

	targetKey := FormatDBKey(config, group, target)
	if value, expireTime, found := unwrapCache.GetWithExpire(targetKey); found {
		if len(value.Proxies) > 0 {
			return value.Proxies, expireTime.Before(time.Now())
		}
	}

	return nil, false
}

func (s *Store) DeleteUnwrapResult(group, config string, target string) {
	if target == "" {
		return
	}

	unwrapCache.Delete(FormatDBKey(config, group, target))
}

func (s *Store) UpdateBlockedNodesCache(group, config string, updates map[string]*NodeState) {
	cacheKey := FormatDBKey(config, group)
	blocked, _, _ := blockedNodesCache.GetWithExpire(cacheKey)

	newBlocked := make(map[string]bool, len(blocked)+len(updates))
	for k, v := range blocked {
		newBlocked[k] = v
	}

	now := time.Now().Unix()

	for node, state := range updates {
		if state == nil {
			continue
		}
		if state.BlockedUntil > 0 && state.BlockedUntil > now {
			newBlocked[node] = true
		} else {
			delete(newBlocked, node)
		}
	}

	blockedNodesCache.Set(cacheKey, newBlocked)
}

func (s *Store) loadBlockedNodes(group, config string) map[string]bool {
	cacheKey := FormatDBKey(config, group)
	stateData, err := s.GetNodeStates(group, config)
	if err != nil {
		return nil
	}
	now := time.Now().Unix()
	blockedNodes := make(map[string]bool)

	for nodeName, data := range stateData {
		var state NodeState
		if json.Unmarshal(data, &state) == nil {
			if state.BlockedUntil > 0 && state.BlockedUntil > now {
				blockedNodes[nodeName] = true
			}
		}
	}

	blockedNodesCache.Set(cacheKey, blockedNodes)
	return blockedNodes
}

func (s *Store) GetBlockedNodes(group, config string) map[string]bool {
	cacheKey := FormatDBKey(config, group)
	if cached, expireTime, ok := blockedNodesCache.GetWithExpire(cacheKey); ok {
		if expireTime.Before(time.Now()) {
			if _, loading := blockedNodesRefreshFlags.LoadOrStore(cacheKey, true); !loading {
				go func() {
					defer blockedNodesRefreshFlags.Delete(cacheKey)
					s.loadBlockedNodes(group, config)
				}()
			}
		}
		return cached
	}
	return s.loadBlockedNodes(group, config)
}

func (s *Store) AdjustCacheParameters() {
	cacheAdjustMutex.Lock()
	defer cacheAdjustMutex.Unlock()

	memoryUsage := GetSystemMemoryUsage()

	globalCacheParams.mutex.Lock()

	isFirstRun := globalCacheParams.LastMemoryUsage == 0
	needAdjust := isFirstRun

	if !isFirstRun {
		memoryChanged := math.Abs(memoryUsage-globalCacheParams.LastMemoryUsage) > 0.05
		needAdjust = memoryChanged
	}

	globalCacheParams.LastMemoryUsage = memoryUsage

	if !needAdjust && !isFirstRun {
		globalCacheParams.mutex.Unlock()
		return
	}

	if memoryUsage > 0.9 {
		globalCacheParams.MaxTargets = MinTargetsLimit
		globalCacheParams.BatchSaveThreshold = MinBatchThreshLimit
	} else {
		adjustFactor := (1 - memoryUsage) * 0.5
		globalCacheParams.MaxTargets = MinTargetsLimit + int(float64(MaxTargetsLimit-MinTargetsLimit)*adjustFactor)
		globalCacheParams.BatchSaveThreshold = MinBatchThreshLimit + int(float64(MaxBatchThreshLimit-MinBatchThreshLimit)*adjustFactor)
	}
	maxTargets := globalCacheParams.MaxTargets
	batchSaveThreshold := globalCacheParams.BatchSaveThreshold
	globalCacheParams.mutex.Unlock()

	log.Infoln("[SmartStore] Parameters adjusted: MaxTargets=%d, BatchThreshold=%d",
		maxTargets,
		batchSaveThreshold)

	cacheSize := maxTargets / 4
	targetCache.Resize(cacheSize)
	unwrapCache.Resize(cacheSize)
	recordCache.Resize(cacheSize)
	dbResultCache.Resize(cacheSize)
	blockedNodesCache.Resize(cacheSize)
	hostStatusCache.Resize(cacheSize)
	go s.FlushQueue(true)
}

func (s *Store) clearCache(level string, config string, group string) {
	s.FlushQueue(true)
	invalidateASNEvidence(level, config, group)

	if level == "all" {
		targetCache.Clear()
		unwrapCache.Clear()
		recordCache.Clear()
		dbResultCache.Clear()
		blockedNodesCache.Clear()
		hostStatusCache.Clear()
		return
	}

	targetCache.Clear()

	if level == "config" {
		unwrapCache.RemoveByKeyPrefix(FormatDBKey(config) + "/")
		recordCache.RemoveByKeyPrefix(FormatDBKey(KeyTypeStats, config) + "/")
		for _, kt := range []string{KeyTypeStats, KeyTypeNode, KeyTypePrefetch, KeyTypeRanking, KeyTypeHostFailures} {
			dbResultCache.RemoveByKeyPrefix(FormatDBKey(kt, config) + "/")
		}
		blockedNodesCache.RemoveByKeyPrefix(FormatDBKey(config) + "/")
		hostStatusCache.RemoveByKeyPrefix(FormatDBKey(KeyTypeHostFailures, config) + "/")
	} else if level == "group" {
		groupKey := FormatDBKey(config, group) // "smart/{config}/{group}"
		unwrapCache.RemoveByKeyPrefix(groupKey + "/")
		recordCache.RemoveByKeyPrefix(FormatDBKey(KeyTypeStats, config, group) + "/")
		for _, kt := range []string{KeyTypeStats, KeyTypeNode, KeyTypePrefetch, KeyTypeRanking, KeyTypeHostFailures} {
			dbResultCache.Delete(FormatDBKey(kt, config, group))
		}
		blockedNodesCache.Delete(groupKey)
		hostStatusCache.RemoveByKeyPrefix(FormatDBKey(KeyTypeHostFailures, config, group) + "/")
	}
}

func GetBatchSaveThreshold() int {
	globalCacheParams.mutex.RLock()
	defer globalCacheParams.mutex.RUnlock()

	if globalCacheParams.BatchSaveThreshold <= 0 {
		return MinBatchThreshLimit
	}

	return globalCacheParams.BatchSaveThreshold
}

// 获取系统内存使用情况
//
// systemMemoryUsage is provided per platform; when it cannot read the system
// figures we fall back to a neutral 0.5 so cache sizing stays in its mid range.
func GetSystemMemoryUsage() float64 {
	if usage, ok := systemMemoryUsage(); ok {
		return usage
	}
	return 0.5
}

func readProcMemoryUsage(readFile func(string) ([]byte, error)) (float64, bool) {
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}

	var totalKB, availableKB uint64
	var foundTotal, foundAvailable bool
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || (name != "MemTotal" && name != "MemAvailable") {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		memoryKB, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			continue
		}
		if name == "MemTotal" {
			totalKB = memoryKB
			foundTotal = true
		} else {
			availableKB = memoryKB
			foundAvailable = true
		}
	}

	if !foundTotal || !foundAvailable || totalKB == 0 {
		return 0, false
	}
	if availableKB >= totalKB {
		return 0, true
	}
	return float64(totalKB-availableKB) / float64(totalKB), true
}

var cacheAdjustMutex sync.Mutex

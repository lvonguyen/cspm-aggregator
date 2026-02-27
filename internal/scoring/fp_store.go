package scoring

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// FPRecord holds false-positive and true-positive counts for a finding type.
type FPRecord struct {
	TotalCount  int
	FPCount     int
	LastUpdated time.Time
}

// FPRate returns the false-positive rate (0.0–1.0). Returns 0 when TotalCount is 0.
func (r FPRecord) FPRate() float64 {
	if r.TotalCount == 0 {
		return 0
	}
	return float64(r.FPCount) / float64(r.TotalCount)
}

// InMemoryFPStore is a thread-safe in-memory implementation of FPHistoryStore.
// It is suitable for testing and single-process deployments; for multi-replica
// deployments, replace with a persistent backend.
type InMemoryFPStore struct {
	mu      sync.RWMutex
	records map[string]*FPRecord // key: findingType+"|"+resourceType
}

// NewInMemoryFPStore creates an empty InMemoryFPStore.
func NewInMemoryFPStore() *InMemoryFPStore {
	return &InMemoryFPStore{
		records: make(map[string]*FPRecord),
	}
}

// GetFPStats returns the false-positive count and rate for the given
// findingType + resourceType combination.
func (s *InMemoryFPStore) GetFPStats(_ context.Context, findingType, resourceType string) (int, float64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.records[storeKey(findingType, resourceType)]
	if !ok {
		return 0, 0, nil
	}
	return rec.FPCount, rec.FPRate(), nil
}

// RecordFP records one false-positive observation for the given combination.
func (s *InMemoryFPStore) RecordFP(_ context.Context, findingType, resourceType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := storeKey(findingType, resourceType)
	rec := s.getOrCreate(key)
	rec.FPCount++
	rec.TotalCount++
	rec.LastUpdated = time.Now()
	return nil
}

// RecordTP records one true-positive observation for the given combination.
// This method is not part of the FPHistoryStore interface but is provided for
// completeness so callers can build an accurate total count alongside FP counts.
func (s *InMemoryFPStore) RecordTP(_ context.Context, findingType, resourceType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := storeKey(findingType, resourceType)
	rec := s.getOrCreate(key)
	rec.TotalCount++
	rec.LastUpdated = time.Now()
	return nil
}

// Snapshot returns a copy of all stored records, keyed by findingType+"|"+resourceType.
// Useful for testing and diagnostics.
func (s *InMemoryFPStore) Snapshot() map[string]FPRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]FPRecord, len(s.records))
	for k, v := range s.records {
		out[k] = *v
	}
	return out
}

// getOrCreate returns the record for key, inserting an empty one if absent.
// Caller must hold the write lock.
func (s *InMemoryFPStore) getOrCreate(key string) *FPRecord {
	rec, ok := s.records[key]
	if !ok {
		rec = &FPRecord{}
		s.records[key] = rec
	}
	return rec
}

// storeKey creates a stable map key from findingType and resourceType.
func storeKey(findingType, resourceType string) string {
	return fmt.Sprintf("%s|%s", findingType, resourceType)
}

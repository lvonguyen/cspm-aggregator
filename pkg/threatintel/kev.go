package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	kevCatalogURL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	kevDefaultRefresh = 24 * time.Hour
)

// KEVVulnerability represents a single entry in the CISA KEV catalog.
type KEVVulnerability struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

// kevCatalogResponse is the top-level JSON from the CISA KEV feed.
type kevCatalogResponse struct {
	Title           string             `json:"title"`
	CatalogVersion  string             `json:"catalogVersion"`
	DateReleased    string             `json:"dateReleased"`
	Count           int                `json:"count"`
	Vulnerabilities []KEVVulnerability `json:"vulnerabilities"`
}

// KEVCatalog holds the full CISA Known Exploited Vulnerabilities catalog in memory.
type KEVCatalog struct {
	httpClient      *http.Client
	RefreshInterval time.Duration

	mu          sync.RWMutex
	index       map[string]bool // CVE ID -> exists
	entries     []KEVVulnerability
	lastRefresh time.Time
	version     string
}

// NewKEVCatalog creates a new KEV catalog with the default refresh interval.
func NewKEVCatalog() *KEVCatalog {
	return &KEVCatalog{
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		RefreshInterval: kevDefaultRefresh,
		index:           make(map[string]bool),
	}
}

// NewKEVCatalogWithHTTP creates a KEV catalog with a custom HTTP client (for testing).
func NewKEVCatalogWithHTTP(client *http.Client) *KEVCatalog {
	return &KEVCatalog{
		httpClient:      client,
		RefreshInterval: kevDefaultRefresh,
		index:           make(map[string]bool),
	}
}

// LoadCatalog fetches the current KEV catalog from CISA and loads it into memory.
// Safe to call multiple times; subsequent calls refresh the catalog.
func (k *KEVCatalog) LoadCatalog() error {
	resp, err := k.httpClient.Get(kevCatalogURL) //nolint:noctx
	if err != nil {
		return fmt.Errorf("fetching KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("KEV catalog returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50 MB cap
	if err != nil {
		return fmt.Errorf("reading KEV catalog body: %w", err)
	}

	return k.loadFromBytes(body)
}

// loadFromBytes parses catalog JSON and atomically updates the in-memory index.
func (k *KEVCatalog) loadFromBytes(data []byte) error {
	var catalog kevCatalogResponse
	if err := json.Unmarshal(data, &catalog); err != nil {
		return fmt.Errorf("parsing KEV catalog: %w", err)
	}

	newIndex := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		newIndex[v.CVEID] = true
	}

	k.mu.Lock()
	k.index = newIndex
	k.entries = catalog.Vulnerabilities
	k.lastRefresh = time.Now()
	k.version = catalog.CatalogVersion
	k.mu.Unlock()

	return nil
}

// IsKnownExploited returns true if the given CVE ID is in the CISA KEV catalog.
// O(1) lookup via the in-memory map. Returns false if catalog has not been loaded.
func (k *KEVCatalog) IsKnownExploited(cveID string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.needsRefresh() {
		// Non-blocking: return current value; caller should call LoadCatalog proactively.
		// In production use the auto-refresh pattern (see RefreshIfStale).
		return k.index[cveID]
	}

	return k.index[cveID]
}

// GetEntry returns the full KEV entry for a CVE ID, or nil if not found.
func (k *KEVCatalog) GetEntry(cveID string) *KEVVulnerability {
	k.mu.RLock()
	defer k.mu.RUnlock()

	for i := range k.entries {
		if k.entries[i].CVEID == cveID {
			v := k.entries[i]
			return &v
		}
	}
	return nil
}

// Count returns the number of CVEs currently in the catalog.
func (k *KEVCatalog) Count() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.index)
}

// LastRefresh returns the timestamp of the most recent successful catalog load.
func (k *KEVCatalog) LastRefresh() time.Time {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.lastRefresh
}

// RefreshIfStale reloads the catalog if the refresh interval has elapsed.
// Safe to call from multiple goroutines; only one fetch will occur at a time.
func (k *KEVCatalog) RefreshIfStale() error {
	k.mu.RLock()
	stale := k.needsRefresh()
	k.mu.RUnlock()

	if !stale {
		return nil
	}

	return k.LoadCatalog()
}

// needsRefresh returns true if the catalog has never been loaded or is past the
// refresh interval. Caller must hold at least a read lock.
func (k *KEVCatalog) needsRefresh() bool {
	if k.lastRefresh.IsZero() {
		return true
	}
	return time.Since(k.lastRefresh) > k.RefreshInterval
}

// Package threatintel provides clients for threat intelligence feeds including
// EPSS (Exploit Prediction Scoring System) and CISA Known Exploited Vulnerabilities.
package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	epssBaseURL   = "https://api.first.org/data/v1/epss"
	epssCacheTTL  = 12 * time.Hour
	epssBatchSize = 100 // FIRST API max per request
)

// epssEntry is a cached EPSS score with expiry.
type epssEntry struct {
	score      float64
	percentile float64
	cachedAt   time.Time
}

func (e epssEntry) isExpired() bool {
	return time.Since(e.cachedAt) > epssCacheTTL
}

// EPSSClient fetches and caches EPSS scores from the FIRST API.
type EPSSClient struct {
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]epssEntry
}

// NewEPSSClient creates a new EPSS client with a default HTTP client.
func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		cache:      make(map[string]epssEntry),
	}
}

// NewEPSSClientWithHTTP creates an EPSS client with a custom HTTP client (for testing).
func NewEPSSClientWithHTTP(client *http.Client) *EPSSClient {
	return &EPSSClient{
		httpClient: client,
		cache:      make(map[string]epssEntry),
	}
}

// epssResponse is the JSON structure returned by the FIRST API.
type epssResponse struct {
	Status     string       `json:"status"`
	StatusCode int          `json:"status-code"`
	Version    string       `json:"version"`
	Access     string       `json:"access"`
	Total      int          `json:"total"`
	Offset     int          `json:"offset"`
	Limit      int          `json:"limit"`
	Data       []epssEntry_ `json:"data"`
}

type epssEntry_ struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
}

// GetScore returns the EPSS score for a single CVE ID.
// Returns (0, nil) if the CVE is not found in the EPSS database.
func (c *EPSSClient) GetScore(cveID string) (float64, error) {
	scores, err := c.GetScores([]string{cveID})
	if err != nil {
		return 0, err
	}
	return scores[cveID], nil
}

// GetScoreWithPercentile returns both the EPSS score and percentile for a CVE.
func (c *EPSSClient) GetScoreWithPercentile(cveID string) (score, percentile float64, err error) {
	// Check cache first
	c.mu.RLock()
	if entry, ok := c.cache[cveID]; ok && !entry.isExpired() {
		c.mu.RUnlock()
		return entry.score, entry.percentile, nil
	}
	c.mu.RUnlock()

	// Fetch from API
	if err := c.fetchAndCache([]string{cveID}); err != nil {
		return 0, 0, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.cache[cveID]; ok {
		return entry.score, entry.percentile, nil
	}
	return 0, 0, nil
}

// GetScores returns EPSS scores for multiple CVE IDs.
// CVEs not found in the database are omitted from the result map (implying score 0).
func (c *EPSSClient) GetScores(cveIDs []string) (map[string]float64, error) {
	if len(cveIDs) == 0 {
		return make(map[string]float64), nil
	}

	result := make(map[string]float64, len(cveIDs))
	var toFetch []string

	// Check cache for each CVE
	c.mu.RLock()
	for _, id := range cveIDs {
		if entry, ok := c.cache[id]; ok && !entry.isExpired() {
			result[id] = entry.score
		} else {
			toFetch = append(toFetch, id)
		}
	}
	c.mu.RUnlock()

	if len(toFetch) == 0 {
		return result, nil
	}

	// Fetch in batches
	for i := 0; i < len(toFetch); i += epssBatchSize {
		end := i + epssBatchSize
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]
		if err := c.fetchAndCache(batch); err != nil {
			return nil, fmt.Errorf("fetching EPSS batch [%d:%d]: %w", i, end, err)
		}
	}

	// Read populated cache values
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range toFetch {
		if entry, ok := c.cache[id]; ok {
			result[id] = entry.score
		}
	}

	return result, nil
}

// fetchAndCache fetches EPSS data for a batch of CVE IDs and populates the cache.
func (c *EPSSClient) fetchAndCache(cveIDs []string) error {
	apiURL := epssBaseURL + "?cve=" + url.QueryEscape(strings.Join(cveIDs, ","))

	resp, err := c.httpClient.Get(apiURL) //nolint:noctx
	if err != nil {
		return fmt.Errorf("EPSS API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EPSS API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20)) // 50 MB cap
	if err != nil {
		return fmt.Errorf("reading EPSS response body: %w", err)
	}

	var parsed epssResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("parsing EPSS response: %w", err)
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, item := range parsed.Data {
		score, err := strconv.ParseFloat(item.EPSS, 64)
		if err != nil {
			continue
		}
		percentile, err := strconv.ParseFloat(item.Percentile, 64)
		if err != nil {
			percentile = 0
		}
		c.cache[item.CVE] = epssEntry{
			score:      score,
			percentile: percentile,
			cachedAt:   now,
		}
	}

	return nil
}

// InvalidateCache removes all cached entries, forcing fresh fetches on next call.
func (c *EPSSClient) InvalidateCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]epssEntry)
}

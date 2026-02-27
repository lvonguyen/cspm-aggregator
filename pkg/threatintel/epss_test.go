package threatintel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockEPSSResponse returns a minimal valid EPSS API response.
func mockEPSSResponse(cves []struct{ id, epss, pct string }) string {
	data := `{"status":"OK","status-code":200,"version":"1.0","access":"public","total":` +
		itoa(len(cves)) + `,"offset":0,"limit":100,"data":[`
	for i, c := range cves {
		if i > 0 {
			data += ","
		}
		data += `{"cve":"` + c.id + `","epss":"` + c.epss + `","percentile":"` + c.pct + `","date":"2024-01-01"}`
	}
	data += `]}`
	return data
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func newMockServer(body string, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}

func TestGetScore_SingleCVE(t *testing.T) {
	srv := newMockServer(mockEPSSResponse([]struct{ id, epss, pct string }{
		{"CVE-2021-44228", "0.97542", "0.99990"},
	}), http.StatusOK)
	defer srv.Close()

	client := NewEPSSClientWithHTTP(patchHTTPClientURL(srv.URL))
	score, err := client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score < 0.97 || score > 0.98 {
		t.Errorf("expected ~0.97542, got %f", score)
	}
}

func TestGetScore_NotFound(t *testing.T) {
	srv := newMockServer(`{"status":"OK","status-code":200,"version":"1.0","access":"public","total":0,"offset":0,"limit":100,"data":[]}`, http.StatusOK)
	defer srv.Close()

	client := NewEPSSClientWithHTTP(patchHTTPClientURL(srv.URL))
	score, err := client.GetScore("CVE-9999-99999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if score != 0 {
		t.Errorf("expected 0 for unknown CVE, got %f", score)
	}
}

func TestGetScores_Batch(t *testing.T) {
	body := mockEPSSResponse([]struct{ id, epss, pct string }{
		{"CVE-2021-44228", "0.97542", "0.99990"},
		{"CVE-2021-26084", "0.97234", "0.99980"},
		{"CVE-2022-22965", "0.96800", "0.99970"},
	})
	srv := newMockServer(body, http.StatusOK)
	defer srv.Close()

	client := NewEPSSClientWithHTTP(patchHTTPClientURL(srv.URL))
	scores, err := client.GetScores([]string{"CVE-2021-44228", "CVE-2021-26084", "CVE-2022-22965"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scores) != 3 {
		t.Errorf("expected 3 scores, got %d", len(scores))
	}
	if scores["CVE-2021-44228"] < 0.97 {
		t.Errorf("CVE-2021-44228 score too low: %f", scores["CVE-2021-44228"])
	}
}

func TestGetScore_Caching(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockEPSSResponse([]struct{ id, epss, pct string }{
			{"CVE-2021-44228", "0.97542", "0.99990"},
		})))
	}))
	defer srv.Close()

	client := NewEPSSClientWithHTTP(patchHTTPClientURL(srv.URL))

	// First call — should hit server
	_, err := client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Second call — should use cache (no additional HTTP request)
	_, err = client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected exactly 1 HTTP call, got %d (caching not working)", callCount)
	}
}

func TestGetScore_CacheExpiry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockEPSSResponse([]struct{ id, epss, pct string }{
			{"CVE-2021-44228", "0.97542", "0.99990"},
		})))
	}))
	defer srv.Close()

	client := NewEPSSClientWithHTTP(patchHTTPClientURL(srv.URL))

	// Seed cache with an expired entry
	client.mu.Lock()
	client.cache["CVE-2021-44228"] = epssEntry{
		score:    0.5,
		cachedAt: time.Now().Add(-25 * time.Hour), // expired
	}
	client.mu.Unlock()

	score, err := client.GetScore("CVE-2021-44228")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	// Should have fetched fresh data
	if callCount != 1 {
		t.Errorf("expected 1 HTTP call for stale entry, got %d", callCount)
	}
	if score < 0.97 {
		t.Errorf("expected refreshed score ~0.97, got %f", score)
	}
}

func TestGetScores_EmptyInput(t *testing.T) {
	client := NewEPSSClient()
	scores, err := client.GetScores(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(scores) != 0 {
		t.Errorf("expected empty map for nil input, got %v", scores)
	}
}

func TestGetScore_HTTPError(t *testing.T) {
	srv := newMockServer("internal server error", http.StatusInternalServerError)
	defer srv.Close()

	client := NewEPSSClientWithHTTP(patchHTTPClientURL(srv.URL))
	_, err := client.GetScore("CVE-2021-44228")
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

// patchHTTPClientURL returns an *http.Client whose transport rewrites all requests
// to the given test server URL. This allows using the actual client code unchanged.
func patchHTTPClientURL(serverURL string) *http.Client {
	return &http.Client{
		Transport: &urlRewriteTransport{base: serverURL},
	}
}

// urlRewriteTransport rewrites all requests to a fixed base URL (test server).
type urlRewriteTransport struct {
	base string
}

func (t *urlRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Preserve query string, rewrite host/scheme to test server
	newURL := t.base + "?" + req.URL.RawQuery
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

package threatintel

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const sampleKEVCatalog = `{
  "title": "CISA Known Exploited Vulnerabilities Catalog",
  "catalogVersion": "2024.01.01",
  "dateReleased": "2024-01-01T00:00:00Z",
  "count": 3,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    },
    {
      "cveID": "CVE-2021-26084",
      "vendorProject": "Atlassian",
      "product": "Confluence Server and Data Center",
      "vulnerabilityName": "Atlassian Confluence Server OGNL Injection Vulnerability",
      "dateAdded": "2021-11-03",
      "shortDescription": "Atlassian Confluence Server and Data Center contain an OGNL injection vulnerability.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-11-17",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    },
    {
      "cveID": "CVE-2022-22965",
      "vendorProject": "VMware",
      "product": "Spring Framework",
      "vulnerabilityName": "Spring Framework Remote Code Execution Vulnerability",
      "dateAdded": "2022-04-04",
      "shortDescription": "Spring MVC or Spring WebFlux running on JDK 9+ may be vulnerable to remote code execution.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2022-04-25",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": ""
    }
  ]
}`

func newKEVTestServer(body string, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}

func TestLoadCatalog_Success(t *testing.T) {
	srv := newKEVTestServer(sampleKEVCatalog, http.StatusOK)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	if cat.Count() != 3 {
		t.Errorf("expected 3 entries, got %d", cat.Count())
	}
}

func TestIsKnownExploited_Present(t *testing.T) {
	srv := newKEVTestServer(sampleKEVCatalog, http.StatusOK)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	cases := []string{"CVE-2021-44228", "CVE-2021-26084", "CVE-2022-22965"}
	for _, cve := range cases {
		if !cat.IsKnownExploited(cve) {
			t.Errorf("expected %s to be in KEV catalog", cve)
		}
	}
}

func TestIsKnownExploited_Absent(t *testing.T) {
	srv := newKEVTestServer(sampleKEVCatalog, http.StatusOK)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	if cat.IsKnownExploited("CVE-9999-99999") {
		t.Error("expected CVE-9999-99999 to NOT be in KEV catalog")
	}
}

func TestIsKnownExploited_EmptyCatalog(t *testing.T) {
	cat := NewKEVCatalog()
	// Catalog not loaded — should return false, not panic
	if cat.IsKnownExploited("CVE-2021-44228") {
		t.Error("expected false for unloaded catalog")
	}
}

func TestGetEntry_Found(t *testing.T) {
	srv := newKEVTestServer(sampleKEVCatalog, http.StatusOK)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	entry := cat.GetEntry("CVE-2021-44228")
	if entry == nil {
		t.Fatal("expected entry for CVE-2021-44228, got nil")
	}
	if entry.VendorProject != "Apache" {
		t.Errorf("expected vendor Apache, got %s", entry.VendorProject)
	}
}

func TestGetEntry_NotFound(t *testing.T) {
	srv := newKEVTestServer(sampleKEVCatalog, http.StatusOK)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}

	if entry := cat.GetEntry("CVE-9999-99999"); entry != nil {
		t.Errorf("expected nil for unknown CVE, got %+v", entry)
	}
}

func TestRefreshIfStale_NotStale(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleKEVCatalog))
	}))
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err != nil {
		t.Fatalf("initial load failed: %v", err)
	}

	// Should not trigger refresh since we just loaded
	if err := cat.RefreshIfStale(); err != nil {
		t.Fatalf("RefreshIfStale failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call, got %d (RefreshIfStale refreshed a fresh catalog)", callCount)
	}
}

func TestRefreshIfStale_Stale(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleKEVCatalog))
	}))
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	// Simulate stale catalog by setting lastRefresh in the past
	cat.mu.Lock()
	cat.lastRefresh = time.Now().Add(-25 * time.Hour)
	cat.mu.Unlock()

	if err := cat.RefreshIfStale(); err != nil {
		t.Fatalf("RefreshIfStale failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call for stale catalog, got %d", callCount)
	}
}

func TestLoadCatalog_HTTPError(t *testing.T) {
	srv := newKEVTestServer("bad gateway", http.StatusBadGateway)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err == nil {
		t.Error("expected error for 502 response, got nil")
	}
}

func TestLoadCatalog_InvalidJSON(t *testing.T) {
	srv := newKEVTestServer("not-json", http.StatusOK)
	defer srv.Close()

	cat := newKEVCatalogWithURL(srv.URL)
	if err := cat.LoadCatalog(); err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// newKEVCatalogWithURL returns a KEVCatalog that fetches from the given test URL.
func newKEVCatalogWithURL(serverURL string) *KEVCatalog {
	cat := NewKEVCatalogWithHTTP(&http.Client{
		Transport: &fixedURLTransport{url: serverURL},
	})
	return cat
}

// fixedURLTransport redirects all requests to a fixed URL (ignores the original URL).
type fixedURLTransport struct {
	url string
}

func (t *fixedURLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, t.url, req.Body)
	if err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(newReq)
}

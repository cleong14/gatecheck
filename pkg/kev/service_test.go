package kev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetch(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		catalog := &Catalog{Title: "Mock Catalog", CatalogVersion: "Mock Version", DateReleased: time.Now(), Count: 1,
			Vulnerabilities: []Vulnerability{{CveID: "abc-123"}}}
		_ = json.NewEncoder(w).Encode(catalog)
	}))

	_, err := NewServiceFromAPI(mockServer.URL, mockServer.Client())
	if err != nil {
		t.Fatal(err)
	}
}

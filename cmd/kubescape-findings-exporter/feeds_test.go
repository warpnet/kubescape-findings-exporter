package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// The EPSS file starts with a comment line holding the model version and the score date, then a CSV header.
const epssCSV = "#model_version:v2025.03.14,score_date:2026-11-08T12:55:00Z\n" +
	"cve,epss,percentile\n" +
	"CVE-2024-1,0.12345,0.98765\n" +
	"CVE-2024-2,0.00042,0.10000\n"

func TestParseEPSS(t *testing.T) {
	f, err := parseEPSS(bytes.NewReader(gz(t, epssCSV)))
	if err != nil {
		t.Fatal(err)
	}
	m := f.Scores
	if len(m) != 2 || m["CVE-2024-1"] != (EPSS{0.12345, 0.98765}) || m["CVE-2024-2"] != (EPSS{0.00042, 0.1}) {
		t.Fatalf("got %+v", m)
	}
	if want := time.Date(2026, 11, 8, 12, 55, 0, 0, time.UTC); !f.Date.Equal(want) {
		t.Fatalf("Date = %v, want %v (score_date)", f.Date, want)
	}
}

func TestParseEPSSRejectsBadInput(t *testing.T) {
	if _, err := parseEPSS(strings.NewReader("not gzip")); err == nil {
		t.Error("plain text: want an error")
	}
	if _, err := parseEPSS(bytes.NewReader(gz(t, "#score_date:2026-11-08T12:55:00Z\ncve,epss,percentile\nCVE-2024-1,abc,0.5\n"))); err == nil {
		t.Error("unparsable score: want an error")
	}
	// Without its date the data's age is unknown, and the stale-data alert would stay silent.
	if _, err := parseEPSS(bytes.NewReader(gz(t, "cve,epss,percentile\nCVE-2024-1,0.1,0.5\n"))); err == nil {
		t.Error("no score_date: want an error")
	}
	if _, err := parseEPSS(bytes.NewReader(gz(t, "#only a comment\n"))); err == nil {
		t.Error("no scores: want an error, an empty feed must not wipe the previous one")
	}
}

const kevJSON = `{"catalogVersion":"2026.11.07","dateReleased":"2026-11-07T19:44:45.1797Z","vulnerabilities":[
 {"cveID":"CVE-2024-1","knownRansomwareCampaignUse":"Known"},
 {"cveID":"CVE-2024-3","knownRansomwareCampaignUse":"Unknown"}]}`

func TestParseKEV(t *testing.T) {
	f, err := parseKEV(strings.NewReader(kevJSON))
	if err != nil {
		t.Fatal(err)
	}
	m := f.Entries
	if len(m) != 2 || m["CVE-2024-1"] != "known" || m["CVE-2024-3"] != "unknown" {
		t.Fatalf("got %+v", m)
	}
	if want := time.Date(2026, 11, 7, 19, 44, 45, 179700000, time.UTC); !f.Released.Equal(want) {
		t.Fatalf("Released = %v, want %v (dateReleased)", f.Released, want)
	}
	if _, err := parseKEV(strings.NewReader(`{"dateReleased":"2026-11-07T19:44:45Z","vulnerabilities":[]}`)); err == nil {
		t.Error("empty catalog: want an error, an empty feed must not wipe the previous one")
	}
	if _, err := parseKEV(strings.NewReader(`{"vulnerabilities":[{"cveID":"CVE-2024-1"}]}`)); err == nil {
		t.Error("no dateReleased: want an error")
	}
}

func TestFetchFeedErrorOnStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := fetchFeed(context.Background(), srv.Client(), srv.URL, parseKEV); err == nil {
		t.Fatal("want an error on a 503")
	}
}

func TestNextFeedDelay(t *testing.T) {
	if d := nextFeedDelay(nil, 24*time.Hour); d != 24*time.Hour {
		t.Errorf("success: got %v, want the interval", d)
	}
	if d := nextFeedDelay(errors.New("boom"), 24*time.Hour); d != time.Hour {
		t.Errorf("failure: got %v, want a retry after an hour", d)
	}
	if d := nextFeedDelay(errors.New("boom"), 10*time.Minute); d != 10*time.Minute {
		t.Errorf("failure with a short interval: got %v, want the interval", d)
	}
}

const frameworksCSV = `frameworkName,ControlID,ControlName
NSA,C-0013,Non-root containers
AllControls,C-0013,Non-root containers
cis-v1.12.0,C-0057,"Privileged container, or not"
AllControls,C-0057,"Privileged container, or not"
`

func TestParseFrameworks(t *testing.T) {
	f, err := parseFrameworks(strings.NewReader(frameworksCSV))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Frameworks["C-0013"]; !slices.Equal(got, []string{"AllControls", "NSA"}) {
		t.Errorf("Frameworks[C-0013] = %v, want [AllControls NSA]", got)
	}
	if got := f.Frameworks["C-0057"]; !slices.Equal(got, []string{"AllControls", "cis-v1.12.0"}) {
		t.Errorf("Frameworks[C-0057] = %v, want [AllControls cis-v1.12.0]", got)
	}
	if f.Names["C-0013"] != "Non-root containers" || f.Names["C-0057"] != "Privileged container, or not" {
		t.Errorf("Names = %v", f.Names)
	}
	if _, err := parseFrameworks(strings.NewReader("cve,epss,percentile\nCVE-1,0.1,0.2\n")); err == nil {
		t.Error("wrong header: want an error")
	}
	if _, err := parseFrameworks(strings.NewReader("")); err == nil {
		t.Error("empty body: want an error, an empty feed must not wipe the previous one")
	}
	if _, err := parseFrameworks(strings.NewReader("frameworkName,ControlID,ControlName\n")); err == nil {
		t.Error("header only: want an error, an empty feed must not wipe the previous one")
	}
}

const sectionsJSON = `[
 {"name": "AllControls", "controls": [{"controlID": "C-0001", "rules": []}]},
 {"name": "cis-v1.12.0", "controls": [{"controlID": "C-0001"}], "subSections": {
  "10": {"id": "10", "name": "Ten", "controlsIDs": ["C-0100"]},
  "4": {"id": "4", "name": "Worker Nodes", "subSections": {
    "1": {"id": "4.1", "name": "Config files", "controlsIDs": ["C-0130", "C-0129"]},
    "2": {"id": "4.2", "name": "Kubelet", "controlsIDs": ["C-0130", "C-0131"]}}},
  "2": {"id": "2", "name": "etcd", "controlsIDs": ["C-0200"]}}}
]`

func TestParseSections(t *testing.T) {
	f, err := parseSections(strings.NewReader(sectionsJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := []Section{
		{"cis-v1.12.0", "2", "etcd", []string{"C-0200"}},
		{"cis-v1.12.0", "4", "Worker Nodes", []string{"C-0129", "C-0130", "C-0131"}},
		{"cis-v1.12.0", "10", "Ten", []string{"C-0100"}},
	}
	if !reflect.DeepEqual(f.Sections, want) {
		t.Errorf("Sections = %v, want %v", f.Sections, want)
	}
	for name, body := range map[string]string{"empty array": "[]", "invalid JSON": "{", "no subSections": `[{"name":"NSA"}]`} {
		if _, err := parseSections(strings.NewReader(body)); err == nil {
			t.Errorf("%s: want an error, an empty feed must not wipe the previous one", name)
		}
	}
}

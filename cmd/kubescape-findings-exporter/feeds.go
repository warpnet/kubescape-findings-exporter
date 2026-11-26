package main

import (
	"bufio"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// EPSS is the exploit prediction of one CVE (FIRST): the probability that it is exploited in the next 30 days, and
// where that probability ranks among all CVEs.
type EPSS struct{ Score, Percentile float64 }

// EPSSFeed is one day of EPSS scores; Date is the publisher's score_date.
type EPSSFeed struct {
	Scores map[string]EPSS
	Date   time.Time
}

// KEVFeed is CISA's Known Exploited Vulnerabilities catalog: CVE ID → known ransomware use ("known" or "unknown");
// Released is the catalog's dateReleased.
type KEVFeed struct {
	Entries  map[string]string
	Released time.Time
}

// FrameworksFeed is regolibrary's control-to-framework mapping: control ID → the frameworks it is in (sorted), and
// control ID → its name.
type FrameworksFeed struct {
	Frameworks map[string][]string
	Names      map[string]string
}

// SectionsFeed is the CIS sections of regolibrary's frameworks, sorted by framework, then numeric-aware ID.
type SectionsFeed struct{ Sections []Section }

// Section is one top-level CIS section (e.g. "4" Worker Nodes) with every control below it (sorted, unique).
type Section struct {
	Framework, ID, Name string
	Controls            []string
}

// parseFrameworks reads regolibrary's FWName_CID_CName release asset: CSV with frameworkName,ControlID,ControlName.
func parseFrameworks(r io.Reader) (FrameworksFeed, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = 3
	header, err := cr.Read()
	if err != nil {
		return FrameworksFeed{}, fmt.Errorf("frameworks header: %w", err)
	}
	if header[0] != "frameworkName" || header[1] != "ControlID" || header[2] != "ControlName" {
		return FrameworksFeed{}, fmt.Errorf("frameworks header: unexpected %v", header)
	}
	f := FrameworksFeed{Frameworks: map[string][]string{}, Names: map[string]string{}}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return FrameworksFeed{}, fmt.Errorf("frameworks: %w", err)
		}
		if !slices.Contains(f.Frameworks[rec[1]], rec[0]) {
			f.Frameworks[rec[1]] = append(f.Frameworks[rec[1]], rec[0])
		}
		f.Names[rec[1]] = rec[2]
	}
	// An empty feed must not replace a good one.
	if len(f.Frameworks) == 0 {
		return FrameworksFeed{}, errors.New("frameworks: no controls")
	}
	for _, fws := range f.Frameworks {
		slices.Sort(fws)
	}
	return f, nil
}

// sectionNode is the part of a regolibrary framework's section tree that is needed here.
type sectionNode struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	ControlsIDs []string               `json:"controlsIDs"`
	SubSections map[string]sectionNode `json:"subSections"`
}

func (n sectionNode) controls() []string {
	ids := slices.Clone(n.ControlsIDs)
	for _, sub := range n.SubSections {
		ids = append(ids, sub.controls()...)
	}
	return ids
}

// parseSections reads regolibrary's "frameworks" release asset (JSON array). Only CIS frameworks have subSections;
// the large controls arrays are not decoded.
func parseSections(r io.Reader) (SectionsFeed, error) {
	var doc []struct {
		Name        string                 `json:"name"`
		SubSections map[string]sectionNode `json:"subSections"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return SectionsFeed{}, fmt.Errorf("sections: %w", err)
	}
	var f SectionsFeed
	for _, fw := range doc {
		for key, s := range fw.SubSections {
			ids := s.controls()
			slices.Sort(ids)
			f.Sections = append(f.Sections, Section{fw.Name, cmp.Or(s.ID, key), s.Name, slices.Compact(ids)})
		}
	}
	// An empty feed must not replace a good one.
	if len(f.Sections) == 0 {
		return SectionsFeed{}, errors.New("sections: no sections")
	}
	slices.SortFunc(f.Sections, func(a, b Section) int {
		if c := cmp.Compare(a.Framework, b.Framework); c != 0 {
			return c
		}
		x, errX := strconv.Atoi(a.ID)
		y, errY := strconv.Atoi(b.ID)
		if errX != nil || errY != nil {
			return cmp.Compare(a.ID, b.ID)
		}
		return cmp.Compare(x, y)
	})
	return f, nil
}

// parseEPSS reads the daily EPSS file: gzipped CSV, a comment line with the model version and the score date, then
// cve,epss,percentile. Plain CSV is accepted too, in case a CDN already decompressed it.
func parseEPSS(r io.Reader) (EPSSFeed, error) {
	in := bufio.NewReader(r)
	if magic, _ := in.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(in)
		if err != nil {
			return EPSSFeed{}, fmt.Errorf("epss: %w", err)
		}
		defer zr.Close()
		in = bufio.NewReader(zr)
	}
	// Comment lines carry the metadata, e.g. "#model_version:v2026.06.15,score_date:2026-11-08T12:00:26Z".
	var date time.Time
	for {
		if b, err := in.Peek(1); err != nil || b[0] != '#' {
			break
		}
		line, err := in.ReadString('\n')
		for _, field := range strings.Split(strings.TrimSpace(strings.TrimPrefix(line, "#")), ",") {
			if v, ok := strings.CutPrefix(field, "score_date:"); ok {
				date, _ = time.Parse(time.RFC3339, v)
			}
		}
		if err != nil {
			break
		}
	}
	// Without its date the data's age is unknown and the stale-data alert would stay silent.
	if date.IsZero() {
		return EPSSFeed{}, errors.New("epss: no score_date")
	}
	cr := csv.NewReader(in)
	cr.Comment = '#'
	cr.FieldsPerRecord = 3
	header, err := cr.Read()
	if err != nil {
		return EPSSFeed{}, fmt.Errorf("epss header: %w", err)
	}
	if header[0] != "cve" {
		return EPSSFeed{}, fmt.Errorf("epss header: unexpected %v", header)
	}
	m := map[string]EPSS{}
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return EPSSFeed{}, fmt.Errorf("epss: %w", err)
		}
		score, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			return EPSSFeed{}, fmt.Errorf("epss %s: %w", rec[0], err)
		}
		pct, err := strconv.ParseFloat(rec[2], 64)
		if err != nil {
			return EPSSFeed{}, fmt.Errorf("epss %s: %w", rec[0], err)
		}
		m[rec[0]] = EPSS{score, pct}
	}
	// An empty feed must not replace a good one.
	if len(m) == 0 {
		return EPSSFeed{}, errors.New("epss: no scores")
	}
	return EPSSFeed{Scores: m, Date: date}, nil
}

// parseKEV reads CISA's Known Exploited Vulnerabilities catalog (JSON).
func parseKEV(r io.Reader) (KEVFeed, error) {
	var doc struct {
		DateReleased    time.Time `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID      string `json:"cveID"`
			Ransomware string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return KEVFeed{}, fmt.Errorf("kev: %w", err)
	}
	m := map[string]string{}
	for _, v := range doc.Vulnerabilities {
		ransomware := strings.ToLower(v.Ransomware)
		if ransomware != "known" {
			ransomware = "unknown"
		}
		m[v.CVEID] = ransomware
	}
	if len(m) == 0 {
		return KEVFeed{}, errors.New("kev: no vulnerabilities")
	}
	if doc.DateReleased.IsZero() {
		return KEVFeed{}, errors.New("kev: no dateReleased")
	}
	return KEVFeed{Entries: m, Released: doc.DateReleased}, nil
}

// fetchFeed downloads url and parses it. Any error leaves the caller's previous data in place.
func fetchFeed[T any](ctx context.Context, hc *http.Client, url string, parse func(io.Reader) (T, error)) (T, error) {
	var zero T
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return zero, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return parse(resp.Body)
}

// nextFeedDelay is the wait before the next download: the interval after a success, at most an hour after a failure.
func nextFeedDelay(err error, interval time.Duration) time.Duration {
	if err != nil && interval > time.Hour {
		return time.Hour
	}
	return interval
}

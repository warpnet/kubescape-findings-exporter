package main

import (
	"cmp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	imageInfoDesc = prometheus.NewDesc("kubescape_image_info",
		"Image (digest) with a Kubescape scan result.",
		[]string{"image", "digest", "tag"}, nil)
	imageVulnDesc = prometheus.NewDesc("kubescape_image_vulnerability",
		"CVE in one package version of an image, from the Kubescape scan.",
		[]string{"image", "digest", "tag", "cve", "severity", "package", "version", "fixed_version", "fix_state"}, nil)
	relevantDesc = prometheus.NewDesc("kubescape_workload_vulnerability_relevant",
		"CVE whose package a workload container loads at runtime.",
		[]string{"namespace", "workload", "kind", "container", "digest", "cve", "package", "version"}, nil)
	exposureDesc = prometheus.NewDesc("kubescape_workload_exposure_info",
		"Workload reachable from outside the cluster, with its entry point.",
		[]string{"namespace", "workload", "kind", "via", "gateway", "hostname", "access"}, nil)
	lastSuccessDesc = prometheus.NewDesc("kubescape_cve_exporter_last_success_timestamp_seconds",
		"Unix time of the last complete list of Kubescape vulnerability manifests.", nil, nil)
	epssScoreDesc = prometheus.NewDesc("kubescape_cve_epss_score",
		"EPSS: probability that the CVE is exploited in the next 30 days (FIRST).", []string{"cve"}, nil)
	epssPercentileDesc = prometheus.NewDesc("kubescape_cve_epss_percentile",
		"EPSS percentile: share of all CVEs with a lower or equal score.", []string{"cve"}, nil)
	kevDesc = prometheus.NewDesc("kubescape_cve_kev",
		"CVE on CISA's Known Exploited Vulnerabilities list.", []string{"cve", "ransomware"}, nil)
	postureResourcesDesc = prometheus.NewDesc("kubescape_posture_control_resources",
		"Resources with one status for one Kubescape control, per namespace.",
		[]string{"namespace", "control", "status"}, nil)
	postureFailedDesc = prometheus.NewDesc("kubescape_posture_resource_failed",
		"Resource failing a Kubescape control; binding is set for RBAC subjects.",
		[]string{"namespace", "kind", "name", "binding", "control"}, nil)
	postureInfoDesc = prometheus.NewDesc("kubescape_posture_control_info",
		"Kubescape control on the cluster, with its name and severity.", []string{"control", "name", "severity"}, nil)
	postureFrameworkDesc = prometheus.NewDesc("kubescape_posture_framework_control",
		"Framework a Kubescape control belongs to: every control of regolibrary's frameworks; unmapped for a control "+
			"on the cluster that the feed does not know.",
		[]string{"framework", "control"}, nil)
	postureSectionDesc = prometheus.NewDesc("kubescape_posture_framework_section",
		"CIS section a Kubescape control belongs to, from regolibrary's frameworks.",
		[]string{"framework", "section", "section_name", "control"}, nil)
	postureLastScanDesc = prometheus.NewDesc("kubescape_posture_last_scan_timestamp_seconds",
		"Unix time of the newest Kubescape configuration scan report.", nil, nil)
	feedSuccessDesc = prometheus.NewDesc("kubescape_cve_exporter_feed_last_success_timestamp_seconds",
		"Unix time of the last successful download of a feed.", []string{"feed"}, nil)
	feedDataDesc = prometheus.NewDesc("kubescape_cve_exporter_feed_data_timestamp_seconds",
		"Unix time the feed's data was published (EPSS score_date, KEV dateReleased).", []string{"feed"}, nil)
)

// Collector serves the last complete Snapshot and the last downloaded EPSS, KEV, frameworks and sections feeds. Scrapes never read the
// storage API or the feeds.
type Collector struct {
	mu          sync.RWMutex
	snap        Snapshot
	ids         map[string]string // vulnerability IDs in the snapshot → the ID to look up in the feeds
	lastSuccess time.Time
	epss        map[string]EPSS
	kev         map[string]string
	frameworks  FrameworksFeed
	sections    SectionsFeed
	feedAt      map[string]time.Time // last successful download per feed
	dataAt      map[string]time.Time // publication time of the downloaded data per feed
}

func NewCollector() *Collector {
	return &Collector{feedAt: map[string]time.Time{}, dataAt: map[string]time.Time{}}
}

// Set replaces the served snapshot; at is the time of the list it was built from.
func (c *Collector) Set(s Snapshot, at time.Time) {
	ids := map[string]string{}
	for _, v := range s.ImageVulns {
		ids[v.CVE] = v.CVE
	}
	for _, r := range s.Relevant {
		ids[r.CVE] = r.CVE
	}
	for id, cve := range s.Aliases {
		if _, ok := ids[id]; ok {
			ids[id] = cve
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snap, c.ids, c.lastSuccess = s, ids, at
}

// SetEPSS replaces the EPSS scores; at is the time of the download.
func (c *Collector) SetEPSS(f EPSSFeed, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epss, c.feedAt["epss"], c.dataAt["epss"] = f.Scores, at, f.Date
}

// SetKEV replaces the KEV catalog; at is the time of the download.
func (c *Collector) SetKEV(f KEVFeed, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kev, c.feedAt["kev"], c.dataAt["kev"] = f.Entries, at, f.Released
}

// SetFrameworks replaces the control-to-framework mapping; at is the time of the download. The CSV has no
// publication date, so there is no data timestamp.
func (c *Collector) SetFrameworks(f FrameworksFeed, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frameworks, c.feedAt["frameworks"] = f, at
}

// SetSections replaces the CIS sections; at is the time of the download. The feed has no publication date either.
func (c *Collector) SetSections(f SectionsFeed, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sections, c.feedAt["sections"] = f, at
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{imageInfoDesc, imageVulnDesc, relevantDesc, exposureDesc, lastSuccessDesc,
		epssScoreDesc, epssPercentileDesc, kevDesc, feedSuccessDesc, feedDataDesc, postureResourcesDesc,
		postureFailedDesc, postureInfoDesc, postureFrameworkDesc, postureSectionDesc, postureLastScanDesc} {
		ch <- d
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	gauge := func(d *prometheus.Desc, v float64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
	}
	for feed, at := range c.feedAt {
		gauge(feedSuccessDesc, float64(at.Unix()), feed)
	}
	for feed, at := range c.dataAt {
		gauge(feedDataDesc, float64(at.Unix()), feed)
	}
	if c.lastSuccess.IsZero() {
		return
	}
	for _, i := range c.snap.Images {
		gauge(imageInfoDesc, 1, i.Image, i.Digest, i.Tag)
	}
	for _, v := range c.snap.ImageVulns {
		gauge(imageVulnDesc, 1, v.Image, v.Digest, v.Tag, v.CVE, v.Severity, v.Package, v.Version, v.FixedVersion,
			v.FixState)
	}
	for _, r := range c.snap.Relevant {
		gauge(relevantDesc, 1, r.Namespace, r.Workload, r.Kind, r.Container, r.Digest, r.CVE, r.Package, r.Version)
	}
	for _, e := range c.snap.Exposures {
		gauge(exposureDesc, 1, e.Namespace, e.Workload, e.Kind, e.Via, e.Gateway, e.Hostname, e.Access)
	}
	// Only for the vulnerabilities on this cluster: the feeds hold all known CVEs.
	for id, cve := range c.ids {
		if e, ok := c.epss[cve]; ok {
			gauge(epssScoreDesc, e.Score, id)
			gauge(epssPercentileDesc, e.Percentile, id)
		}
		if ransomware, ok := c.kev[cve]; ok {
			gauge(kevDesc, 1, id, ransomware)
		}
	}
	p := c.snap.Posture
	for _, n := range p.Counts {
		gauge(postureResourcesDesc, float64(n.Resources), n.Namespace, n.Control, n.Status)
	}
	for _, f := range p.Failed {
		gauge(postureFailedDesc, 1, f.Namespace, f.Kind, f.Name, f.Binding, f.Control)
	}
	// Info only for the controls on this cluster; the dashboard needs every control of a framework to score it.
	for control, severity := range p.Severity {
		gauge(postureInfoDesc, 1, control, cmp.Or(c.frameworks.Names[control], control), severity)
		if len(c.frameworks.Frameworks[control]) == 0 {
			gauge(postureFrameworkDesc, 1, "unmapped", control)
		}
	}
	for control, fws := range c.frameworks.Frameworks {
		for _, fw := range fws {
			gauge(postureFrameworkDesc, 1, fw, control)
		}
	}
	for _, s := range c.sections.Sections {
		for _, control := range s.Controls {
			gauge(postureSectionDesc, 1, s.Framework, s.ID, s.Name, control)
		}
	}
	if !p.LastScan.IsZero() {
		gauge(postureLastScanDesc, float64(p.LastScan.Unix()))
	}
	gauge(lastSuccessDesc, float64(c.lastSuccess.Unix()))
}

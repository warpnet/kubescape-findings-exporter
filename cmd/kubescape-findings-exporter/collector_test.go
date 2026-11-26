package main

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCollectorExposition(t *testing.T) {
	c := NewCollector()
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Fatalf("a collector without a snapshot exposes %d series, want 0", n)
	}

	c.Set(Snapshot{
		Images: []ImageInfo{{"docker.io/library/nginx", digestA, "1.27"}},
		ImageVulns: []ImageVuln{{"docker.io/library/nginx", digestA, "1.27", "CVE-2024-1", "critical", "openssl",
			"3.0.1", "3.0.2", "fixed"}},
		Relevant:  []RelevantVuln{{"app", "web", "Deployment", "nginx", digestA, "CVE-2024-1", "openssl", "3.0.1"}},
		Exposures: []Exposure{{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", "public"}},
	}, time.Unix(1700000000, 0))

	want := `
# HELP kubescape_image_info Image (digest) with a Kubescape scan result.
# TYPE kubescape_image_info gauge
kubescape_image_info{digest="` + digestA + `",image="docker.io/library/nginx",tag="1.27"} 1
# HELP kubescape_image_vulnerability CVE in one package version of an image, from the Kubescape scan.
# TYPE kubescape_image_vulnerability gauge
kubescape_image_vulnerability{cve="CVE-2024-1",digest="` + digestA + `",fix_state="fixed",fixed_version="3.0.2",image="docker.io/library/nginx",package="openssl",severity="critical",tag="1.27",version="3.0.1"} 1
# HELP kubescape_workload_vulnerability_relevant CVE whose package a workload container loads at runtime.
# TYPE kubescape_workload_vulnerability_relevant gauge
kubescape_workload_vulnerability_relevant{container="nginx",cve="CVE-2024-1",digest="` + digestA + `",kind="Deployment",namespace="app",package="openssl",version="3.0.1",workload="web"} 1
# HELP kubescape_workload_exposure_info Workload reachable from outside the cluster, with its entry point.
# TYPE kubescape_workload_exposure_info gauge
kubescape_workload_exposure_info{access="public",gateway="cilium/ext",hostname="a.example",kind="Deployment",namespace="app",via="HTTPRoute",workload="web"} 1
# HELP kubescape_cve_exporter_last_success_timestamp_seconds Unix time of the last complete list of Kubescape vulnerability manifests.
# TYPE kubescape_cve_exporter_last_success_timestamp_seconds gauge
kubescape_cve_exporter_last_success_timestamp_seconds 1.7e+09
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorFeeds(t *testing.T) {
	c := NewCollector()
	c.Set(Snapshot{
		ImageVulns: []ImageVuln{
			{"app", digestA, "1", "CVE-2026-1", "critical", "openssl", "3.0.1", "3.0.2", "fixed"},
			{"app", digestA, "1", "GHSA-aaaa-bbbb-cccc", "high", "golang.org/x/net", "v0.59.0", "0.60.0", "fixed"},
		},
		Aliases: map[string]string{"GHSA-aaaa-bbbb-cccc": "CVE-2026-9"},
	}, time.Unix(1700000000, 0))
	c.SetEPSS(EPSSFeed{Scores: map[string]EPSS{"CVE-2026-1": {0.5, 0.95}, "CVE-2026-9": {0.25, 0.9},
		"CVE-1999-1": {0.9, 0.99}}, Date: time.Unix(1699990000, 0)}, time.Unix(1700000100, 0))
	c.SetKEV(KEVFeed{Entries: map[string]string{"CVE-2026-9": "known", "CVE-1999-1": "unknown"},
		Released: time.Unix(1699900000, 0)}, time.Unix(1700000200, 0))

	want := `
# HELP kubescape_cve_epss_score EPSS: probability that the CVE is exploited in the next 30 days (FIRST).
# TYPE kubescape_cve_epss_score gauge
kubescape_cve_epss_score{cve="CVE-2026-1"} 0.5
kubescape_cve_epss_score{cve="GHSA-aaaa-bbbb-cccc"} 0.25
# HELP kubescape_cve_epss_percentile EPSS percentile: share of all CVEs with a lower or equal score.
# TYPE kubescape_cve_epss_percentile gauge
kubescape_cve_epss_percentile{cve="CVE-2026-1"} 0.95
kubescape_cve_epss_percentile{cve="GHSA-aaaa-bbbb-cccc"} 0.9
# HELP kubescape_cve_kev CVE on CISA's Known Exploited Vulnerabilities list.
# TYPE kubescape_cve_kev gauge
kubescape_cve_kev{cve="GHSA-aaaa-bbbb-cccc",ransomware="known"} 1
# HELP kubescape_cve_exporter_feed_last_success_timestamp_seconds Unix time of the last successful download of a feed.
# TYPE kubescape_cve_exporter_feed_last_success_timestamp_seconds gauge
kubescape_cve_exporter_feed_last_success_timestamp_seconds{feed="epss"} 1.7000001e+09
kubescape_cve_exporter_feed_last_success_timestamp_seconds{feed="kev"} 1.7000002e+09
# HELP kubescape_cve_exporter_feed_data_timestamp_seconds Unix time the feed's data was published (EPSS score_date, KEV dateReleased).
# TYPE kubescape_cve_exporter_feed_data_timestamp_seconds gauge
kubescape_cve_exporter_feed_data_timestamp_seconds{feed="epss"} 1.69999e+09
kubescape_cve_exporter_feed_data_timestamp_seconds{feed="kev"} 1.6999e+09
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "kubescape_cve_epss_score",
		"kubescape_cve_epss_percentile", "kubescape_cve_kev",
		"kubescape_cve_exporter_feed_last_success_timestamp_seconds",
		"kubescape_cve_exporter_feed_data_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}
}

var testPosture = Posture{
	Counts: []ControlCount{{"", "C-0035", "failed", 1}, {"app", "C-0013", "failed", 1},
		{"app", "C-0013", "passed", 2}},
	Failed: []ResourceFailed{{"", "ServiceAccount", "deployer", "ClusterRoleBinding/deployer", "C-0035"},
		{"app", "Deployment", "web", "", "C-0013"}},
	Severity: map[string]string{"C-0013": "medium", "C-0035": "high"},
	LastScan: time.Unix(1699999000, 0),
}

func TestCollectPosture(t *testing.T) {
	c := NewCollector()
	c.Set(Snapshot{Posture: testPosture}, time.Unix(1700000000, 0))
	// C-0057 is not on the cluster but is in the feed: it still gets framework series; C-0035 is unknown to the feed.
	c.SetFrameworks(FrameworksFeed{
		Frameworks: map[string][]string{"C-0013": {"AllControls", "NSA"}, "C-0057": {"AllControls"}},
		Names:      map[string]string{"C-0013": "Non-root containers", "C-0057": "Privileged container"},
	}, time.Unix(1700000300, 0))
	c.SetSections(SectionsFeed{Sections: []Section{{"cis-v1.12.0", "5", "Policies", []string{"C-0013", "C-0057"}}}},
		time.Unix(1700000400, 0))

	want := `
# HELP kubescape_posture_control_resources Resources with one status for one Kubescape control, per namespace.
# TYPE kubescape_posture_control_resources gauge
kubescape_posture_control_resources{control="C-0035",namespace="",status="failed"} 1
kubescape_posture_control_resources{control="C-0013",namespace="app",status="failed"} 1
kubescape_posture_control_resources{control="C-0013",namespace="app",status="passed"} 2
# HELP kubescape_posture_resource_failed Resource failing a Kubescape control; binding is set for RBAC subjects.
# TYPE kubescape_posture_resource_failed gauge
kubescape_posture_resource_failed{binding="ClusterRoleBinding/deployer",control="C-0035",kind="ServiceAccount",name="deployer",namespace=""} 1
kubescape_posture_resource_failed{binding="",control="C-0013",kind="Deployment",name="web",namespace="app"} 1
# HELP kubescape_posture_control_info Kubescape control on the cluster, with its name and severity.
# TYPE kubescape_posture_control_info gauge
kubescape_posture_control_info{control="C-0013",name="Non-root containers",severity="medium"} 1
kubescape_posture_control_info{control="C-0035",name="C-0035",severity="high"} 1
# HELP kubescape_posture_framework_control Framework a Kubescape control belongs to: every control of regolibrary's frameworks; unmapped for a control on the cluster that the feed does not know.
# TYPE kubescape_posture_framework_control gauge
kubescape_posture_framework_control{control="C-0013",framework="AllControls"} 1
kubescape_posture_framework_control{control="C-0013",framework="NSA"} 1
kubescape_posture_framework_control{control="C-0035",framework="unmapped"} 1
kubescape_posture_framework_control{control="C-0057",framework="AllControls"} 1
# HELP kubescape_posture_framework_section CIS section a Kubescape control belongs to, from regolibrary's frameworks.
# TYPE kubescape_posture_framework_section gauge
kubescape_posture_framework_section{control="C-0013",framework="cis-v1.12.0",section="5",section_name="Policies"} 1
kubescape_posture_framework_section{control="C-0057",framework="cis-v1.12.0",section="5",section_name="Policies"} 1
# HELP kubescape_posture_last_scan_timestamp_seconds Unix time of the newest Kubescape configuration scan report.
# TYPE kubescape_posture_last_scan_timestamp_seconds gauge
kubescape_posture_last_scan_timestamp_seconds 1.699999e+09
# HELP kubescape_cve_exporter_feed_last_success_timestamp_seconds Unix time of the last successful download of a feed.
# TYPE kubescape_cve_exporter_feed_last_success_timestamp_seconds gauge
kubescape_cve_exporter_feed_last_success_timestamp_seconds{feed="frameworks"} 1.7000003e+09
kubescape_cve_exporter_feed_last_success_timestamp_seconds{feed="sections"} 1.7000004e+09
`
	names := []string{"kubescape_posture_control_resources", "kubescape_posture_resource_failed",
		"kubescape_posture_control_info", "kubescape_posture_framework_control",
		"kubescape_posture_framework_section", "kubescape_posture_last_scan_timestamp_seconds", "kubescape_cve_exporter_feed_last_success_timestamp_seconds",
		"kubescape_cve_exporter_feed_data_timestamp_seconds"}
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), names...); err != nil {
		t.Fatal(err)
	}
}

func TestCollectPostureWithoutFrameworks(t *testing.T) {
	c := NewCollector()
	p := testPosture
	p.LastScan = time.Time{}
	c.Set(Snapshot{Posture: p}, time.Unix(1700000000, 0))

	want := `
# HELP kubescape_posture_control_info Kubescape control on the cluster, with its name and severity.
# TYPE kubescape_posture_control_info gauge
kubescape_posture_control_info{control="C-0013",name="C-0013",severity="medium"} 1
kubescape_posture_control_info{control="C-0035",name="C-0035",severity="high"} 1
# HELP kubescape_posture_framework_control Framework a Kubescape control belongs to: every control of regolibrary's frameworks; unmapped for a control on the cluster that the feed does not know.
# TYPE kubescape_posture_framework_control gauge
kubescape_posture_framework_control{control="C-0013",framework="unmapped"} 1
kubescape_posture_framework_control{control="C-0035",framework="unmapped"} 1
`
	// No report time: no last_scan series.
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "kubescape_posture_control_info",
		"kubescape_posture_framework_control", "kubescape_posture_last_scan_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}
}

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

// mf builds a manifest the way Kubescape storage returns it, with only the fields the exporter reads.
func mf(withRelevancy bool, imageID, imageTag string, labels map[string]string, matches ...Match) Manifest {
	var m Manifest
	m.Metadata.Labels = labels
	m.Metadata.Annotations = map[string]string{}
	if imageID != "" {
		m.Metadata.Annotations["kubescape.io/image-id"] = imageID
	}
	if imageTag != "" {
		m.Metadata.Annotations["kubescape.io/image-tag"] = imageTag
	}
	m.Spec.Metadata.WithRelevancy = withRelevancy
	m.Spec.Payload.Matches = matches
	return m
}

func match(cve, severity, pkg, version, fixState string, fixVersions ...string) Match {
	var m Match
	m.Vulnerability.ID = cve
	m.Vulnerability.Severity = severity
	m.Vulnerability.Fix.State = fixState
	m.Vulnerability.Fix.Versions = fixVersions
	m.Artifact.Name = pkg
	m.Artifact.Version = version
	return m
}

func workloadLabels(ns, name, kind, container string) map[string]string {
	return map[string]string{
		"kubescape.io/workload-namespace":      ns,
		"kubescape.io/workload-name":           name,
		"kubescape.io/workload-kind":           kind,
		"kubescape.io/workload-container-name": container,
	}
}

func TestSplitRef(t *testing.T) {
	cases := []struct{ ref, image, tag string }{
		{"quay.io/cilium/cilium:v1.20.4@" + digestA, "quay.io/cilium/cilium", "v1.20.4"},
		{"docker.io/library/wordpress@" + digestA, "docker.io/library/wordpress", ""},
		{"localhost:5000/app", "localhost:5000/app", ""},
		{digestA, "", ""},
		{"registry.example.com/team/app:3.4.0",
			"registry.example.com/team/app", "3.4.0"},
	}
	for _, c := range cases {
		image, tag := splitRef(c.ref)
		if image != c.image || tag != c.tag {
			t.Errorf("splitRef(%q) = (%q, %q), want (%q, %q)", c.ref, image, tag, c.image, c.tag)
		}
	}
}

func TestDigestOf(t *testing.T) {
	cases := map[string]string{
		"docker.io/library/wordpress@" + digestA: digestA,
		digestA:                                  digestA,
		"wordpress:6.5":                          "",
	}
	for in, want := range cases {
		if got := digestOf(in); got != want {
			t.Errorf("digestOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildDedupesByDigest(t *testing.T) {
	m := match("CVE-2024-1", "High", "openssl", "3.0.1", "fixed", "3.0.2")
	s := Build([]Manifest{
		mf(false, "docker.io/library/wordpress@"+digestA, "docker.io/library/wordpress:latest", nil, m),
		mf(false, "docker.io/library/wordpress@"+digestA, "docker.io/library/wordpress:6.5", nil, m),
	}, "medium")
	if len(s.Images) != 1 || s.Images[0].Tag != "6.5" || s.Images[0].Image != "docker.io/library/wordpress" {
		t.Fatalf("Images = %+v, want one docker.io/library/wordpress with tag 6.5", s.Images)
	}
	if len(s.ImageVulns) != 1 || s.ImageVulns[0].Tag != "6.5" {
		t.Fatalf("ImageVulns = %+v, want one with tag 6.5", s.ImageVulns)
	}
}

func TestBuildVersionInIdentity(t *testing.T) {
	s := Build([]Manifest{mf(false, digestA, "app:1", nil,
		match("CVE-2024-1", "High", "openssl", "3.0.1", "fixed", "3.0.3"),
		match("CVE-2024-1", "High", "openssl", "3.0.2", "fixed", "3.0.3"),
	)}, "medium")
	if len(s.ImageVulns) != 2 {
		t.Fatalf("got %d image vulns, want 2: %+v", len(s.ImageVulns), s.ImageVulns)
	}
}

func TestBuildHighestSeverityWins(t *testing.T) {
	s := Build([]Manifest{mf(false, digestA, "app:1", nil,
		match("CVE-2024-1", "Medium", "openssl", "3.0.1", "fixed", "1.1"),
		match("CVE-2024-1", "High", "openssl", "3.0.1", "not-fixed"),
	)}, "medium")
	if len(s.ImageVulns) != 1 {
		t.Fatalf("got %d image vulns, want 1", len(s.ImageVulns))
	}
	v := s.ImageVulns[0]
	if v.Severity != "high" || v.FixedVersion != "" || v.FixState != "not-fixed" {
		t.Fatalf("got %+v, want severity high, no fixed version, fix state not-fixed", v)
	}
}

func TestBuildFixedVersionJoined(t *testing.T) {
	s := Build([]Manifest{mf(false, digestA, "app:1", nil,
		match("CVE-2024-1", "High", "openssl", "3.0.1", "fixed", "1.2.4", "1.2.3", "1.2.4"),
	)}, "medium")
	if len(s.ImageVulns) != 1 || s.ImageVulns[0].FixedVersion != "1.2.3,1.2.4" {
		t.Fatalf("got %+v, want fixed version 1.2.3,1.2.4", s.ImageVulns)
	}
}

func TestBuildSeverityFloor(t *testing.T) {
	var matches []Match
	for i, sev := range []string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown", ""} {
		matches = append(matches, match("CVE-2024-"+string(rune('0'+i)), sev, "pkg", "1", "not-fixed"))
	}
	ms := []Manifest{mf(false, digestA, "app:1", nil, matches...)}
	severities := func(floor string) string {
		var out []string
		for _, v := range Build(ms, floor).ImageVulns {
			out = append(out, v.Severity)
		}
		return strings.Join(out, ",")
	}
	for floor, want := range map[string]string{
		"medium":   "critical,high,medium",
		"low":      "critical,high,medium,low",
		"critical": "critical",
	} {
		if got := severities(floor); got != want {
			t.Errorf("floor %s: severities %q, want %q", floor, got, want)
		}
	}
}

func TestBuildRelevant(t *testing.T) {
	s := Build([]Manifest{mf(true, "docker.io/library/nginx@"+digestA, "docker.io/library/nginx:1.27",
		workloadLabels("app", "web", "Deployment", "nginx"),
		match("CVE-2024-1", "Critical", "openssl", "3.0.1", "fixed", "3.0.2"),
		match("CVE-2024-2", "Low", "zlib", "1.3", "not-fixed"),
	)}, "medium")
	if len(s.Images) != 0 || len(s.ImageVulns) != 0 {
		t.Fatalf("a relevancy manifest must not produce image series: %+v", s)
	}
	want := RelevantVuln{Namespace: "app", Workload: "web", Kind: "Deployment", Container: "nginx",
		Digest: digestA, CVE: "CVE-2024-1", Package: "openssl", Version: "3.0.1"}
	if len(s.Relevant) != 1 || s.Relevant[0] != want {
		t.Fatalf("Relevant = %+v, want [%+v]", s.Relevant, want)
	}
}

func TestBuildTwoInstancesOneWorkload(t *testing.T) {
	labels := workloadLabels("app", "web", "Deployment", "nginx")
	m := match("CVE-2024-1", "Critical", "openssl", "3.0.1", "fixed", "3.0.2")
	s := Build([]Manifest{
		mf(true, digestA, "nginx:1.26", labels, m),
		mf(true, digestB, "nginx:1.27", labels, m),
	}, "medium")
	if len(s.Relevant) != 2 || s.Relevant[0].Digest == s.Relevant[1].Digest {
		t.Fatalf("Relevant = %+v, want two entries with different digests", s.Relevant)
	}
}

func TestBuildSkipsManifestWithoutDigest(t *testing.T) {
	s := Build([]Manifest{
		mf(false, "", "", workloadLabels("host", "node-1", "Node", "host"),
			match("CVE-2024-1", "Critical", "linux", "6.8", "fixed", "6.9")),
		mf(true, "", "", workloadLabels("host", "node-1", "Node", "host"),
			match("CVE-2024-1", "Critical", "linux", "6.8", "fixed", "6.9")),
	}, "medium")
	if len(s.Images)+len(s.ImageVulns)+len(s.Relevant) != 0 {
		t.Fatalf("manifests without a digest must be skipped, got %+v", s)
	}
}

func TestBuildLabFixtures(t *testing.T) {
	var ms []Manifest
	for _, f := range []string{"testdata/lab-image.json", "testdata/lab-filtered.json"} {
		b, err := os.ReadFile(f)
		if os.IsNotExist(err) {
			t.Skipf("%s missing: export it from lab (see the plan, Task 1 Step 1)", f)
		}
		if err != nil {
			t.Fatal(err)
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ms = append(ms, m)
	}
	s := Build(ms, "low")
	if len(s.ImageVulns) == 0 || len(s.Relevant) == 0 {
		t.Fatalf("want image and relevant series from the lab fixtures, got %d and %d",
			len(s.ImageVulns), len(s.Relevant))
	}
	for _, v := range s.ImageVulns {
		if v.Digest == "" || v.CVE == "" || v.Package == "" || v.Version == "" || v.Severity != strings.ToLower(v.Severity) {
			t.Errorf("incomplete image vuln: %+v", v)
		}
	}
	for _, v := range s.Relevant {
		if v.Digest == "" || v.CVE == "" || v.Package == "" || v.Version == "" {
			t.Errorf("incomplete relevant vuln: %+v", v)
		}
	}
}

// Prometheus drops a label with an empty value, so an empty Grype fix state would leave the series without
// fix_state. Report it as unknown instead.
func TestBuildEmptyFixStateIsUnknown(t *testing.T) {
	s := Build([]Manifest{mf(false, digestA, "app:1", nil, match("CVE-2018-9057", "Critical", "terraform", "v1.5.7", ""))}, "medium")
	if len(s.ImageVulns) != 1 || s.ImageVulns[0].FixState != "unknown" {
		t.Fatalf("got %+v, want fix state unknown", s.ImageVulns)
	}
}

// EPSS and KEV only know CVE IDs; Grype sometimes reports a GHSA or GO ID with the CVE as related vulnerability.
func TestBuildAliases(t *testing.T) {
	ghsa := match("GHSA-aaaa-bbbb-cccc", "High", "golang.org/x/net", "v0.59.0", "fixed", "0.60.0")
	ghsa.RelatedVulnerabilities = append(ghsa.RelatedVulnerabilities, relatedID("GO-2026-1"), relatedID("CVE-2026-9"))
	noCVE := match("GO-2026-2", "High", "stdlib", "go1.25.4", "fixed", "1.25.6")
	plain := match("CVE-2026-1", "High", "openssl", "3.0.1", "fixed", "3.0.2")
	plain.RelatedVulnerabilities = append(plain.RelatedVulnerabilities, relatedID("CVE-2026-7"))
	s := Build([]Manifest{
		mf(false, digestA, "app:1", nil, ghsa, noCVE, plain),
		mf(true, digestA, "app:1", workloadLabels("app", "web", "Deployment", "app"), ghsa),
	}, "medium")
	want := map[string]string{"GHSA-aaaa-bbbb-cccc": "CVE-2026-9"}
	if len(s.Aliases) != len(want) || s.Aliases["GHSA-aaaa-bbbb-cccc"] != "CVE-2026-9" {
		t.Fatalf("Aliases = %v, want %v", s.Aliases, want)
	}
}

func relatedID(id string) (r struct {
	ID string `json:"id"`
}) {
	r.ID = id
	return r
}

package main

import (
	"cmp"
	"strings"
	"time"
)

// Label and annotation keys Kubescape sets on its WorkloadConfigurationScanSummaries.
// lblNamespace, lblWorkload and lblKind are shared with the vulnerability manifests (series.go).
const (
	lblRBAC               = "kubescape.io/rbac-resource"
	lblRoleBinding        = "kubescape.io/rolebinding-name"
	lblClusterRoleBinding = "kubescape.io/clusterrolebinding-name"
	annReportCreatedAt    = "kubescape.io/report-created-at"
)

// Summary is the part of a WorkloadConfigurationScanSummary (spdx.softwarecomposition.kubescape.io/v1beta1) the
// exporter reads.
type Summary struct {
	Metadata struct {
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Controls map[string]Control `json:"controls"`
	} `json:"spec"`
}

// Control is the result of one control on one resource.
type Control struct {
	ControlID string `json:"controlID"`
	Severity  struct {
		Severity string `json:"severity"`
	} `json:"severity"`
	Status struct {
		Status string `json:"status"`
	} `json:"status"`
}

// ControlCount is the number of summaries (resources) with one status for one control in one namespace.
type ControlCount struct {
	Namespace, Control, Status string
	Resources                  int
}

// ResourceFailed is one resource failing one control. Binding is set for RBAC subjects only.
type ResourceFailed struct{ Namespace, Kind, Name, Binding, Control string }

// Posture is the complete posture series set built from one list of all summaries.
type Posture struct {
	Counts []ControlCount
	Failed []ResourceFailed
	// Severity maps every control seen to its lowercased severity ("unknown" when empty).
	Severity map[string]string
	// LastScan is the newest report-created-at; zero when no summary has a valid one.
	LastScan time.Time
}

// postureStatus maps a Kubescape status onto passed, failed or skipped.
func postureStatus(s string) string {
	switch s {
	case "passed", "excluded":
		return "passed"
	case "failed":
		return "failed"
	}
	return "skipped"
}

// BuildPosture turns summaries into series; every slice is sorted, so equal input gives equal output.
func BuildPosture(ss []Summary) Posture {
	p := Posture{Severity: map[string]string{}}
	counts := map[ControlCount]int{}
	failed := map[ResourceFailed]bool{}

	for _, s := range ss {
		l := s.Metadata.Labels
		if t, err := time.Parse(time.RFC3339Nano, s.Metadata.Annotations[annReportCreatedAt]); err == nil &&
			t.After(p.LastScan) {
			p.LastScan = t
		}
		// metadata.namespace is where Kubescape stores the record (kubescape for cluster-scoped ones), not the
		// resource's namespace.
		ns, binding := l[lblNamespace], ""
		if l[lblRBAC] == "true" {
			if n := l[lblClusterRoleBinding]; n != "" && l[lblRoleBinding] == "" {
				binding = "ClusterRoleBinding/" + n
			} else if n := l[lblRoleBinding]; n != "" {
				binding = "RoleBinding/" + n
			}
		}
		for key, c := range s.Spec.Controls {
			id := cmp.Or(c.ControlID, key)
			if _, ok := p.Severity[id]; !ok {
				// Prometheus drops labels with an empty value: an empty severity would leave the series without it.
				p.Severity[id] = cmp.Or(strings.ToLower(c.Severity.Severity), "unknown")
			}
			st := postureStatus(c.Status.Status)
			counts[ControlCount{Namespace: ns, Control: id, Status: st}]++
			if st == "failed" {
				failed[ResourceFailed{ns, l[lblKind], l[lblWorkload], binding, id}] = true
			}
		}
	}

	for k, n := range counts {
		k.Resources = n
		p.Counts = append(p.Counts, k)
	}
	for k := range failed {
		p.Failed = append(p.Failed, k)
	}
	sortBy(p.Counts, func(c ControlCount) []string { return []string{c.Namespace, c.Control, c.Status} })
	sortBy(p.Failed, func(f ResourceFailed) []string {
		return []string{f.Namespace, f.Kind, f.Name, f.Binding, f.Control}
	})
	return p
}

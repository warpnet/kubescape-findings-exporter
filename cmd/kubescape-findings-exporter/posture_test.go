package main

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"
)

func loadSummary(t *testing.T, file string) Summary {
	t.Helper()
	b, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var s Summary
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// inline decodes a summary from JSON, so tests can state labels, annotations and controls compactly.
func inline(t *testing.T, js string) Summary {
	t.Helper()
	var s Summary
	if err := json.Unmarshal([]byte(js), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func ctl(id, severity, status string) string {
	return `"` + id + `":{"controlID":"` + id + `","severity":{"severity":"` + severity + `"},"status":{"status":"` + status + `"}}`
}

func TestBuildPostureDeployment(t *testing.T) {
	p := BuildPosture([]Summary{loadSummary(t, "summary-deployment.json")})
	if len(p.Failed) != 17 {
		t.Fatalf("failed rows = %d, want 17", len(p.Failed))
	}
	for _, f := range p.Failed {
		if f.Namespace != "cert-manager" || f.Kind != "Deployment" || f.Name != "cert-manager" || f.Binding != "" {
			t.Fatalf("unexpected row %+v", f)
		}
	}
	total := 0
	for _, c := range p.Counts {
		total += c.Resources
	}
	if total != 64 {
		t.Errorf("counts sum = %d, want 64", total)
	}
}

func TestBuildPostureRBAC(t *testing.T) {
	p := BuildPosture([]Summary{loadSummary(t, "summary-rbac.json")})
	if len(p.Failed) == 0 {
		t.Fatal("fixture has no failed controls")
	}
	f := p.Failed[0]
	want := ResourceFailed{"cert-manager", "ServiceAccount", "cert-manager-cainjector",
		"ClusterRoleBinding/cert-manager-cainjector", f.Control}
	if f != want {
		t.Errorf("got %+v, want %+v", f, want)
	}

	s := inline(t, `{"metadata":{"labels":{"kubescape.io/rbac-resource":"true","kubescape.io/workload-kind":"User",
		"kubescape.io/workload-name":"u","kubescape.io/rolebinding-name":"x"}},"spec":{"controls":{`+
		ctl("C-1", "High", "failed")+`}}}`)
	if got := BuildPosture([]Summary{s}).Failed[0].Binding; got != "RoleBinding/x" {
		t.Errorf("binding = %q", got)
	}
}

func TestBuildPostureClusterScoped(t *testing.T) {
	s := loadSummary(t, "summary-node.json")
	s.Metadata.Labels = map[string]string{lblKind: "Node", lblWorkload: "n"}
	c := Control{ControlID: "C-9999"}
	c.Status.Status = "failed"
	s.Spec.Controls["C-9999"] = c
	p := BuildPosture([]Summary{s})
	if len(p.Failed) != 1 || p.Failed[0].Namespace != "" || p.Failed[0].Kind != "Node" {
		t.Errorf("failed = %+v", p.Failed)
	}
	for _, c := range p.Counts {
		if c.Namespace != "" {
			t.Errorf("count in namespace %q", c.Namespace)
		}
	}
	if got := loadSummary(t, "summary-node.json").Metadata.Namespace; got != "kubescape" {
		t.Fatalf("fixture namespace = %q", got)
	}
}

func TestBuildPostureNoControls(t *testing.T) {
	for _, js := range []string{`{"spec":{"controls":null}}`, `{"spec":{"controls":{}}}`} {
		p := BuildPosture([]Summary{inline(t, js)})
		if len(p.Counts) != 0 || len(p.Failed) != 0 {
			t.Errorf("%s: %+v", js, p)
		}
	}
}

func TestBuildPostureStatus(t *testing.T) {
	cases := map[string]string{"passed": "passed", "excluded": "passed", "failed": "failed", "skipped": "skipped",
		"irrelevant": "skipped", "": "skipped"}
	for in, want := range cases {
		p := BuildPosture([]Summary{inline(t, `{"spec":{"controls":{`+ctl("C-1", "High", in)+`}}}`)})
		if len(p.Counts) != 1 || p.Counts[0].Status != want {
			t.Errorf("%q: counts %+v, want %s", in, p.Counts, want)
		}
		if (len(p.Failed) == 1) != (want == "failed") {
			t.Errorf("%q: failed %+v", in, p.Failed)
		}
	}
}

func TestBuildPostureCounts(t *testing.T) {
	mk := func(ns, name string) Summary {
		return inline(t, `{"metadata":{"labels":{"kubescape.io/workload-namespace":"`+ns+`","kubescape.io/workload-name":"`+
			name+`","kubescape.io/workload-kind":"Deployment"}},"spec":{"controls":{`+ctl("C-0013", "High", "failed")+`}}}`)
	}
	p := BuildPosture([]Summary{mk("b", "z"), mk("a", "x"), mk("a", "y")})
	want := []ControlCount{{"a", "C-0013", "failed", 2}, {"b", "C-0013", "failed", 1}}
	if !slices.Equal(p.Counts, want) {
		t.Errorf("got %+v, want %+v", p.Counts, want)
	}
}

func TestBuildPostureSeverityAndLastScan(t *testing.T) {
	mk := func(ts string) Summary {
		ann := ""
		if ts != "" {
			ann = `"annotations":{"kubescape.io/report-created-at":"` + ts + `"},`
		}
		return inline(t, `{"metadata":{`+ann+`"labels":{}},"spec":{"controls":{`+ctl("C-1", "High", "failed")+","+
			ctl("C-2", "", "passed")+`}}}`)
	}
	p := BuildPosture([]Summary{mk("2026-11-09T03:58:02.955064615Z"), mk("2026-11-08T01:00:00Z"), mk("garbage"), mk("")})
	if p.Severity["C-1"] != "high" || p.Severity["C-2"] != "unknown" {
		t.Errorf("severity = %v", p.Severity)
	}
	want := time.Date(2026, 11, 9, 3, 58, 2, 955064615, time.UTC)
	if !p.LastScan.Equal(want) {
		t.Errorf("last scan = %v, want %v", p.LastScan, want)
	}
	if got := BuildPosture([]Summary{mk("")}).LastScan; !got.IsZero() {
		t.Errorf("last scan = %v, want zero", got)
	}
}

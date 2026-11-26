package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRefreshSetsSnapshot(t *testing.T) {
	c := NewCollector()
	list := func(context.Context) ([]Manifest, error) {
		return []Manifest{mf(false, digestA, "app:1", nil, match("CVE-2024-1", "High", "openssl", "3.0.1", "fixed", "3.0.2"))}, nil
	}
	cl := cluster(t, `, "services": [{"metadata": {"namespace": "app", "name": "np"}, "spec": {"type": "NodePort"}}],
	 "slices": [{"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "np"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x1"}}]}]`)
	exposed := func(context.Context) (Cluster, error) { return cl, nil }
	if _, err := refresh(context.Background(), c, list, exposed, noSummaries, "medium", time.Second); err != nil {
		t.Fatal(err)
	}
	// image info, image vulnerability, exposure and the timestamp
	if n := testutil.CollectAndCount(c); n != 4 {
		t.Fatalf("got %d series, want 4", n)
	}
}

// A rollout that keeps the image leaves the old ReplicaSet's manifest until Kubescape collects it. Its packages must
// not count for the running container, which has the same workload, container and digest.
func TestRefreshSkipsReplicaSetsWithoutPods(t *testing.T) {
	instance := func(hash, cve string) Manifest {
		l := workloadLabels("app", "web", "Deployment", "web")
		l["kubescape.io/instance-template-hash"] = hash
		return mf(true, digestA, "", l, match(cve, "Critical", "node", "22.20.0", "fixed", "22.23.4"))
	}
	list := func(context.Context) ([]Manifest, error) {
		return []Manifest{instance("5d8", "CVE-2026-1"), instance("6f6", "CVE-2026-2")}, nil
	}
	cl := cluster(t, `,"x": []`)
	snap, err := refresh(context.Background(), NewCollector(), list,
		func(context.Context) (Cluster, error) { return cl, nil }, noSummaries, "medium", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []RelevantVuln{{"app", "web", "Deployment", "web", digestA, "CVE-2026-1", "node", "22.20.0"}}
	if !slices.Equal(snap.Relevant, want) {
		t.Fatalf("relevant = %v, want %v", snap.Relevant, want)
	}
}

// A storage request that never answers must not stop the exporter: the list gets the timeout, and the previous
// snapshot and its timestamp stay.
func TestRefreshTimesOutAndKeepsPreviousSnapshot(t *testing.T) {
	c := NewCollector()
	before := time.Unix(1700000000, 0)
	c.Set(Snapshot{Images: []ImageInfo{{"app", digestA, "1"}}}, before)

	hang := func(ctx context.Context) ([]Manifest, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	noCluster := func(context.Context) (Cluster, error) { return Cluster{}, nil }
	_, err := refresh(context.Background(), c, hang, noCluster, noSummaries, "medium", 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got err %v, want context.DeadlineExceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("refresh did not stop at the timeout")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.lastSuccess.Equal(before) || len(c.snap.Images) != 1 {
		t.Fatalf("previous snapshot or timestamp changed: %v, %+v", c.lastSuccess, c.snap)
	}
}

// The exposure list fails (missing RBAC, for example): the CVE series and the timestamp stay as they were, so the
// exporter-failing alert fires instead of the exposure alert silently going quiet.
func TestRefreshClusterListFailsKeepsPreviousSnapshot(t *testing.T) {
	c := NewCollector()
	before := time.Unix(1700000000, 0)
	c.Set(Snapshot{Images: []ImageInfo{{"app", digestA, "1"}}}, before)
	list := func(context.Context) ([]Manifest, error) { return nil, nil }
	forbidden := func(context.Context) (Cluster, error) { return Cluster{}, errors.New("services is forbidden") }
	if _, err := refresh(context.Background(), c, list, forbidden, noSummaries, "medium", time.Second); err == nil {
		t.Fatal("want the cluster list error")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.lastSuccess.Equal(before) || len(c.snap.Images) != 1 {
		t.Fatalf("previous snapshot or timestamp changed: %v, %+v", c.lastSuccess, c.snap)
	}
}

func noSummaries(context.Context) ([]Summary, error) { return nil, nil }

func TestRefreshSetsPosture(t *testing.T) {
	c := NewCollector()
	list := func(context.Context) ([]Manifest, error) { return nil, nil }
	noCluster := func(context.Context) (Cluster, error) { return Cluster{}, nil }
	summaries := func(context.Context) ([]Summary, error) {
		return []Summary{loadSummary(t, "summary-deployment.json")}, nil
	}
	s, err := refresh(context.Background(), c, list, noCluster, summaries, "medium", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Posture.Counts) == 0 {
		t.Fatal("snapshot has no posture counts")
	}
}

// The summary list fails (missing RBAC, for example): every series and the timestamp stay as they were.
func TestRefreshSummaryError(t *testing.T) {
	c := NewCollector()
	before := time.Unix(1700000000, 0)
	c.Set(Snapshot{Images: []ImageInfo{{"app", digestA, "1"}},
		Posture: Posture{Counts: []ControlCount{{"app", "C-0013", "failed", 1}}}}, before)
	list := func(context.Context) ([]Manifest, error) { return nil, nil }
	noCluster := func(context.Context) (Cluster, error) { return Cluster{}, nil }
	forbidden := func(context.Context) ([]Summary, error) {
		return nil, errors.New("workloadconfigurationscansummaries is forbidden")
	}
	if _, err := refresh(context.Background(), c, list, noCluster, forbidden, "medium", time.Second); err == nil {
		t.Fatal("want the summary list error")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.lastSuccess.Equal(before) || len(c.snap.Images) != 1 || len(c.snap.Posture.Counts) != 1 {
		t.Fatalf("previous snapshot or timestamp changed: %v, %+v", c.lastSuccess, c.snap)
	}
}

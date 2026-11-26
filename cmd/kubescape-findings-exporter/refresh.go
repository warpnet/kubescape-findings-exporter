package main

import (
	"context"
	"time"
)

// refresh lists all manifests, the cluster objects the exposure comes from and the configuration scan summaries and,
// only when all lists succeed, replaces the collector's snapshot and returns it. The list gets at most timeout: a storage request that never answers would otherwise stop the loop for good. On
// an error the previous snapshot stays and its timestamp shows how old it is.
func refresh(ctx context.Context, c *Collector, list func(context.Context) ([]Manifest, error),
	listCluster func(context.Context) (Cluster, error), listSummaries func(context.Context) ([]Summary, error),
	minSeverity string, timeout time.Duration) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ms, err := list(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	cl, err := listCluster(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	ss, err := listSummaries(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	snap := Build(withoutIdleReplicaSets(ms, cl.Pods), minSeverity)
	snap.Exposures = BuildExposure(cl)
	snap.Posture = BuildPosture(ss)
	c.Set(snap, time.Now())
	return snap, nil
}

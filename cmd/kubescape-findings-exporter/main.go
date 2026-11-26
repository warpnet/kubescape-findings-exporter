// kubescape-findings-exporter serves per-CVE and configuration posture Prometheus series from Kubescape results.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"
)

func main() {
	namespace := flag.String("namespace", "kubescape", "namespace of the Kubescape VulnerabilityManifests")
	interval := flag.Duration("interval", 5*time.Minute, "time between two lists of all manifests")
	minSeverity := flag.String("min-severity", "medium", "lowest severity exported: negligible, low, medium, high or critical")
	pageSize := flag.Int("page-size", 10, "manifests per list request; bounds memory, manifests are large")
	clusterPageSize := flag.Int("cluster-page-size", 500,
		"objects per list request for the exposure (routes, services, endpointslices, pods, replicasets) and the "+
			"configuration scan summaries")
	gatewayAccess := flag.String("gateway-access", "",
		"comma-separated gateway=public|restricted overriding the derived access, for a firewall or cloud rule "+
			"outside the cluster; gateway as in the gateway label (Gateway or Service namespace/name, ingress class)")
	listen := flag.String("listen", ":8080", "address for /metrics and /healthz")
	feedInterval := flag.Duration("feed-interval", 24*time.Hour,
		"time between two downloads of the EPSS, KEV, frameworks and sections feeds")
	epssURL := flag.String("epss-url", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		"daily EPSS scores (gzipped CSV); empty disables EPSS")
	kevURL := flag.String("kev-url", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		"CISA Known Exploited Vulnerabilities catalog (JSON); empty disables KEV")
	frameworksURL := flag.String("frameworks-url",
		"https://github.com/kubescape/regolibrary/releases/download/v2.0.39/FWName_CID_CName",
		"Kubescape regolibrary control-to-framework mapping (CSV); empty maps every control to unmapped")
	sectionsURL := flag.String("sections-url",
		"https://github.com/kubescape/regolibrary/releases/download/v2.0.39/frameworks",
		"Kubescape regolibrary frameworks (JSON) for the CIS sections; empty disables them")
	flag.Parse()

	if _, ok := severityRanks[*minSeverity]; !ok {
		slog.Error("invalid --min-severity", "value", *minSeverity)
		os.Exit(2)
	}

	access := map[string]string{}
	for _, v := range strings.Split(*gatewayAccess, ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		gw, acc, _ := strings.Cut(v, "=")
		if gw == "" || (acc != "public" && acc != "restricted") {
			slog.Error("invalid --gateway-access, want gateway=public or gateway=restricted", "value", v)
			os.Exit(2)
		}
		access[gw] = acc
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("in-cluster config", "err", err)
		os.Exit(1)
	}
	hc, err := rest.HTTPClientFor(cfg)
	if err != nil {
		slog.Error("http client", "err", err)
		os.Exit(1)
	}

	collector := NewCollector()
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	list := func(ctx context.Context) ([]Manifest, error) {
		return listManifests(ctx, hc, cfg.Host, *namespace, *pageSize)
	}
	cluster := func(ctx context.Context) (Cluster, error) {
		c, err := listCluster(ctx, hc, cfg.Host, *clusterPageSize)
		c.Access = access
		return c, err
	}
	summaries := func(ctx context.Context) ([]Summary, error) {
		return listSummaries(ctx, hc, cfg.Host, *clusterPageSize)
	}
	go func() {
		for {
			// A list may take at most one interval.
			if s, err := refresh(ctx, collector, list, cluster, summaries, *minSeverity, *interval); err != nil {
				slog.Error("list manifests, exposure or posture, keeping the previous snapshot", "err", err)
			} else {
				slog.Info("listed manifests", "images", len(s.Images), "image_vulnerabilities", len(s.ImageVulns),
					"relevant", len(s.Relevant), "exposures", len(s.Exposures),
					"posture_failed", len(s.Posture.Failed), "posture_controls", len(s.Posture.Severity))
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(*interval):
			}
		}
	}()

	// The feeds come from the internet, not from the API server: a plain client, not the in-cluster one.
	feedClient := &http.Client{Timeout: 5 * time.Minute}
	if *epssURL != "" {
		go feedLoop(ctx, "epss", *feedInterval, func(ctx context.Context) error {
			f, err := fetchFeed(ctx, feedClient, *epssURL, parseEPSS)
			if err == nil {
				collector.SetEPSS(f, time.Now())
				slog.Info("downloaded feed", "feed", "epss", "cves", len(f.Scores), "published", f.Date)
			}
			return err
		})
	}
	if *kevURL != "" {
		go feedLoop(ctx, "kev", *feedInterval, func(ctx context.Context) error {
			f, err := fetchFeed(ctx, feedClient, *kevURL, parseKEV)
			if err == nil {
				collector.SetKEV(f, time.Now())
				slog.Info("downloaded feed", "feed", "kev", "cves", len(f.Entries), "published", f.Released)
			}
			return err
		})
	}

	if *frameworksURL != "" {
		go feedLoop(ctx, "frameworks", *feedInterval, func(ctx context.Context) error {
			f, err := fetchFeed(ctx, feedClient, *frameworksURL, parseFrameworks)
			if err == nil {
				collector.SetFrameworks(f, time.Now())
				slog.Info("downloaded feed", "feed", "frameworks", "controls", len(f.Names))
			}
			return err
		})
	}

	if *sectionsURL != "" {
		go feedLoop(ctx, "sections", *feedInterval, func(ctx context.Context) error {
			f, err := fetchFeed(ctx, feedClient, *sectionsURL, parseSections)
			if err == nil {
				collector.SetSections(f, time.Now())
				slog.Info("downloaded feed", "feed", "sections", "sections", len(f.Sections))
			}
			return err
		})
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("http server", "err", err)
		os.Exit(1)
	}
}

// feedLoop downloads a feed right away and then every interval; after a failure it retries within the hour and the
// previous data stays.
func feedLoop(ctx context.Context, name string, interval time.Duration, refresh func(context.Context) error) {
	for {
		err := refresh(ctx)
		if err != nil {
			slog.Error("download feed, keeping the previous data", "feed", name, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextFeedDelay(err, interval)):
		}
	}
}

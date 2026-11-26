package main

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"testing"
)

const manifestsPath = "/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/vulnerabilitymanifests"

// pagedServer serves page 1 (two items, continue token t1) and then page 2 with the given status.
func pagedServer(t *testing.T, page2Status int, reqs *[]*url.URL) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reqs = append(*reqs, r.URL)
		if r.URL.Query().Get("continue") == "" {
			fmt.Fprint(w, `{"metadata":{"continue":"t1"},"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`)
			return
		}
		w.WriteHeader(page2Status)
		fmt.Fprint(w, `{"metadata":{},"items":[{"metadata":{"name":"c"}}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListManifestsPages(t *testing.T) {
	var reqs []*url.URL
	srv := pagedServer(t, http.StatusOK, &reqs)
	ms, err := listManifests(context.Background(), srv.Client(), srv.URL, "kubescape", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 || ms[0].Metadata.Name != "a" || ms[2].Metadata.Name != "c" {
		t.Fatalf("got %d manifests, want a, b, c", len(ms))
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	for _, u := range reqs {
		q := u.Query()
		if u.Path != manifestsPath || q.Get("resourceVersion") != "fullSpec" || q.Get("limit") != "10" {
			t.Errorf("request %s: want path %s with resourceVersion=fullSpec and limit=10", u, manifestsPath)
		}
	}
	if reqs[1].Query().Get("continue") != "t1" {
		t.Errorf("second request %s: want continue=t1", reqs[1])
	}
}

func TestListManifestsPageError(t *testing.T) {
	var reqs []*url.URL
	srv := pagedServer(t, http.StatusInternalServerError, &reqs)
	ms, err := listManifests(context.Background(), srv.Client(), srv.URL, "kubescape", 10)
	if err == nil || ms != nil {
		t.Fatalf("got %d manifests and err %v, want no manifests and an error", len(ms), err)
	}
}

const gatewayGroup = "/apis/gateway.networking.k8s.io"

// clusterServer serves the discovery documents and one item per list. Paths in missing answer 404, paths in fail 403.
func clusterServer(t *testing.T, discovery map[string]string, missing, fail []string, reqs *[]string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reqs = append(*reqs, r.URL.Path)
		switch {
		case slices.Contains(missing, r.URL.Path):
			w.WriteHeader(http.StatusNotFound)
		case slices.Contains(fail, r.URL.Path):
			w.WriteHeader(http.StatusForbidden)
		case discovery[r.URL.Path] != "":
			fmt.Fprint(w, discovery[r.URL.Path])
		default:
			fmt.Fprintf(w, `{"metadata":{},"items":[{"metadata":{"namespace":"ns","name":%q}}]}`, path.Base(r.URL.Path))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

var twoVersions = map[string]string{
	gatewayGroup: `{"kind":"APIGroup","versions":[{"version":"v1alpha2"},{"version":"v1"}],"preferredVersion":{"version":"v1"}}`,
	gatewayGroup + "/v1": `{"kind":"APIResourceList","resources":[{"name":"gateways"},{"name":"httproutes"},
		{"name":"httproutes/status"},{"name":"grpcroutes"},{"name":"tcproutes"}]}`,
	gatewayGroup + "/v1alpha2": `{"kind":"APIResourceList","resources":[{"name":"tcproutes"},{"name":"tlsroutes"},
		{"name":"udproutes"}]}`,
}

func TestGatewayVersionsPreferredFirst(t *testing.T) {
	var reqs []string
	srv := clusterServer(t, twoVersions, nil, nil, &reqs)
	got, err := gatewayVersions(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"gateways": "v1", "httproutes": "v1", "grpcroutes": "v1", "tcproutes": "v1",
		"tlsroutes": "v1alpha2", "udproutes": "v1alpha2"}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGatewayVersionsGroupMissing(t *testing.T) {
	var reqs []string
	srv := clusterServer(t, nil, []string{gatewayGroup}, nil, &reqs)
	got, err := gatewayVersions(context.Background(), srv.Client(), srv.URL)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v and err %v, want nothing and no error", got, err)
	}
}

func TestListClusterAllKinds(t *testing.T) {
	var reqs []string
	srv := clusterServer(t, twoVersions, nil, nil, &reqs)
	c, err := listCluster(context.Background(), srv.Client(), srv.URL, 500)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, r := range c.Routes {
		kinds = append(kinds, r.Kind+" "+r.Metadata.Name)
	}
	want := []string{"HTTPRoute httproutes", "GRPCRoute grpcroutes", "TLSRoute tlsroutes", "TCPRoute tcproutes",
		"UDPRoute udproutes"}
	if !slices.Equal(kinds, want) {
		t.Fatalf("routes %v, want %v", kinds, want)
	}
	if len(c.Gateways) != 1 || len(c.Ingresses) != 1 || len(c.Services) != 1 || len(c.Slices) != 1 ||
		len(c.Pods) != 1 || len(c.ReplicaSets) != 1 || c.Pods[0].Name != "pods" {
		t.Fatalf("want one of every object, got %+v", c)
	}
	for _, p := range []string{gatewayGroup + "/v1alpha2/tlsroutes", gatewayGroup + "/v1/tcproutes",
		"/apis/networking.k8s.io/v1/ingresses", "/api/v1/services", "/api/v1/pods",
		"/apis/discovery.k8s.io/v1/endpointslices", "/apis/apps/v1/replicasets"} {
		if !slices.Contains(reqs, p) {
			t.Errorf("no request for %s in %v", p, reqs)
		}
	}
}

func TestListClusterRouteAPIMissing(t *testing.T) {
	var reqs []string
	d := maps.Clone(twoVersions)
	d[gatewayGroup+"/v1alpha2"] = `{"kind":"APIResourceList","resources":[{"name":"tlsroutes"}]}`
	srv := clusterServer(t, d, nil, nil, &reqs)
	c, err := listCluster(context.Background(), srv.Client(), srv.URL, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Routes) != 4 || slices.ContainsFunc(reqs, func(p string) bool { return strings.HasSuffix(p, "udproutes") }) {
		t.Fatalf("got %d routes and requests %v, want 4 and no udproutes request", len(c.Routes), reqs)
	}
}

// A CRD removed between discovery and the list: empty, not an error.
func TestListClusterRouteGoneAfterDiscovery(t *testing.T) {
	var reqs []string
	srv := clusterServer(t, twoVersions, []string{gatewayGroup + "/v1alpha2/udproutes"}, nil, &reqs)
	c, err := listCluster(context.Background(), srv.Client(), srv.URL, 500)
	if err != nil || len(c.Routes) != 4 {
		t.Fatalf("got %d routes and err %v, want 4 and no error", len(c.Routes), err)
	}
}

func TestListClusterServicesFail(t *testing.T) {
	var reqs []string
	srv := clusterServer(t, twoVersions, nil, []string{"/api/v1/services"}, &reqs)
	if _, err := listCluster(context.Background(), srv.Client(), srv.URL, 500); err == nil {
		t.Fatal("want an error when services cannot be listed")
	}
}

// Services answering 404 is not a missing CRD: it fails the list.
func TestListClusterCore404Fails(t *testing.T) {
	var reqs []string
	srv := clusterServer(t, twoVersions, []string{"/api/v1/pods"}, nil, &reqs)
	if _, err := listCluster(context.Background(), srv.Client(), srv.URL, 500); err == nil {
		t.Fatal("want an error when pods answer 404")
	}
}

const summariesPath = "/apis/spdx.softwarecomposition.kubescape.io/v1beta1/workloadconfigurationscansummaries"

func TestListSummaries(t *testing.T) {
	var reqs []*url.URL
	srv := pagedServer(t, http.StatusOK, &reqs)
	ss, err := listSummaries(context.Background(), srv.Client(), srv.URL, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != 3 || len(reqs) != 2 {
		t.Fatalf("got %d summaries in %d requests, want 3 in 2", len(ss), len(reqs))
	}
	for _, u := range reqs {
		q := u.Query()
		if u.Path != summariesPath || q.Get("resourceVersion") != "fullSpec" || q.Get("limit") != "500" {
			t.Errorf("request %s: want path %s with resourceVersion=fullSpec and limit=500", u, summariesPath)
		}
	}
	if reqs[1].Query().Get("continue") != "t1" {
		t.Errorf("second request %s: want continue=t1", reqs[1])
	}
	reqs = nil
	failing := pagedServer(t, http.StatusInternalServerError, &reqs)
	if ss, err := listSummaries(context.Background(), failing.Client(), failing.URL, 500); err == nil || ss != nil {
		t.Fatalf("failing page: got %d summaries and err %v, want none and an error", len(ss), err)
	}
}

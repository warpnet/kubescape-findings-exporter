package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// listManifests lists all VulnerabilityManifests in namespace, pageSize at a time. Kubescape storage returns items
// without spec unless resourceVersion=fullSpec is set. Any failing page fails the whole list: a partial list would
// make CVEs disappear from the series.
func listManifests(ctx context.Context, hc *http.Client, host, namespace string, pageSize int) ([]Manifest, error) {
	return listAll[Manifest](ctx, hc, host+"/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/"+
		url.PathEscape(namespace)+"/vulnerabilitymanifests", url.Values{"resourceVersion": {"fullSpec"}}, pageSize, false)
}

// listSummaries lists all WorkloadConfigurationScanSummaries in all namespaces, pageSize at a time. Any failing page
// fails the whole list.
func listSummaries(ctx context.Context, hc *http.Client, host string, pageSize int) ([]Summary, error) {
	return listAll[Summary](ctx, hc, host+"/apis/spdx.softwarecomposition.kubescape.io/v1beta1/"+
		"workloadconfigurationscansummaries", url.Values{"resourceVersion": {"fullSpec"}}, pageSize, false)
}

// errNotFound marks a 404: the API is not served (any more).
var errNotFound = errors.New("not found")

// listAll lists every item of a list endpoint, pageSize at a time. With allow404 a 404 gives an empty list.
func listAll[T any](ctx context.Context, hc *http.Client, rawURL string, q url.Values, pageSize int,
	allow404 bool) ([]T, error) {
	var all []T
	cont := ""
	for {
		q := maps.Clone(q)
		if q == nil {
			q = url.Values{}
		}
		q.Set("limit", strconv.Itoa(pageSize))
		if cont != "" {
			q.Set("continue", cont)
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := getJSON(ctx, hc, rawURL+"?"+q.Encode(), &page); err != nil {
			if allow404 && errors.Is(err, errNotFound) {
				return nil, nil
			}
			return nil, err
		}
		all = append(all, page.Items...)
		if cont = page.Metadata.Continue; cont == "" {
			return all, nil
		}
	}
}

func getJSON(ctx context.Context, hc *http.Client, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("get %s: %w", req.URL.Path, errNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("get %s: %s: %s", req.URL.Path, resp.Status, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", req.URL.Path, err)
	}
	return nil
}

const gatewayAPI = "/apis/gateway.networking.k8s.io"

// routeKinds in list order: resource → kind.
var routeKinds = []struct{ resource, kind string }{
	{"httproutes", "HTTPRoute"}, {"grpcroutes", "GRPCRoute"}, {"tlsroutes", "TLSRoute"}, {"tcproutes", "TCPRoute"},
	{"udproutes", "UDPRoute"},
}

// gatewayVersions maps each Gateway API resource to the version to list it with: the preferred version when it
// serves the resource, else the first other version that does. Versions are discovered, never pinned, so a Gateway
// API upgrade that adds or drops a version keeps working. No Gateway API at all gives an empty map.
func gatewayVersions(ctx context.Context, hc *http.Client, host string) (map[string]string, error) {
	var group struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
		PreferredVersion struct {
			Version string `json:"version"`
		} `json:"preferredVersion"`
	}
	versions := map[string]string{}
	if err := getJSON(ctx, hc, host+gatewayAPI, &group); err != nil {
		if errors.Is(err, errNotFound) {
			return versions, nil
		}
		return nil, err
	}
	order := []string{group.PreferredVersion.Version}
	for _, v := range group.Versions {
		if v.Version != group.PreferredVersion.Version {
			order = append(order, v.Version)
		}
	}
	for _, v := range order {
		var list struct {
			Resources []struct {
				Name string `json:"name"`
			} `json:"resources"`
		}
		if err := getJSON(ctx, hc, host+gatewayAPI+"/"+v, &list); err != nil {
			if errors.Is(err, errNotFound) {
				continue
			}
			return nil, err
		}
		for _, r := range list.Resources {
			if _, seen := versions[r.Name]; !seen && !strings.Contains(r.Name, "/") {
				versions[r.Name] = v
			}
		}
	}
	return versions, nil
}

type metaOnly struct {
	Metadata ObjectMeta `json:"metadata"`
}

func metas(items []metaOnly) []ObjectMeta {
	out := make([]ObjectMeta, len(items))
	for i, m := range items {
		out[i] = m.Metadata
	}
	return out
}

// listCluster lists, in all namespaces, the objects the exposure is derived from. Gateway API resources that are not
// served count as empty; every other failure fails the whole list.
func listCluster(ctx context.Context, hc *http.Client, host string, pageSize int) (Cluster, error) {
	var c Cluster
	versions, err := gatewayVersions(ctx, hc, host)
	if err != nil {
		return c, err
	}
	gw := func(resource string) (string, bool) {
		v, ok := versions[resource]
		return host + gatewayAPI + "/" + v + "/" + resource, ok
	}
	if u, ok := gw("gateways"); ok {
		if c.Gateways, err = listAll[Gateway](ctx, hc, u, nil, pageSize, true); err != nil {
			return c, err
		}
	}
	for _, rk := range routeKinds {
		u, ok := gw(rk.resource)
		if !ok {
			continue
		}
		routes, err := listAll[Route](ctx, hc, u, nil, pageSize, true)
		if err != nil {
			return c, err
		}
		for i := range routes {
			routes[i].Kind = rk.kind
		}
		c.Routes = append(c.Routes, routes...)
	}
	if c.Ingresses, err = listAll[Ingress](ctx, hc, host+"/apis/networking.k8s.io/v1/ingresses", nil, pageSize,
		false); err != nil {
		return c, err
	}
	if c.Services, err = listAll[Service](ctx, hc, host+"/api/v1/services", nil, pageSize, false); err != nil {
		return c, err
	}
	if c.Slices, err = listAll[EndpointSlice](ctx, hc, host+"/apis/discovery.k8s.io/v1/endpointslices", nil,
		pageSize, false); err != nil {
		return c, err
	}
	pods, err := listAll[metaOnly](ctx, hc, host+"/api/v1/pods", nil, pageSize, false)
	if err != nil {
		return c, err
	}
	rs, err := listAll[metaOnly](ctx, hc, host+"/apis/apps/v1/replicasets", nil, pageSize, false)
	if err != nil {
		return c, err
	}
	c.Pods, c.ReplicaSets = metas(pods), metas(rs)
	return c, nil
}

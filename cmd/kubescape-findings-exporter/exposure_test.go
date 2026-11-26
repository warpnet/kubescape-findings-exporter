package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// The objects below use the API's own JSON, so the tests also cover the decoding of the fields the exporter reads.

// A Deployment web in app behind the Service web, a public Gateway cilium/ext and a restricted cilium/int.
const baseObjects = `
"gateways": [
  {"metadata": {"namespace": "cilium", "name": "ext"}, "status": {"addresses": [{"value": "1.2.3.4"}]}},
  {"metadata": {"namespace": "cilium", "name": "int"}, "status": {"addresses": [{"value": "5.6.7.8"}]}},
  {"metadata": {"namespace": "cilium", "name": "lost"}, "status": {"addresses": [{"value": "9.9.9.9"}]}}
],
"services": [
  {"metadata": {"namespace": "cilium", "name": "cilium-gateway-ext"},
   "spec": {"type": "LoadBalancer"}, "status": {"loadBalancer": {"ingress": [{"ip": "1.2.3.4"}]}}},
  {"metadata": {"namespace": "cilium", "name": "cilium-gateway-int"},
   "spec": {"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.1/32"]},
   "status": {"loadBalancer": {"ingress": [{"ip": "5.6.7.8"}]}}},
  {"metadata": {"namespace": "app", "name": "web"}, "spec": {"type": "ClusterIP"}},
  {"metadata": {"namespace": "data", "name": "db"}, "spec": {"type": "ClusterIP"}}
],
"slices": [
  {"metadata": {"namespace": "app", "name": "web-abc", "labels": {"kubernetes.io/service-name": "web"}},
   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x1"}}, {"targetRef": {"kind": "Pod", "name": "web-5d8-x2"}}, {}]},
  {"metadata": {"namespace": "data", "name": "db-abc", "labels": {"kubernetes.io/service-name": "db"}},
   "endpoints": [{"targetRef": {"kind": "Pod", "name": "db-0"}}]}
],
"pods": [
  {"namespace": "app", "name": "web-5d8-x1", "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d8", "controller": true}]},
  {"namespace": "app", "name": "web-5d8-x2", "ownerReferences": [{"kind": "ReplicaSet", "name": "web-5d8", "controller": true}]},
  {"namespace": "data", "name": "db-0", "ownerReferences": [{"kind": "StatefulSet", "name": "db", "controller": true}]}
],
"replicaSets": [
  {"namespace": "app", "name": "web-5d8", "ownerReferences": [{"kind": "Deployment", "name": "web", "controller": true}]}
]`

func cluster(t *testing.T, extra string) Cluster {
	t.Helper()
	// extra replaces whole lists: decoding a duplicate key into a struct would merge into the reused slice elements.
	objs := map[string]json.RawMessage{}
	for _, js := range []string{"{" + baseObjects + "}", "{" + extra[1:] + "}"} {
		if err := json.Unmarshal([]byte(js), &objs); err != nil {
			t.Fatal(err)
		}
	}
	merged, _ := json.Marshal(objs)
	var c Cluster
	if err := json.Unmarshal(merged, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func route(kind, js string) string {
	return `, "routes": [{"kind": "` + kind + `", ` + js + `}]`
}

// status is a route status with one entry per parent, "namespace/name" or "name", and the given conditions.
func status(conditions string, parents ...string) string {
	var ps []string
	for _, p := range parents {
		ref := `{"name": "` + p + `"}`
		if ns, name, ok := strings.Cut(p, "/"); ok {
			ref = `{"namespace": "` + ns + `", "name": "` + name + `"}`
		}
		ps = append(ps, `{"parentRef": `+ref+`, "conditions": [`+conditions+`]}`)
	}
	return `, "status": {"parents": [` + strings.Join(ps, ", ") + `]}`
}

const accepted = `{"type": "Accepted", "status": "True"}, {"type": "ResolvedRefs", "status": "True"}`

func checkExposure(t *testing.T, c Cluster, want ...Exposure) {
	t.Helper()
	got := BuildExposure(c)
	if !slices.Equal(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestExposureHTTPRoute(t *testing.T) {
	c := cluster(t, route("HTTPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["b.example", "a.example"],
	           "parentRefs": [{"name": "ext", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web", "port": 80}]}]}`+status(accepted, "cilium/ext")))
	checkExposure(t, c,
		Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", "public"},
		Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "b.example", "public"})
}

func TestExposureRestrictedGateway(t *testing.T) {
	c := cluster(t, route("GRPCRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["g.example"], "parentRefs": [{"name": "int", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}]}]}`+status(accepted, "cilium/int")))
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "GRPCRoute", "cilium/int", "g.example", "restricted"})
}

// A firewall outside the cluster blocks the public Gateway ext: the override wins, other gateways keep theirs.
func TestExposureAccessOverride(t *testing.T) {
	c := cluster(t, route("HTTPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["a.example"], "parentRefs": [{"name": "ext", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}]}]}`+status(accepted, "cilium/ext")))
	c.Access = map[string]string{"cilium/ext": "restricted"}
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", "restricted"})
	c.Access = map[string]string{"cilium/int": "restricted"}
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", "public"})
}

// The access annotation on the Gateway or on its LoadBalancer Service; an invalid value is ignored, the flag wins.
func TestExposureAccessAnnotation(t *testing.T) {
	c := cluster(t, route("HTTPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["a.example"], "parentRefs": [{"name": "ext", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}]}]}`+status(accepted, "cilium/ext")))
	want := func(acc string) Exposure {
		return Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", acc}
	}
	gw, svc := &c.Gateways[0].Metadata, &c.Services[0].Metadata
	if err := json.Unmarshal([]byte(`{"metadata": {"namespace": "cilium", "name": "ext",
	  "annotations": {"kubescape-findings-exporter.warpnet.nl/access": "restricted"}}}`), &c.Gateways[0]); err != nil {
		t.Fatal(err)
	}
	checkExposure(t, c, want("restricted"))
	gw.Annotations[annAccess] = "yes"
	checkExposure(t, c, want("public"))
	svc.Annotations = map[string]string{annAccess: "restricted"}
	checkExposure(t, c, want("restricted"))
	c.Access = map[string]string{"cilium/ext": "public"}
	checkExposure(t, c, want("public"))
}

func TestExposureGatewayWithoutService(t *testing.T) {
	c := cluster(t, route("TLSRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["t.example"], "parentRefs": [{"name": "lost", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}]}]}`+status(accepted, "cilium/lost")))
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "TLSRoute", "cilium/lost", "t.example", "unknown"})
}

// A parentRef without namespace is the route's namespace; a Gateway that does not exist gives unknown.
func TestExposureTCPRouteNoHostname(t *testing.T) {
	c := cluster(t, route("TCPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"parentRefs": [{"name": "gw"}], "rules": [{"backendRefs": [{"name": "web"}]}]}`+status(accepted, "gw")))
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "TCPRoute", "app/gw", "", "unknown"})
}

func TestExposureCrossNamespaceBackend(t *testing.T) {
	c := cluster(t, route("HTTPRoute", `"metadata": {"namespace": "app", "name": "db"},
	  "spec": {"hostnames": ["db.example"], "parentRefs": [{"name": "ext", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "db", "namespace": "data"}]}]}`+status(accepted, "cilium/ext")))
	checkExposure(t, c, Exposure{"data", "db", "StatefulSet", "HTTPRoute", "cilium/ext", "db.example", "public"})
}

func TestExposureSkipsNonServiceBackend(t *testing.T) {
	c := cluster(t, route("HTTPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"parentRefs": [{"name": "ext", "namespace": "cilium"},
	                          {"group": "gateway.networking.x-k8s.io", "kind": "XListenerSet", "name": "ls"}],
	           "rules": [{"backendRefs": [{"group": "gateway.envoyproxy.io", "kind": "Backend", "name": "web"}]},
	                     {"backendRefs": [{"name": "missing"}]}]}`+status(accepted, "cilium/ext")))
	checkExposure(t, c)
}

func TestExposureIngress(t *testing.T) {
	c := cluster(t, `, "ingresses": [{"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"ingressClassName": "nginx", "defaultBackend": {"service": {"name": "web"}},
	           "rules": [{"host": "x.example", "http": {"paths": [{"backend": {"service": {"name": "web"}}}]}}]},
	  "status": {"loadBalancer": {"ingress": [{"ip": "1.2.3.4"}]}}}]`)
	checkExposure(t, c,
		Exposure{"app", "web", "Deployment", "Ingress", "nginx", "", "public"},
		Exposure{"app", "web", "Deployment", "Ingress", "nginx", "x.example", "public"})
}

func TestExposureLoadBalancerAndNodePortServices(t *testing.T) {
	c := cluster(t, `, "services": [
	  {"metadata": {"namespace": "app", "name": "web-lb"},
	   "spec": {"type": "LoadBalancer", "loadBalancerSourceRanges": ["10.0.0.1/32"]}},
	  {"metadata": {"namespace": "app", "name": "web-np"}, "spec": {"type": "NodePort"}},
	  {"metadata": {"namespace": "app", "name": "web"}, "spec": {"type": "ClusterIP"}}],
	 "slices": [
	  {"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "web-lb"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x1"}}]},
	  {"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "web-np"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x1"}}]},
	  {"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "web"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x1"}}]}]`)
	checkExposure(t, c,
		Exposure{"app", "web", "Deployment", "Service", "app/web-lb", "", "restricted"},
		Exposure{"app", "web", "Deployment", "Service", "app/web-np", "", "unknown"})
}

// A ReplicaSet without a Deployment is the workload itself; a pod without a controller as well. Endpoints that are
// not pods are skipped.
func TestExposureOwners(t *testing.T) {
	c := cluster(t, `, "services": [{"metadata": {"namespace": "app", "name": "lb"}, "spec": {"type": "NodePort"}}],
	 "slices": [{"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "lb"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "solo"}}, {"targetRef": {"kind": "Pod", "name": "rs-1"}},
	                 {"targetRef": {"kind": "Node", "name": "n1"}}, {"targetRef": {"kind": "Pod", "name": "gone"}}]}],
	 "pods": [{"namespace": "app", "name": "solo"},
	          {"namespace": "app", "name": "rs-1", "ownerReferences": [{"kind": "ReplicaSet", "name": "rs", "controller": true}]}],
	 "replicaSets": [{"namespace": "app", "name": "rs"}]`)
	checkExposure(t, c,
		Exposure{"app", "rs", "ReplicaSet", "Service", "app/lb", "", "unknown"},
		Exposure{"app", "solo", "Pod", "Service", "app/lb", "", "unknown"})
}

// Two Services in front of the same pods behind one route: one series.
func TestExposureDedup(t *testing.T) {
	c := cluster(t, `, "services": [
	  {"metadata": {"namespace": "cilium", "name": "cilium-gateway-ext"},
	   "spec": {"type": "LoadBalancer"}, "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example"}]}}},
	  {"metadata": {"namespace": "app", "name": "web"}}, {"metadata": {"namespace": "app", "name": "web2"}}],
	 "gateways": [{"metadata": {"namespace": "cilium", "name": "ext"}, "status": {"addresses": [{"value": "lb.example"}]}}],
	 "slices": [
	  {"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "web"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x1"}}]},
	  {"metadata": {"namespace": "app", "labels": {"kubernetes.io/service-name": "web2"}},
	   "endpoints": [{"targetRef": {"kind": "Pod", "name": "web-5d8-x2"}}]}]`+
		route("HTTPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["a.example"], "parentRefs": [{"name": "ext", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}, {"name": "web2"}]}]}`+status(accepted, "cilium/ext")))
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", "public"})
}

// A route the Gateway has not accepted (listener allowedRoutes, no such Gateway) or not processed yet (no status)
// carries no traffic: no exposure. Only the parent that accepted it counts.
func TestExposureSkipsParentNotAccepted(t *testing.T) {
	spec := `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["a.example"],
	           "parentRefs": [{"name": "ext", "namespace": "cilium"}, {"name": "int", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}]}]}`
	checkExposure(t, cluster(t, route("HTTPRoute", spec)))
	checkExposure(t, cluster(t, route("HTTPRoute", spec+status(`{"type": "Accepted", "status": "False"}`,
		"cilium/ext", "cilium/int"))))
	checkExposure(t, cluster(t, route("HTTPRoute", spec+status(accepted, "cilium/int")+``)),
		Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/int", "a.example", "restricted"})
}

// A backend in another namespace without a ReferenceGrant: the route is accepted, but ResolvedRefs is False and the
// Gateway sends no traffic there. Backends in the route's own namespace still count.
func TestExposureSkipsCrossNamespaceBackendNotPermitted(t *testing.T) {
	c := cluster(t, route("HTTPRoute", `"metadata": {"namespace": "app", "name": "web"},
	  "spec": {"hostnames": ["a.example"], "parentRefs": [{"name": "ext", "namespace": "cilium"}],
	           "rules": [{"backendRefs": [{"name": "web"}, {"name": "db", "namespace": "data"}]}]}`+
		status(`{"type": "Accepted", "status": "True"}, {"type": "ResolvedRefs", "status": "False", "reason": "RefNotPermitted"}`,
			"cilium/ext")))
	checkExposure(t, c, Exposure{"app", "web", "Deployment", "HTTPRoute", "cilium/ext", "a.example", "public"})
}

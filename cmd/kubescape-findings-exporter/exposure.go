package main

import "cmp"

// Exposure: which workloads can be reached from outside the cluster, and through what. Derived as route or Ingress →
// backend Services → EndpointSlices → pods → owner, plus Services of type LoadBalancer or NodePort themselves.

// Exposure is one exposed workload and one entry point. Access is public (LoadBalancer without source ranges),
// restricted (with source ranges) or unknown (NodePort, or no LoadBalancer Service found for the address).
type Exposure struct{ Namespace, Workload, Kind, Via, Gateway, Hostname, Access string }

type ObjectMeta struct {
	Namespace       string            `json:"namespace"`
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []struct {
		Kind       string `json:"kind"`
		Name       string `json:"name"`
		Controller bool   `json:"controller"`
	} `json:"ownerReferences"`
}

// Ref is a Gateway API parentRef or backendRef. Group and Kind default to the core Service (backends) or the Gateway
// (parents); Namespace defaults to the route's.
type Ref struct {
	Group     string `json:"group"`
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// Route is any Gateway API route (HTTP, GRPC, TLS, TCP, UDP): the fields read are the same in all of them and in all
// their API versions. Kind is set by the lister: list items carry no kind.
type Route struct {
	Kind     string     `json:"kind"`
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Hostnames  []string `json:"hostnames"`
		ParentRefs []Ref    `json:"parentRefs"`
		Rules      []struct {
			BackendRefs []Ref `json:"backendRefs"`
		} `json:"rules"`
	} `json:"spec"`
	// Per parent: whether it accepted the route (Accepted) and whether every backend could be used (ResolvedRefs).
	Status struct {
		Parents []struct {
			ParentRef  Ref `json:"parentRef"`
			Conditions []struct {
				Type   string `json:"type"`
				Status string `json:"status"`
			} `json:"conditions"`
		} `json:"parents"`
	} `json:"status"`
}

// parentStatus reports whether the parent accepted the route, and whether all its backend references resolved.
// A parent without status (not processed yet) has not accepted it.
func (r Route) parentStatus(p Ref) (accepted, resolved bool) {
	ns := r.Metadata.Namespace
	for _, s := range r.Status.Parents {
		q := s.ParentRef
		if q.Name != p.Name || cmp.Or(q.Namespace, ns) != cmp.Or(p.Namespace, ns) ||
			cmp.Or(q.Kind, "Gateway") != cmp.Or(p.Kind, "Gateway") {
			continue
		}
		resolved = true
		for _, c := range s.Conditions {
			switch c.Type {
			case "Accepted":
				accepted = c.Status == "True"
			case "ResolvedRefs":
				resolved = c.Status != "False"
			}
		}
		return accepted, resolved
	}
	return false, false
}

type Gateway struct {
	Metadata ObjectMeta `json:"metadata"`
	Status   struct {
		Addresses []struct {
			Value string `json:"value"`
		} `json:"addresses"`
	} `json:"status"`
}

type LBStatus struct {
	LoadBalancer struct {
		Ingress []struct {
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		} `json:"ingress"`
	} `json:"loadBalancer"`
}

type IngressBackend struct {
	Service *struct {
		Name string `json:"name"`
	} `json:"service"`
}

type Ingress struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		IngressClassName string          `json:"ingressClassName"`
		DefaultBackend   *IngressBackend `json:"defaultBackend"`
		Rules            []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Backend IngressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
	Status LBStatus `json:"status"`
}

type Service struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     struct {
		Type                     string   `json:"type"`
		LoadBalancerSourceRanges []string `json:"loadBalancerSourceRanges"`
	} `json:"spec"`
	Status LBStatus `json:"status"`
}

type EndpointSlice struct {
	Metadata  ObjectMeta `json:"metadata"`
	Endpoints []struct {
		TargetRef *struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"targetRef"`
	} `json:"endpoints"`
}

// Cluster holds the objects the exposure is derived from. Pods and ReplicaSets: metadata only.
type Cluster struct {
	Gateways    []Gateway       `json:"gateways"`
	Routes      []Route         `json:"routes"`
	Ingresses   []Ingress       `json:"ingresses"`
	Services    []Service       `json:"services"`
	Slices      []EndpointSlice `json:"slices"`
	Pods        []ObjectMeta    `json:"pods"`
	ReplicaSets []ObjectMeta    `json:"replicaSets"`
}

const lblServiceName = "kubernetes.io/service-name"

func key(ns, name string) string { return ns + "/" + name }

// controller returns the kind and name of the object's controlling owner, or false when it has none.
func controller(m ObjectMeta) (kind, name string, ok bool) {
	for _, o := range m.OwnerReferences {
		if o.Controller {
			return o.Kind, o.Name, true
		}
	}
	return "", "", false
}

// BuildExposure derives one Exposure per workload and entry point, deduplicated and sorted.
func BuildExposure(c Cluster) []Exposure {
	services := map[string]Service{}
	byAddress := map[string]Service{}
	for _, s := range c.Services {
		services[key(s.Metadata.Namespace, s.Metadata.Name)] = s
		if s.Spec.Type == "LoadBalancer" {
			for _, i := range s.Status.LoadBalancer.Ingress {
				for _, a := range []string{i.IP, i.Hostname} {
					if a != "" {
						byAddress[a] = s
					}
				}
			}
		}
	}
	podsOf := map[string][]string{} // namespace/service → pod names
	for _, sl := range c.Slices {
		k := key(sl.Metadata.Namespace, sl.Metadata.Labels[lblServiceName])
		for _, e := range sl.Endpoints {
			if e.TargetRef != nil && e.TargetRef.Kind == "Pod" {
				podsOf[k] = append(podsOf[k], e.TargetRef.Name)
			}
		}
	}
	pods := map[string]ObjectMeta{}
	for _, p := range c.Pods {
		pods[key(p.Namespace, p.Name)] = p
	}
	replicaSets := map[string]ObjectMeta{}
	for _, r := range c.ReplicaSets {
		replicaSets[key(r.Namespace, r.Name)] = r
	}
	// workload follows pod → controller, and a ReplicaSet on to its Deployment.
	workload := func(ns, pod string) (kind, name string, ok bool) {
		p, found := pods[key(ns, pod)]
		if !found {
			return "", "", false
		}
		kind, name, owned := controller(p)
		if !owned {
			return "Pod", pod, true
		}
		if kind == "ReplicaSet" {
			if k, n, up := controller(replicaSets[key(ns, name)]); up {
				return k, n, true
			}
		}
		return kind, name, true
	}
	access := func(s Service) string {
		switch {
		case s.Spec.Type != "LoadBalancer":
			return "unknown"
		case len(s.Spec.LoadBalancerSourceRanges) > 0:
			return "restricted"
		}
		return "public"
	}
	accessOf := func(addresses []string) string {
		for _, a := range addresses {
			if s, ok := byAddress[a]; ok {
				return access(s)
			}
		}
		return "unknown"
	}

	out := map[Exposure]bool{}
	expose := func(svcNS, svc, via, gateway string, hostnames []string, acc string) {
		if len(hostnames) == 0 {
			hostnames = []string{""}
		}
		for _, pod := range podsOf[key(svcNS, svc)] {
			kind, name, ok := workload(svcNS, pod)
			if !ok {
				continue
			}
			for _, h := range hostnames {
				out[Exposure{svcNS, name, kind, via, gateway, h, acc}] = true
			}
		}
	}

	gateways := map[string][]string{}
	for _, g := range c.Gateways {
		k := key(g.Metadata.Namespace, g.Metadata.Name)
		for _, a := range g.Status.Addresses {
			gateways[k] = append(gateways[k], a.Value)
		}
	}
	for _, r := range c.Routes {
		ns := r.Metadata.Namespace
		for _, p := range r.Spec.ParentRefs {
			if (p.Group != "" && p.Group != "gateway.networking.k8s.io") || (p.Kind != "" && p.Kind != "Gateway") {
				continue
			}
			// A route the Gateway did not accept gets no traffic from it. With ResolvedRefs False some backend is
			// unusable; a backend in another namespace without a ReferenceGrant is the one case that still has pods,
			// so those are left out.
			accepted, resolved := r.parentStatus(p)
			if !accepted {
				continue
			}
			gw := key(cmp.Or(p.Namespace, ns), p.Name)
			acc := accessOf(gateways[gw])
			for _, rule := range r.Spec.Rules {
				for _, b := range rule.BackendRefs {
					if b.Group != "" || (b.Kind != "" && b.Kind != "Service") {
						continue
					}
					if !resolved && cmp.Or(b.Namespace, ns) != ns {
						continue
					}
					expose(cmp.Or(b.Namespace, ns), b.Name, r.Kind, gw, r.Spec.Hostnames, acc)
				}
			}
		}
	}

	for _, in := range c.Ingresses {
		var addresses []string
		for _, i := range in.Status.LoadBalancer.Ingress {
			addresses = append(addresses, i.IP, i.Hostname)
		}
		acc := accessOf(addresses)
		backend := func(b *IngressBackend, host string) {
			if b != nil && b.Service != nil {
				expose(in.Metadata.Namespace, b.Service.Name, "Ingress", in.Spec.IngressClassName, []string{host}, acc)
			}
		}
		backend(in.Spec.DefaultBackend, "")
		for _, rule := range in.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, p := range rule.HTTP.Paths {
				backend(&p.Backend, rule.Host)
			}
		}
	}

	for _, s := range c.Services {
		if s.Spec.Type == "LoadBalancer" || s.Spec.Type == "NodePort" {
			ns, name := s.Metadata.Namespace, s.Metadata.Name
			expose(ns, name, "Service", key(ns, name), nil, access(s))
		}
	}

	exposures := make([]Exposure, 0, len(out))
	for e := range out {
		exposures = append(exposures, e)
	}
	sortBy(exposures, func(e Exposure) []string {
		return []string{e.Namespace, e.Workload, e.Kind, e.Via, e.Gateway, e.Hostname, e.Access}
	})
	return exposures
}

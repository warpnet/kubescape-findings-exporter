package main

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
)

// Annotation and label keys Kubescape sets on its VulnerabilityManifests.
const (
	annImageID   = "kubescape.io/image-id"
	annImageTag  = "kubescape.io/image-tag"
	lblNamespace = "kubescape.io/workload-namespace"
	lblWorkload  = "kubescape.io/workload-name"
	lblKind      = "kubescape.io/workload-kind"
	lblContainer = "kubescape.io/workload-container-name"
)

// ImageInfo marks an image (digest) as scanned.
type ImageInfo struct{ Image, Digest, Tag string }

// ImageVuln is one CVE in one package version of an image. Identity: Digest, CVE, Package, Version.
type ImageVuln struct{ Image, Digest, Tag, CVE, Severity, Package, Version, FixedVersion, FixState string }

// RelevantVuln is one CVE whose package a workload container loads at runtime. Severity and fix come from the
// ImageVuln with the same Digest, CVE, Package and Version.
type RelevantVuln struct{ Namespace, Workload, Kind, Container, Digest, CVE, Package, Version string }

// Snapshot is the complete series set built from one list of all manifests.
type Snapshot struct {
	Images     []ImageInfo
	ImageVulns []ImageVuln
	Relevant   []RelevantVuln
	Exposures  []Exposure
	Posture    Posture
	// Aliases maps a non-CVE vulnerability ID (GHSA, GO) to its CVE, for the EPSS and KEV lookups.
	Aliases map[string]string
}

var digestRE = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

var severityRanks = map[string]int{"negligible": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

// severityRank orders Grype severities; anything unknown ranks 0, below every floor.
func severityRank(s string) int { return severityRanks[strings.ToLower(s)] }

// digestOf returns the sha256 digest in an image ID, or "" when there is none.
func digestOf(imageID string) string { return digestRE.FindString(imageID) }

// splitRef splits an image reference into repository and tag, dropping any digest.
func splitRef(ref string) (image, tag string) {
	if strings.HasPrefix(ref, "sha256:") {
		return "", ""
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

type vulnKey struct{ digest, cve, pkg, version string }

type vulnVal struct {
	rank                          int
	severity, fixedVersion, state string
}

// Build turns manifests into series. Manifests without a digest (host scans, for now) are skipped; matches below
// minSeverity are dropped. Every slice is sorted, so equal input gives equal output.
func Build(ms []Manifest, minSeverity string) Snapshot {
	floor := severityRank(minSeverity)
	keep := func(m Match) (int, bool) {
		r := severityRank(m.Vulnerability.Severity)
		return r, r > 0 && r >= floor
	}

	images := map[string]ImageInfo{}
	vulns := map[vulnKey]vulnVal{}
	relevant := map[RelevantVuln]bool{}
	aliases := map[string]string{}
	alias := func(x Match) {
		id := x.Vulnerability.ID
		if strings.HasPrefix(id, "CVE-") {
			return
		}
		for _, r := range x.RelatedVulnerabilities {
			if strings.HasPrefix(r.ID, "CVE-") {
				aliases[id] = r.ID
				return
			}
		}
	}

	for _, m := range ms {
		ann := m.Metadata.Annotations
		digest := digestOf(ann[annImageID])
		if digest == "" {
			continue
		}
		if m.Spec.Metadata.WithRelevancy {
			l := m.Metadata.Labels
			for _, x := range m.Spec.Payload.Matches {
				if _, ok := keep(x); ok {
					alias(x)
					relevant[RelevantVuln{l[lblNamespace], l[lblWorkload], l[lblKind], l[lblContainer],
						digest, x.Vulnerability.ID, x.Artifact.Name, x.Artifact.Version}] = true
				}
			}
			continue
		}

		ref := ann[annImageTag]
		if ref == "" {
			ref = ann[annImageID]
		}
		image, tag := splitRef(ref)
		// One digest can be scanned under several tags: keep the smallest non-empty one.
		if cur, ok := images[digest]; !ok || (tag != "" && (cur.Tag == "" || tag < cur.Tag)) {
			images[digest] = ImageInfo{image, digest, tag}
		}
		for _, x := range m.Spec.Payload.Matches {
			r, ok := keep(x)
			if !ok {
				continue
			}
			alias(x)
			k := vulnKey{digest, x.Vulnerability.ID, x.Artifact.Name, x.Artifact.Version}
			// Grype can match one package through several matchers: the highest severity wins.
			if cur, seen := vulns[k]; seen && cur.rank >= r {
				continue
			}
			fixed := slices.Compact(slices.Sorted(slices.Values(x.Vulnerability.Fix.Versions)))
			// Prometheus drops labels with an empty value: an empty state would leave the series without fix_state.
			state := cmp.Or(x.Vulnerability.Fix.State, "unknown")
			vulns[k] = vulnVal{r, strings.ToLower(x.Vulnerability.Severity), strings.Join(fixed, ","), state}
		}
	}

	s := Snapshot{Aliases: aliases}
	for _, i := range images {
		s.Images = append(s.Images, i)
	}
	for k, v := range vulns {
		i := images[k.digest]
		s.ImageVulns = append(s.ImageVulns, ImageVuln{i.Image, k.digest, i.Tag, k.cve, v.severity, k.pkg, k.version,
			v.fixedVersion, v.state})
	}
	for r := range relevant {
		s.Relevant = append(s.Relevant, r)
	}
	sortBy(s.Images, func(i ImageInfo) []string { return []string{i.Image, i.Digest, i.Tag} })
	sortBy(s.ImageVulns, func(v ImageVuln) []string {
		return []string{v.Image, v.Digest, v.Tag, v.CVE, v.Severity, v.Package, v.Version, v.FixedVersion, v.FixState}
	})
	sortBy(s.Relevant, func(r RelevantVuln) []string {
		return []string{r.Namespace, r.Workload, r.Kind, r.Container, r.Digest, r.CVE, r.Package, r.Version}
	})
	return s
}

func sortBy[T any](xs []T, fields func(T) []string) {
	slices.SortFunc(xs, func(a, b T) int { return slices.Compare(fields(a), fields(b)) })
}

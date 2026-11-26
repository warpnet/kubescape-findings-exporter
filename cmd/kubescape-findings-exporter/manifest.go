package main

// Manifest is the part of a Kubescape VulnerabilityManifest (spdx.softwarecomposition.kubescape.io/v1beta1) the
// exporter reads. Decoding only these fields keeps memory low: a full manifest carries descriptions, CVSS scores and
// URLs for every match.
type Manifest struct {
	Metadata struct {
		Name        string            `json:"name"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Metadata struct {
			// true for the filtered manifest of a workload instance: only the matches of packages loaded at runtime.
			WithRelevancy bool `json:"withRelevancy"`
		} `json:"metadata"`
		Payload struct {
			Matches []Match `json:"matches"`
		} `json:"payload"`
	} `json:"spec"`
}

// Match is one Grype match: a vulnerability found in one package.
type Match struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Fix      struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
	} `json:"vulnerability"`
	// Aliases of the vulnerability, such as the CVE of a GHSA or GO ID.
	RelatedVulnerabilities []struct {
		ID string `json:"id"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"artifact"`
}

// Package schema was auto-generated.
// Command: jsonschema2go -gen go -gofmt -gopkg schema -goptr -o schema.go https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
package schema

// CVEAPIJSON20CPEMatch was auto-generated.
// CPE match string or range.
type CVEAPIJSON20CPEMatch struct {
	Criteria              string `json:"criteria"`
	MatchCriteriaId       string `json:"matchCriteriaId"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	Vulnerable            bool   `json:"vulnerable"`
}

// CVEAPIJSON20Node was auto-generated.
// Defines a configuration node in an NVD applicability statement.
type CVEAPIJSON20Node struct {
	CpeMatch []*CVEAPIJSON20CPEMatch `json:"cpeMatch"`
	Negate   bool                    `json:"negate,omitempty"`
	Operator string                  `json:"operator"`
}

// CVEAPIJSON20Config was auto-generated.
type CVEAPIJSON20Config struct {
	Negate   bool                `json:"negate,omitempty"`
	Nodes    []*CVEAPIJSON20Node `json:"nodes"`
	Operator string              `json:"operator,omitempty"`
}

// CVEAPIJSON20LangString was auto-generated.
type CVEAPIJSON20LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// CVSSV20 was auto-generated.
// Source: csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json
type CVSSV20 struct {
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	AccessVector               string  `json:"accessVector,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
	BaseScore                  float64 `json:"baseScore"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
	ConfidentialityImpact      string  `json:"confidentialityImpact,omitempty"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement,omitempty"`
	EnvironmentalScore         float64 `json:"environmentalScore,omitempty"`
	Exploitability             string  `json:"exploitability,omitempty"`
	IntegrityImpact            string  `json:"integrityImpact,omitempty"`
	IntegrityRequirement       string  `json:"integrityRequirement,omitempty"`
	RemediationLevel           string  `json:"remediationLevel,omitempty"`
	ReportConfidence           string  `json:"reportConfidence,omitempty"`
	TargetDistribution         string  `json:"targetDistribution,omitempty"`
	TemporalScore              float64 `json:"temporalScore,omitempty"`
	VectorString               string  `json:"vectorString"`
	Version                    string  `json:"version"`
}

// CVEAPIJSON20CVSSV2 was auto-generated.
type CVEAPIJSON20CVSSV2 struct {
	AcInsufInfo             bool     `json:"acInsufInfo,omitempty"`
	BaseSeverity            string   `json:"baseSeverity,omitempty"`
	CvssData                *CVSSV20 `json:"cvssData"`
	ExploitabilityScore     float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64  `json:"impactScore,omitempty"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege,omitempty"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege,omitempty"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege,omitempty"`
	Source                  string   `json:"source"`
	Type                    string   `json:"type"`
	UserInteractionRequired bool     `json:"userInteractionRequired,omitempty"`
}

// CVSSV30 was auto-generated.
// Source: csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json
type CVSSV30 struct {
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	VectorString                  string  `json:"vectorString"`
	Version                       string  `json:"version"`
}

// CVEAPIJSON20CVSSV30 was auto-generated.
type CVEAPIJSON20CVSSV30 struct {
	CvssData            *CVSSV30 `json:"cvssData"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
	Source              string   `json:"source"`
	Type                string   `json:"type"`
}

// CVSSV31 was auto-generated.
// Source: csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json
type CVSSV31 struct {
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	VectorString                  string  `json:"vectorString"`
	Version                       string  `json:"version"`
}

// CVEAPIJSON20CVSSV31 was auto-generated.
type CVEAPIJSON20CVSSV31 struct {
	CvssData            *CVSSV31 `json:"cvssData"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
	Source              string   `json:"source"`
	Type                string   `json:"type"`
}

// CVEAPIJSON20CVEItemMetrics was auto-generated.
// Metric scores for a vulnerability as found on NVD.
type CVEAPIJSON20CVEItemMetrics struct {
	CvssMetricV2  []*CVEAPIJSON20CVSSV2  `json:"cvssMetricV2,omitempty"`
	CvssMetricV30 []*CVEAPIJSON20CVSSV30 `json:"cvssMetricV30,omitempty"`
	CvssMetricV31 []*CVEAPIJSON20CVSSV31 `json:"cvssMetricV31,omitempty"`
}

// CVEAPIJSON20Reference was auto-generated.
type CVEAPIJSON20Reference struct {
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url"`
}

// CVEAPIJSON20VendorComment was auto-generated.
type CVEAPIJSON20VendorComment struct {
	Comment      string `json:"comment"`
	LastModified string `json:"lastModified"`
	Organization string `json:"organization"`
}

// CVEAPIJSON20Weakness was auto-generated.
type CVEAPIJSON20Weakness struct {
	Description []*CVEAPIJSON20LangString `json:"description"`
	Source      string                    `json:"source"`
	Type        string                    `json:"type"`
}

// CVEAPIJSON20CVEItem was auto-generated.
type CVEAPIJSON20CVEItem struct {
	CisaActionDue         string                       `json:"cisaActionDue,omitempty"`
	CisaExploitAdd        string                       `json:"cisaExploitAdd,omitempty"`
	CisaRequiredAction    string                       `json:"cisaRequiredAction,omitempty"`
	CisaVulnerabilityName string                       `json:"cisaVulnerabilityName,omitempty"`
	Configurations        []*CVEAPIJSON20Config        `json:"configurations,omitempty"`
	Descriptions          []*CVEAPIJSON20LangString    `json:"descriptions"`
	EvaluatorComment      string                       `json:"evaluatorComment,omitempty"`
	EvaluatorImpact       string                       `json:"evaluatorImpact,omitempty"`
	EvaluatorSolution     string                       `json:"evaluatorSolution,omitempty"`
	ID                    string                       `json:"id"`
	LastModified          string                       `json:"lastModified"`
	Metrics               *CVEAPIJSON20CVEItemMetrics  `json:"metrics,omitempty"`
	Published             string                       `json:"published"`
	References            []*CVEAPIJSON20Reference     `json:"references"`
	SourceIdentifier      string                       `json:"sourceIdentifier,omitempty"`
	VendorComments        []*CVEAPIJSON20VendorComment `json:"vendorComments,omitempty"`
	VulnStatus            string                       `json:"vulnStatus,omitempty"`
	Weaknesses            []*CVEAPIJSON20Weakness      `json:"weaknesses,omitempty"`
}

// CVEAPIJSON20DefCVEItem was auto-generated.
type CVEAPIJSON20DefCVEItem struct {
	CVE *CVEAPIJSON20CVEItem `json:"cve"`
}

// CVEAPIJSON20 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
type CVEAPIJSON20 struct {
	Format          string                    `json:"format"`
	ResultsPerPage  int                       `json:"resultsPerPage"`
	StartIndex      int                       `json:"startIndex"`
	Timestamp       string                    `json:"timestamp"`
	TotalResults    int                       `json:"totalResults"`
	Version         string                    `json:"version"`
	Vulnerabilities []*CVEAPIJSON20DefCVEItem `json:"vulnerabilities"`
}

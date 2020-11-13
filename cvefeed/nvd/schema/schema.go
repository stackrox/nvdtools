// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

// TimeLayout is the layout of NVD CVE timestamps.
const TimeLayout = "2006-01-02T15:04Z"

// NVDCVEFeedJSON10DefCPEName was auto-generated.
// CPE name.
type NVDCVEFeedJSON10DefCPEName struct {
	Cpe22Uri string `json:"cpe22Uri,omitempty"`
	Cpe23Uri string `json:"cpe23Uri,omitempty"`
}

// NVDCVEFeedJSON10DefCPEMatch was auto-generated.
// CPE match string or range.
type NVDCVEFeedJSON10DefCPEMatch struct {
	CPEName               []*NVDCVEFeedJSON10DefCPEName `json:"cpe_name,omitempty"`
	Cpe22Uri              string                        `json:"cpe22Uri,omitempty"`
	Cpe23Uri              string                        `json:"cpe23Uri,omitempty"`
	VersionEndExcluding   string                        `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string                        `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding string                        `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string                        `json:"versionStartIncluding,omitempty"`
	Vulnerable            bool                          `json:"vulnerable,omitempty"`
}

// NVDCVEFeedJSON10DefNode was auto-generated.
// Defines a node or sub-node in an NVD applicability statement.
type NVDCVEFeedJSON10DefNode struct {
	CPEMatch []*NVDCVEFeedJSON10DefCPEMatch `json:"cpe_match,omitempty"`
	Children []*NVDCVEFeedJSON10DefNode     `json:"children,omitempty"`
	Negate   bool                           `json:"negate,omitempty"`
	Operator string                         `json:"operator,omitempty"`
}

// NVDCVEFeedJSON10DefConfigurations was auto-generated.
// Defines the set of product configurations for a NVD applicability statement.
type NVDCVEFeedJSON10DefConfigurations struct {
	CVEDataVersion string                     `json:"CVE_data_version,omitempty"`
	Nodes          []*NVDCVEFeedJSON10DefNode `json:"nodes,omitempty"`
}

// CVEJSON40CVEDataMeta was auto-generated.
type CVEJSON40CVEDataMeta struct {
	ASSIGNER string `json:"ASSIGNER,omitempty"`
	ID       string `json:"ID,omitempty"`
	STATE    string `json:"STATE,omitempty"`
}

// CVEJSON40ProductVersionVersionData was auto-generated.
type CVEJSON40ProductVersionVersionData struct {
	VersionAffected string `json:"version_affected,omitempty"`
	VersionValue    string `json:"version_value,omitempty"`
}

// CVEJSON40ProductVersion was auto-generated.
type CVEJSON40ProductVersion struct {
	VersionData []*CVEJSON40ProductVersionVersionData `json:"version_data,omitempty"`
}

// CVEJSON40Product was auto-generated.
type CVEJSON40Product struct {
	ProductName string                   `json:"product_name,omitempty"`
	Version     *CVEJSON40ProductVersion `json:"version,omitempty"`
}

// CVEJSON40AffectsVendorVendorDataProduct was auto-generated.
type CVEJSON40AffectsVendorVendorDataProduct struct {
	ProductData []*CVEJSON40Product `json:"product_data,omitempty"`
}

// CVEJSON40AffectsVendorVendorData was auto-generated.
type CVEJSON40AffectsVendorVendorData struct {
	Product    *CVEJSON40AffectsVendorVendorDataProduct `json:"product,omitempty"`
	VendorName string                                   `json:"vendor_name,omitempty"`
}

// CVEJSON40AffectsVendor was auto-generated.
type CVEJSON40AffectsVendor struct {
	VendorData []*CVEJSON40AffectsVendorVendorData `json:"vendor_data,omitempty"`
}

// CVEJSON40Affects was auto-generated.
type CVEJSON40Affects struct {
	Vendor *CVEJSON40AffectsVendor `json:"vendor,omitempty"`
}

// CVEJSON40LangString was auto-generated.
type CVEJSON40LangString struct {
	Lang  string `json:"lang,omitempty"`
	Value string `json:"value,omitempty"`
}

// CVEJSON40Description was auto-generated.
type CVEJSON40Description struct {
	DescriptionData []*CVEJSON40LangString `json:"description_data,omitempty"`
}

// CVEJSON40ProblemtypeProblemtypeData was auto-generated.
type CVEJSON40ProblemtypeProblemtypeData struct {
	Description []*CVEJSON40LangString `json:"description,omitempty"`
}

// CVEJSON40Problemtype was auto-generated.
type CVEJSON40Problemtype struct {
	ProblemtypeData []*CVEJSON40ProblemtypeProblemtypeData `json:"problemtype_data,omitempty"`
}

// CVEJSON40Reference was auto-generated.
type CVEJSON40Reference struct {
	Name      string   `json:"name,omitempty"`
	Refsource string   `json:"refsource,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	URL       string   `json:"url,omitempty"`
}

// CVEJSON40References was auto-generated.
type CVEJSON40References struct {
	ReferenceData []*CVEJSON40Reference `json:"reference_data,omitempty"`
}

// CVEJSON40 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/CVE_JSON_4.0_min.schema
type CVEJSON40 struct {
	Affects     *CVEJSON40Affects     `json:"affects,omitempty"`
	CVEDataMeta *CVEJSON40CVEDataMeta `json:"CVE_data_meta,omitempty"`
	DataFormat  string                `json:"data_format,omitempty"`
	DataType    string                `json:"data_type,omitempty"`
	DataVersion string                `json:"data_version,omitempty"`
	Description *CVEJSON40Description `json:"description,omitempty"`
	Problemtype *CVEJSON40Problemtype `json:"problemtype,omitempty"`
	References  *CVEJSON40References  `json:"references,omitempty"`
}

// CVSSV20 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/cvss-v2.0.json
type CVSSV20 struct {
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	AccessVector               string  `json:"accessVector,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
	BaseScore                  float64 `json:"baseScore,omitempty"`
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
	VectorString               string  `json:"vectorString,omitempty"`
	Version                    string  `json:"version,omitempty"`
}

// NVDCVEFeedJSON10DefImpactBaseMetricV2 was auto-generated.
// CVSS V2.0 score.
type NVDCVEFeedJSON10DefImpactBaseMetricV2 struct {
	AcInsufInfo             bool     `json:"acInsufInfo,omitempty"`
	CVSSV2                  *CVSSV20 `json:"cvssV2,omitempty"`
	ExploitabilityScore     float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64  `json:"impactScore,omitempty"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege,omitempty"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege,omitempty"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege,omitempty"`
	Severity                string   `json:"severity,omitempty"`
	UserInteractionRequired bool     `json:"userInteractionRequired,omitempty"`
}

// CVSSV30 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/cvss-v3.0.json
type CVSSV30 struct {
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	BaseScore                     float64 `json:"baseScore,omitempty"`
	BaseSeverity                  string  `json:"baseSeverity,omitempty"`
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
	VectorString                  string  `json:"vectorString,omitempty"`
	Version                       string  `json:"version,omitempty"`
}

// NVDCVEFeedJSON10DefImpactBaseMetricV3 was auto-generated.
// CVSS V3.0 score.
type NVDCVEFeedJSON10DefImpactBaseMetricV3 struct {
	CVSSV3              *CVSSV30 `json:"cvssV3,omitempty"`
	ExploitabilityScore float64  `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64  `json:"impactScore,omitempty"`
}

// NVDCVEFeedJSON10DefImpact was auto-generated.
// Impact scores for a vulnerability as found on NVD.
type NVDCVEFeedJSON10DefImpact struct {
	BaseMetricV2 *NVDCVEFeedJSON10DefImpactBaseMetricV2 `json:"baseMetricV2,omitempty"`
	BaseMetricV3 *NVDCVEFeedJSON10DefImpactBaseMetricV3 `json:"baseMetricV3,omitempty"`
}

// NVDCVEFeedJSON10DefCVEItem was auto-generated.
// Defines a vulnerability in the NVD data feed.
type NVDCVEFeedJSON10DefCVEItem struct {
	CVE              *CVEJSON40                         `json:"cve,omitempty"`
	Configurations   *NVDCVEFeedJSON10DefConfigurations `json:"configurations,omitempty"`
	Impact           *NVDCVEFeedJSON10DefImpact         `json:"impact,omitempty"`
	LastModifiedDate string                             `json:"lastModifiedDate,omitempty"`
	PublishedDate    string                             `json:"publishedDate,omitempty"`
}

// NVDCVEFeedJSON10 was auto-generated.
// Source: https://csrc.nist.gov/schema/nvd/feed/1.0/nvd_cve_feed_json_1.0.schema
type NVDCVEFeedJSON10 struct {
	CVEDataFormat       string                        `json:"CVE_data_format,omitempty"`
	CVEDataNumberOfCVEs string                        `json:"CVE_data_numberOfCVEs,omitempty"`
	CVEDataTimestamp    string                        `json:"CVE_data_timestamp,omitempty"`
	CVEDataType         string                        `json:"CVE_data_type,omitempty"`
	CVEDataVersion      string                        `json:"CVE_data_version,omitempty"`
	CVEItems            []*NVDCVEFeedJSON10DefCVEItem `json:"CVE_Items,omitempty"`
}

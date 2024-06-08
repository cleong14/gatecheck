// vim: fdm=marker:

package artifacts

// SarifReportMin is a minimum representation of a Sarif scan report
//
// # It contains only the necessary fields for validation and listing
//
// SARIFREPORTMIN{{{

type SarifReportMin struct {
	Runs []SarifRuns `json:"runs"` // RUNS
}

// RUNS{{{

type SarifRuns struct {
	Results []SarifResults `json:"results"` // RESULTS
	Tool    []SarifTool    `json:"tool"`    // TOOL
	Version string         `json:"version"` // VERSION
}

// RESULTS{{{

type SarifResults struct {
	Fixes     []SarifFixes     `json:"fixes"`     // FIXES
	Level     string           `json:"level"`     // LEVEL
	Locations []SarifLocations `json:"locations"` // LOCATIONS
	Message   SarifMessage     `json:"message"`   // MESSAGE
	RuleId    string           `json:"ruleId"`    // RULEID
}

// RESULTS - FIXES{{{

type SarifFixes struct {
	ArtifactChanges []SarifArtifactChanges `json:"artifactChanges"` // RESULTS - FIXES - ARTIFACT CHANGES
	Description     SarifDescription       `json:"description"`     // RESULTS - FIXES - DESCRIPTION
}

// RESULTS - FIXES - ARTIFACT CHANGES{{{

type SarifArtifactChanges struct {
	ArtifactChangesLocation SarifArtifactChangesLocation `json:"artifactLocation"` // RESULTS - FIXES - ARTIFACT CHANGES - ARTIFACT LOCATION
	Replacements            SarifReplacements            `json:"replacements"`     // RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS
}

// RESULTS - FIXES - ARTIFACT CHANGES - ARTIFACT LOCATION{{{

type SarifArtifactChangesLocation struct {
	Uri string `json:"uri"` // RESULTS - FIXES - ARTIFACT CHANGES - ARTIFACT LOCATION - URI
}

// }}}

// RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS{{{

type SarifReplacements struct {
	DeletedRegion   SarifDeletedRegion   `json:"deletedRegion"`   // RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS - DELETED REGION
	InsertedContent SarifInsertedContent `json:"insertedContent"` // RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS - INSERTED CONTENT
}

// RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS - DELETED REGION{{{

type SarifDeletedRegion struct {
	StartLine int `json:"startLine"` // RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS - DELETED REGION - STARTLINE
}

// }}}

// RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS - INSERTED CONTENT{{{

type SarifInsertedContent struct {
	Text string `json:"text"` // RESULTS - FIXES - ARTIFACT CHANGES - REPLACEMENTS - INSERTED CONTENT - TEXT
}

// }}}

// }}}

// }}}

// RESULTS - FIXES - DESCRIPTION{{{

type SarifDescription struct {
	Text string `json:"text"` // RESULTS - FIXES - DESCRIPTION - TEXT
}

// }}}

// }}}

// RESULTS - LEVEL{{{

// }}}

// RESULTS - LOCATIONS{{{

type SarifLocations struct {
	LogicalLocations []SarifLogicalLocations `json:"logicalLocations"` // RESULTS - LOCATIONS - LOGICAL LOCATIONS
	PhysicalLocation []SarifPhysicalLocation `json:"physicalLocation"` // RESULTS - LOCATIONS - PHYSICAL LOCATION
}

// RESULTS - LOCATIONS - LOGICAL LOCATIONS{{{

type SarifLogicalLocations struct {
	FullyQualifiedName string `json:"fullyQualifiedName"` // RESULTS - LOCATIONS - LOGICAL LOCATIONS - FULLY QUALIFIED NAME
}

// }}}

// RESULTS - LOCATIONS - PHYSICAL LOCATION{{{

type SarifPhysicalLocation struct {
	PhysicalArtifactLocation SarifPhysicalArtifactLocation `json:"artifactLocation"` // RESULTS - LOCATIONS - PHYSICAL LOCATION - ARTIFACT LOCATION
	PhysicalLocationRegion   SarifPhysicalLocationRegion   `json:"region"`           // RESULTS - LOCATIONS - PHYSICAL LOCATION - REGION
}

// RESULTS - LOCATIONS - PHYSICAL LOCATION - ARTIFACT LOCATION{{{

type SarifPhysicalArtifactLocation struct {
	Uri string `json:"uri"` // RESULTS - LOCATIONS - PHYSICAL LOCATION - ARTIFACT LOCATION - URI
}

// }}}

// RESULTS - LOCATIONS - PHYSICAL LOCATION - REGION{{{

type SarifPhysicalLocationRegion struct {
	StartLine int `json:"startLine"` // RESULTS - LOCATIONS - PHYSICAL LOCATION - REGION - STARTLINE
}

// }}}

// }}}

// }}}

// RESULTS - MESSAGE{{{

type SarifMessage struct {
	Text string `json:"text"` // RESULTS - MESSAGE - TEXT
}

// }}}

// RESULTS - RULEID{{{

// }}}

// }}}

// TOOL{{{

type SarifTool struct {
	Driver SarifDriver `json:"driver"` // DRIVER
}

// TOOL - DRIVER{{{

type SarifDriver struct {
	Name       string                 `json:"name"`       // TOOL - DRIVER - NAME
	Properties struct{}               `json:"properties"` // TOOL - DRIVER - PROPERTIES
	Rules      []SarifToolDriverRules `json:"rules"`      // TOOL - DRIVER - RULES
}

// TOOL - DRIVER - RULES{{{

type SarifToolDriverRules struct {
	FullDescription  SarifToolDriverRulesFullDescription  `json:"fullDescription"`  // TOOL - DRIVER - RULES - FULL DESCRIPTION
	Help             SarifToolDriverRulesHelp             `json:"help"`             // TOOL - DRIVER - RULES - HELP
	Id               string                               `json:"id"`               // TOOL - DRIVER - RULES - ID
	Properties       SarifToolDriverRulesProperties       `json:"properties"`       // TOOL - DRIVER - RULES - PROPERTIES
	ShortDescription SarifToolDriverRulesShortDescription `json:"shortDescription"` // TOOL - DRIVER - RULES - SHORT DESCRIPTION
}

// TOOL - DRIVER - RULES - FULL DESCRIPTION{{{

type SarifToolDriverRulesFullDescription struct {
	Text string `json:"text"` // TOOL - DRIVER - RULES - FULL DESCRIPTION - TEXT
}

// }}}

// TOOL - DRIVER - RULES - HELP{{{

type SarifToolDriverRulesHelp struct {
	Markdown string `json:"markdown"` // TOOL - DRIVER - RULES - HELP - MARKDOWN
	Text     string `json:"text"`     // TOOL - DRIVER - RULES - HELP - TEXT
}

// }}}

// TOOL - DRIVER - RULES - ID{{{

// }}}

// TOOL - DRIVER - RULES - PROPERTIES{{{

type SarifToolDriverRulesProperties struct {
	Cvssv3_baseScore  float64  `json:"cvssv3_baseScore"`  // TOOL - DRIVER - RULES - PROPERTIES - CVSSV3_BASESCORE
	Security_severity string   `json:"security-severity"` // TOOL - DRIVER - RULES - PROPERTIES - SECURITY_SEVERITY
	Tags              []string `json:"tags"`              // TOOL - DRIVER - RULES - PROPERTIES - TAGS
}

// }}}

// TOOL - DRIVER - RULES - SHORT DESCRIPTION{{{

type SarifToolDriverRulesShortDescription struct {
	Text string `json:"text"` // TOOL - DRIVER - RULES - SHORT DESCRIPTION - TEXT
}

// }}}

// }}}

// }}}

// }}}

// VERSION{{{

// }}}

// }}}

// }}}

// ======================================================================

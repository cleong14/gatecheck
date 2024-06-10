package artifacts

// SarifReportMin is a minimum representation of a Sarif scan report
//
// # It contains only the necessary fields for validation and listing
type SarifReportMin struct {
	Runs []SarifRun `json:"runs"`
}

type SarifRun struct {
	Results []SarifResult `json:"results"`
}

type SarifResult struct {
	Level   string       `json:"level"`
	Message SarifMessage `json:"message"`
	RuleId  string       `json:"ruleId"`
}

type SarifMessage struct {
	Text string `json:"text"`
}

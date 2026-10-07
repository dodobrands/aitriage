package models

import "strings"

// NormalizeFindingStatus validates writes while retaining supported legacy names.
func NormalizeFindingStatus(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "fixed":
		value = "resolved"
	case "accepted_risk":
		value = "risk_accepted"
	}
	switch value {
	case "open", "confirmed", "triage", "in_progress", "sent_to_agent", "pending_verification", "verification_failed", "resolved", "closed", "mitigated", "false_positive", "risk_accepted":
		return value, true
	}
	return "", false
}

func FindingStatus(f *Finding) string {
	status := strings.ToLower(strings.TrimSpace(f.Status))
	if status == "" {
		status = "open"
	}
	if status == "fixed" || (status == "open" && f.VerificationStatus != nil && *f.VerificationStatus == "fixed") {
		return "resolved"
	}
	if status == "accepted_risk" {
		return "risk_accepted"
	}
	return status
}
func FindingResolved(f *Finding) bool {
	switch FindingStatus(f) {
	case "resolved", "closed", "mitigated":
		return true
	}
	return false
}
func FindingActive(f *Finding) bool {
	switch FindingStatus(f) {
	case "resolved", "closed", "mitigated", "false_positive", "risk_accepted":
		return false
	}
	return true
}

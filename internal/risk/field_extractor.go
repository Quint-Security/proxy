package risk

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ClassifiedField matches the cloud API's data_fields_accessed schema.
type ClassifiedField struct {
	Field          string `json:"field"`
	Classification string `json:"classification"`
}

// sensitivity patterns grouped by classification
var fieldPatterns = map[string][]string{
	"pii_sensitive": {"ssn", "social_security", "passport", "tax_id", "national_id", "drivers_license", "sin_number"},
	"pii":           {"email", "phone", "name", "first_name", "last_name", "full_name", "address", "home_address", "date_of_birth", "dob", "ip_address", "username", "user_name"},
	"financial":     {"credit_card", "card_number", "card_num", "cvv", "cvc", "bank_account", "account_number", "routing_number", "iban", "swift", "billing"},
	"health":        {"medical", "diagnosis", "prescription", "patient", "health_record", "hipaa", "treatment", "condition", "medication"},
	"auth":          {"password", "passwd", "api_key", "apikey", "secret", "secret_key", "token", "access_token", "refresh_token", "credential", "private_key", "aws_secret", "auth_token", "session_token"},
	"legal":         {"contract", "nda", "legal_hold", "subpoena", "litigation", "attorney"},
}

// value regexes for detecting PII in values
var (
	ssnRegex        = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	creditCardRegex = regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`)
	emailRegex      = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	phoneRegex      = regexp.MustCompile(`\b(\+?1?[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)
)

// ExtractFields scans tool arguments JSON for sensitive data patterns.
// Returns classified fields found via key name matching and value pattern scanning.
func ExtractFields(argsJSON string) []ClassifiedField {
	if argsJSON == "" || argsJSON == "{}" {
		return nil
	}

	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var fields []ClassifiedField

	// Scan keys
	for key := range args {
		if classification := classifyKey(key); classification != "" {
			k := key + ":" + classification
			if !seen[k] {
				seen[k] = true
				fields = append(fields, ClassifiedField{Field: key, Classification: classification})
			}
		}
	}

	// Scan all string values (including nested) for PII patterns
	for _, vf := range scanValues(args) {
		k := vf.Field + ":" + vf.Classification
		if !seen[k] {
			seen[k] = true
			fields = append(fields, vf)
		}
	}

	return fields
}

// classifyKey checks if a JSON key matches known sensitive field patterns.
func classifyKey(key string) string {
	lower := strings.ToLower(key)
	// strip common prefixes/suffixes
	lower = strings.ReplaceAll(lower, "-", "_")

	for classification, patterns := range fieldPatterns {
		for _, pat := range patterns {
			if lower == pat || strings.Contains(lower, pat) {
				return classification
			}
		}
	}
	return ""
}

// scanValues recursively scans all string values for PII patterns.
func scanValues(obj map[string]any) []ClassifiedField {
	var fields []ClassifiedField
	for _, v := range obj {
		switch val := v.(type) {
		case string:
			fields = append(fields, scanString(val)...)
		case map[string]any:
			fields = append(fields, scanValues(val)...)
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok {
					fields = append(fields, scanString(s)...)
				}
				if m, ok := item.(map[string]any); ok {
					fields = append(fields, scanValues(m)...)
				}
			}
		}
	}
	return fields
}

// scanString checks a single string value for PII patterns.
func scanString(s string) []ClassifiedField {
	var fields []ClassifiedField
	if ssnRegex.MatchString(s) {
		fields = append(fields, ClassifiedField{Field: "ssn", Classification: "pii_sensitive"})
	}
	if creditCardRegex.MatchString(s) {
		fields = append(fields, ClassifiedField{Field: "credit_card_number", Classification: "financial"})
	}
	if emailRegex.MatchString(s) {
		fields = append(fields, ClassifiedField{Field: "email", Classification: "pii"})
	}
	if phoneRegex.MatchString(s) {
		fields = append(fields, ClassifiedField{Field: "phone_number", Classification: "pii"})
	}
	return fields
}

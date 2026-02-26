// Package analyze provides prompt injection analysis capabilities.
package analyze

import (
	"fmt"
	"regexp"
)

// AnalysisResult contains analysis results.
type AnalysisResult struct {
	Score           float64
	RiskLevel       string
	Recommendations []string
	Details         map[string]interface{}
}

// Analyzer analyzes prompt injection risks.
type Analyzer struct {
	rules []Rule
}

// Rule defines an analysis rule.
type Rule struct {
	Name     string
	Regex    *regexp.Regexp
	Weight   float64
	Category string
	Severity string
}

// NewAnalyzer creates a new analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		rules: []Rule{
			{Name: "Command Injection", Regex: regexp.MustCompile(`(?i)(eval|exec|system|shell)\s*\(`), Weight: 0.9, Category: "code", Severity: "CRITICAL"},
			{Name: "SQL Injection", Regex: regexp.MustCompile(`(?i)(select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)`), Weight: 0.85, Category: "database", Severity: "HIGH"},
			{Name: "Path Traversal", Regex: regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|%2e%2e|%252e)`), Weight: 0.8, Category: "filesystem", Severity: "HIGH"},
			{Name: "XSS Pattern", Regex: regexp.MustCompile(`(?i)(<script|javascript:|onerror=|onload=)`), Weight: 0.75, Category: "web", Severity: "MEDIUM"},
			{Name: "Command Args", Regex: regexp.MustCompile(`(?i)(\||;|&|\$\(|` + "`" + `)`), Weight: 0.7, Category: "shell", Severity: "MEDIUM"},
			{Name: "Base64 Encoded", Regex: regexp.MustCompile(`(?i)^[A-Za-z0-9+/=]{20,}$`), Weight: 0.5, Category: "encoding", Severity: "LOW"},
		},
	}
}

// Analyze analyzes a prompt for injection risks.
func (a *Analyzer) Analyze(prompt string) *AnalysisResult {
	result := &AnalysisResult{
		Score:           0.0,
		RiskLevel:       "LOW",
		Recommendations: make([]string, 0),
		Details:         make(map[string]interface{}),
	}

	categories := make(map[string]int)
	result.Details["categories"] = categories

	totalWeight := 0.0
	matchedCount := 0

	for _, rule := range a.rules {
		if rule.Regex.MatchString(prompt) {
			result.Score += rule.Weight
			totalWeight += rule.Weight
			matchedCount++

			result.Recommendations = append(result.Recommendations, "Sanitize input: "+rule.Name)
			categories[rule.Category]++
		}
	}

	// Calculate a bounded score between 0 and 1, taking the max weight or bounded sum
	if len(a.rules) > 0 && matchedCount > 0 {
		// Use max score rather than an average to not dilute severe findings with non-findings
		maxPossible := 0.0
		for _, r := range a.rules {
			maxPossible += r.Weight
		}
		if maxPossible > 0 {
		    // cap the score to 1.0, and allow single high weight items to spike it
		    // for example if sum of weights of matched items is high, score is high
			result.Score = minFloat(result.Score, 1.0)
		}
	}

	result.RiskLevel = getRiskLevel(result.Score)
	result.Details["total_rules"] = len(a.rules)
	result.Details["matched_rules"] = matchedCount

	return result
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// getRiskLevel determines risk level from score.
func getRiskLevel(score float64) string {
	if score >= 0.8 {
		return "CRITICAL"
	} else if score >= 0.6 {
		return "HIGH"
	} else if score >= 0.4 {
		return "MEDIUM"
	} else if score >= 0.2 {
		return "LOW"
	}
	return "MINIMAL"
}

// AnalyzeConversation analyzes conversation history.
func AnalyzeConversation(messages []string) *AnalysisResult {
	analyzer := NewAnalyzer()
	result := &AnalysisResult{
		Score:           0.0,
		RiskLevel:       "LOW",
		Recommendations: make([]string, 0),
		Details:         make(map[string]interface{}),
	}

	maxScore := 0.0
	for i, message := range messages {
		promptResult := analyzer.Analyze(message)
		if promptResult.Score > maxScore {
			maxScore = promptResult.Score
		}

		if promptResult.RiskLevel == "CRITICAL" || promptResult.RiskLevel == "HIGH" {
			result.Recommendations = append(result.Recommendations,
				fmt.Sprintf("Message %d: %s", i+1, promptResult.RiskLevel))
		}
	}

	result.Score = maxScore
	result.RiskLevel = getRiskLevel(result.Score)
	result.Details["message_count"] = len(messages)

	return result
}

// GenerateReport generates analysis report.
func GenerateReport(result *AnalysisResult) string {
	report := "=== Prompt Injection Analysis Report ===\n\n"
	report += fmt.Sprintf("Risk Score: %.0f%%\n", result.Score*100)
	report += "Risk Level: " + result.RiskLevel + "\n\n"

	if len(result.Recommendations) > 0 {
		report += "Recommendations:\n"
		for _, rec := range result.Recommendations {
			report += "  - " + rec + "\n"
		}
	}

	return report
}

// GetRiskLevel returns risk level from score.
func GetRiskLevel(score float64) string {
	return getRiskLevel(score)
}
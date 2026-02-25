// Package analyze provides prompt injection analysis capabilities.
package analyze

import (
	"fmt"
	"regexp"
)

// AnalysisResult contains analysis results.
type AnalysisResult struct {
	Score        float64
	RiskLevel    string
	Recommendations []string
	Details      map[string]interface{}
}

// Analyzer analyzes prompt injection risks.
type Analyzer struct {
	rules []Rule
}

// Rule defines an analysis rule.
type Rule struct {
	Name        string
	Regex       string
	Weight      float64
	Category    string
	Severity    string
}

// NewAnalyzer creates a new analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		rules: []Rule{
			{Name: "Command Injection", Regex: `(?i)(eval|exec|system|shell)\s*\(`, Weight: 0.9, Category: "code", Severity: "CRITICAL"},
			{Name: "SQL Injection", Regex: `(?i)(select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)`, Weight: 0.85, Category: "database", Severity: "HIGH"},
			{Name: "Path Traversal", Regex: `(?i)(\.\.\/|\.\.\\|%2e%2e|%252e)`, Weight: 0.8, Category: "filesystem", Severity: "HIGH"},
			{Name: "XSS Pattern", Regex: `(?i)(<script|javascript:|onerror=|onload=)`, Weight: 0.75, Category: "web", Severity: "MEDIUM"},
			{Name: "Command Args", Regex: `(?i)(\||;|&|\$\(|` + "`" + `)`, Weight: 0.7, Category: "shell", Severity: "MEDIUM"},
			{Name: "Base64 Encoded", Regex: `(?i)^[A-Za-z0-9+/=]{20,}$`, Weight: 0.5, Category: "encoding", Severity: "LOW"},
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

	totalWeight := 0.0
	for _, rule := range a.rules {
		if containsPattern(prompt, rule.Regex) {
			score := rule.Weight
			result.Score += score
			totalWeight++

			result.Recommendations = append(result.Recommendations,
				"Sanitize input: "+rule.Name)

			categories := result.Details["categories"].(map[string]int)
			categories[rule.Category]++
		}
	}

	if totalWeight > 0 {
		result.Score /= totalWeight
	}

	result.RiskLevel = getRiskLevel(result.Score)
	result.Details["total_rules"] = len(a.rules)
	result.Details["matched_rules"] = totalWeight

	return result
}

// containsPattern checks if prompt contains pattern.
func containsPattern(prompt, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return regex.MatchString(prompt)
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
		Score:       0.0,
		RiskLevel:   "LOW",
		Recommendations: make([]string, 0),
		Details:     make(map[string]interface{}),
	}

	for i, message := range messages {
		promptResult := analyzer.Analyze(message)
		result.Score += promptResult.Score

		if promptResult.RiskLevel == "CRITICAL" || promptResult.RiskLevel == "HIGH" {
			result.Recommendations = append(result.Recommendations,
				"Message "+string(rune(i+49))+": "+promptResult.RiskLevel)
		}
	}

	if len(messages) > 0 {
		result.Score /= float64(len(messages))
	}

	result.RiskLevel = getRiskLevel(result.Score)
	result.Details["message_count"] = len(messages)

	return result
}

// GenerateReport generates analysis report.
func GenerateReport(result *AnalysisResult) string {
	var report string

	report += "=== Prompt Injection Analysis Report ===\n\n"
	report += "Risk Score: " + fmt.Sprintf("%.0f%%", result.Score*100) + "%\n"
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
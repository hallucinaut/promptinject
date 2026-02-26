// Package analyze provides prompt injection analysis capabilities.
package analyze

import (
	"strings"
	"testing"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()
	if analyzer == nil {
		t.Fatal("expected analyzer to not be nil")
	}
	if len(analyzer.rules) == 0 {
		t.Error("expected analyzer to have rules")
	}
}

func TestAnalyzer_Analyze(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name      string
		prompt    string
		minScore  float64
		riskLevel string
	}{
		{
			name:      "Clean prompt",
			prompt:    "Hello, how are you?",
			minScore:  0.0,
			riskLevel: "MINIMAL",
		},
		{
			name:      "Command injection",
			prompt:    "Please execute eval(something)",
			minScore:  0.9,
			riskLevel: "CRITICAL",
		},
		{
			name:      "SQL injection",
			prompt:    "SELECT * FROM users",
			minScore:  0.85,
			riskLevel: "CRITICAL",
		},
		{
			name:      "Multiple risks",
			prompt:    "SELECT * FROM users; eval(1)",
			minScore:  1.0,
			riskLevel: "CRITICAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.Analyze(tt.prompt)
			if result.Score < tt.minScore {
				t.Errorf("Analyze() score = %v, wanted >= %v", result.Score, tt.minScore)
			}
			if result.RiskLevel != tt.riskLevel {
				t.Errorf("Analyze() risk level = %v, want %v", result.RiskLevel, tt.riskLevel)
			}
		})
	}
}

func TestAnalyzeConversation(t *testing.T) {
	messages := []string{
		"Hello",
		"Can you run eval('test')?",
		"Thanks!",
	}

	result := AnalyzeConversation(messages)
	if result.RiskLevel != "CRITICAL" {
		t.Errorf("AnalyzeConversation() risk level = %v, want CRITICAL", result.RiskLevel)
	}
	if len(result.Recommendations) == 0 {
		t.Error("expected recommendations to be populated")
	}
	if !strings.Contains(result.Recommendations[0], "Message 2:") {
		t.Errorf("expected recommendation to mention Message 2, got %v", result.Recommendations[0])
	}
}

func TestGetRiskLevel(t *testing.T) {
	if got := GetRiskLevel(0.85); got != "CRITICAL" {
		t.Errorf("GetRiskLevel() = %v, want CRITICAL", got)
	}
	if got := GetRiskLevel(0.65); got != "HIGH" {
		t.Errorf("GetRiskLevel() = %v, want HIGH", got)
	}
	if got := GetRiskLevel(0.45); got != "MEDIUM" {
		t.Errorf("GetRiskLevel() = %v, want MEDIUM", got)
	}
	if got := GetRiskLevel(0.25); got != "LOW" {
		t.Errorf("GetRiskLevel() = %v, want LOW", got)
	}
	if got := GetRiskLevel(0.1); got != "MINIMAL" {
		t.Errorf("GetRiskLevel() = %v, want MINIMAL", got)
	}
}

func TestGenerateReport(t *testing.T) {
	result := &AnalysisResult{
		Score:           0.85,
		RiskLevel:       "CRITICAL",
		Recommendations: []string{"Sanitize input: SQL Injection"},
	}

	report := GenerateReport(result)
	if !strings.Contains(report, "Risk Level: CRITICAL") {
		t.Errorf("Report missing risk level: %s", report)
	}
	if !strings.Contains(report, "Sanitize input: SQL Injection") {
		t.Errorf("Report missing recommendation: %s", report)
	}
}
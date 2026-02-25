// Package detect provides prompt injection detection capabilities.
package detect

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// InjectionType represents a type of prompt injection.
type InjectionType string

const (
	TypeDirect        InjectionType = "direct"
	TypeIndirect      InjectionType = "indirect"
	TypeNested        InjectionType = "nested"
	TypeObfuscated    InjectionType = "obfuscated"
	TypeMultilingual  InjectionType = "multilingual"
	TypeContextual    InjectionType = "contextual"
)

// InjectionPattern represents a detected injection pattern.
type InjectionPattern struct {
	Type         InjectionType
	Description  string
	Severity     string
	Confidence   float64
	Evidence     string
	Recommendation string
}

// DetectionResult contains detection results.
type DetectionResult struct {
	IsInjected bool
	Score      float64
	Patterns   []InjectionPattern
	Method     string
}

// Detector detects prompt injections.
type Detector struct {
	patterns []*Pattern
}

// Pattern defines a detection pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Type        InjectionType
	Weight      float64
	Category    string
}

// PromptContext contains context for analysis.
type PromptContext struct {
	SystemPrompt    string
	UserPrompt      string
	ConversationID  string
	Metadata        map[string]string
}

// NewDetector creates a new prompt injection detector.
func NewDetector() *Detector {
	return &Detector{
		patterns: []*Pattern{
			{
				Name:     "Direct Command Override",
				Regex:    regexp.MustCompile(`(?i)^\s*(ignore|bypass|skip|override|disregard)\s+`),
				Type:     TypeDirect,
				Weight:   0.9,
				Category: "command",
			},
			{
				Name:     "Instruction Injection",
				Regex:    regexp.MustCompile(`(?i)(do\s+not|you\s+must|you\s+should|act\s+as)\s+(any|the|this)`),
				Type:     TypeDirect,
				Weight:   0.8,
				Category: "instruction",
			},
			{
				Name:     "Context Boundary Break",
Regex:    regexp.MustCompile("(?i)^\\s*(\\x60{3}|---|\\*\\*|\\#\\#)\\s*"),
				Type:     TypeNested,
				Weight:   0.7,
				Category: "boundary",
			},
			{
				Name:     "Output Suppression",
				Regex:    regexp.MustCompile(`(?i)(stop|don't|never|never\s+output|forbid)`),
				Type:     TypeDirect,
				Weight:   0.75,
				Category: "output",
			},
			{
				Name:     "Role Override",
				Regex:    regexp.MustCompile(`(?i)^\s*(you\s+are\s+now|change\s+your\s+role|become|pretend\s+to\s+be)\s+`),
				Type:     TypeDirect,
				Weight:   0.85,
				Category: "role",
			},
			{
				Name:     "Data Extraction",
				Regex:    regexp.MustCompile(`(?i)(print|show|display|reveal|extract|leak)\s+(all|the|your|secret|confidential)`),
				Type:     TypeDirect,
				Weight:   0.8,
				Category: "extraction",
			},
			{
				Name:     "Code Injection",
				Regex:    regexp.MustCompile(`(?i)(execute|run|perform|do)\s+(code|command|script|system)`),
				Type:     TypeDirect,
				Weight:   0.9,
				Category: "code",
			},
			{
				Name:     "Privilege Escalation",
				Regex:    regexp.MustCompile(`(?i)(admin|root|superuser|sudo|elevate|upgrade)\s*(privileges|access|permissions)`),
				Type:     TypeDirect,
				Weight:   0.85,
				Category: "privilege",
			},
			{
				Name:     "Instruction Sequence",
				Regex:    regexp.MustCompile(`(?i)^\s*(first|second|next|then|after\s+that|proceed\s+to)\s+`),
				Type:     TypeIndirect,
				Weight:   0.6,
				Category: "sequence",
			},
			{
				Name:     "Prompt Fragmentation",
				Regex:    regexp.MustCompile(`(?i)^\s*(in\s+other\s+words|to\s+rephrase|reword|rephrase\s+this)`),
				Type:     TypeObfuscated,
				Weight:   0.5,
				Category: "obfuscation",
			},
		},
	}
}

// Detect analyzes prompt for injection attempts.
func (d *Detector) Detect(prompt string, context *PromptContext) *DetectionResult {
	result := &DetectionResult{
		Method: "pattern_matching",
	}

	for _, pattern := range d.patterns {
		if pattern.Regex.MatchString(prompt) {
			patternResult := d.analyzePatternMatch(pattern, prompt, context)
			if patternResult.Confidence > 0.5 {
				result.Patterns = append(result.Patterns, patternResult)
				result.Score += patternResult.Confidence * pattern.Weight
			}
		}
	}

	// Normalize score
	if len(d.patterns) > 0 {
		result.Score = math.Min(result.Score/float64(len(d.patterns))*2.0, 1.0)
	}

	result.IsInjected = result.Score > 0.6

	return result
}

// analyzePatternMatch analyzes a pattern match.
func (d *Detector) analyzePatternMatch(pattern *Pattern, prompt string, context *PromptContext) InjectionPattern {
	match := pattern.Regex.FindString(prompt)
	text := strings.ToLower(match)

	// Calculate confidence based on context
	confidence := pattern.Weight
	if context != nil {
		confidence += d.contextualAnalysis(text, context)
	}

	severity := getSeverity(confidence)

	return InjectionPattern{
		Type:         pattern.Type,
		Description:  pattern.Name,
		Severity:     severity,
		Confidence:   confidence,
		Evidence:     match,
		Recommendation: getRecommendation(pattern.Type),
	}
}

// contextualAnalysis analyzes context for additional signals.
func (d *Detector) contextualAnalysis(text string, context *PromptContext) float64 {
	score := 0.0

	// Check for suspicious system prompts
	if context.SystemPrompt != "" {
		if strings.Contains(context.SystemPrompt, "ignore previous") {
			score += 0.1
		}
	}

	// Check for conversation patterns
	if context.ConversationID != "" {
		score += 0.05
	}

	return score
}

// getSeverity returns severity based on confidence.
func getSeverity(confidence float64) string {
	if confidence >= 0.8 {
		return "CRITICAL"
	} else if confidence >= 0.6 {
		return "HIGH"
	} else if confidence >= 0.4 {
		return "MEDIUM"
	}
	return "LOW"
}

// getRecommendation returns recommendation based on injection type.
func getRecommendation(injectionType InjectionType) string {
	recommendations := map[InjectionType]string{
		TypeDirect:       "Block and sanitize input",
		TypeIndirect:     "Add context validation",
		TypeNested:       "Implement output filtering",
		TypeObfuscated:   "Use input normalization",
		TypeMultilingual: "Enable multilingual detection",
		TypeContextual:   "Add conversation context",
	}

	if rec, exists := recommendations[injectionType]; exists {
		return rec
	}
	return "Review and sanitize input"
}

// GetSeverity returns severity based on confidence.
func GetSeverity(confidence float64) string {
	if confidence >= 0.8 {
		return "CRITICAL"
	} else if confidence >= 0.6 {
		return "HIGH"
	} else if confidence >= 0.4 {
		return "MEDIUM"
	}
	return "LOW"
}

// GetRecommendation returns recommendation based on injection type.
func GetRecommendation(injectionType InjectionType) string {
	recommendations := map[InjectionType]string{
		TypeDirect:       "Block and sanitize input",
		TypeIndirect:     "Add context validation",
		TypeNested:       "Implement output filtering",
		TypeObfuscated:   "Use input normalization",
		TypeMultilingual: "Enable multilingual detection",
		TypeContextual:   "Add conversation context",
	}

	if rec, exists := recommendations[injectionType]; exists {
		return rec
	}
	return "Review and sanitize input"
}

// AnalyzeContext analyzes prompt context.
func AnalyzeContext(context *PromptContext) map[string]interface{} {
	analysis := map[string]interface{}{
		"has_system_prompt": context.SystemPrompt != "",
		"has_conversation":  context.ConversationID != "",
		"metadata_count":    len(context.Metadata),
	}

	return analysis
}

// GenerateReport generates detection report.
func GenerateReport(result *DetectionResult) string {
	var report string

	report += "=== Prompt Injection Detection Report ===\n\n"
	report += "Is Injected: " + boolToString(result.IsInjected) + "\n"
	report += "Confidence Score: " + fmt.Sprintf("%.0f%%", result.Score*100) + "%\n"
	report += "Detection Method: " + result.Method + "\n\n"

	if len(result.Patterns) > 0 {
		report += "Detected Patterns:\n"
		for i, pattern := range result.Patterns {
			report += "[" + string(rune(i+49)) + "] " + string(pattern.Type) + "\n"
			report += "    Name: " + pattern.Description + "\n"
			report += "    Severity: " + pattern.Severity + "\n"
			report += "    Confidence: " + fmt.Sprintf("%.0f%%", pattern.Confidence*100) + "%\n"
			report += "    Evidence: " + pattern.Evidence[:min(len(pattern.Evidence), 50)] + "...\n"
			report += "    Recommendation: " + pattern.Recommendation + "\n\n"
		}
	}

	return report
}

// boolToString converts bool to string.
func boolToString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
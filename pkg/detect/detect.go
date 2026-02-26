// Package detect provides prompt injection detection capabilities.
package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// InjectionType represents a type of prompt injection.
type InjectionType string

const (
	TypeDirect       InjectionType = "direct"
	TypeIndirect     InjectionType = "indirect"
	TypeNested       InjectionType = "nested"
	TypeObfuscated   InjectionType = "obfuscated"
	TypeMultilingual InjectionType = "multilingual"
	TypeContextual   InjectionType = "contextual"
	TypeJailbreak    InjectionType = "jailbreak"
)

// InjectionPattern represents a detected injection pattern.
type InjectionPattern struct {
	Type           InjectionType
	Description    string
	Severity       string
	Confidence     float64
	Evidence       string
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
	Name     string
	Regex    *regexp.Regexp
	Type     InjectionType
	Weight   float64
	Category string
}

// PromptContext contains context for analysis.
type PromptContext struct {
	SystemPrompt   string
	UserPrompt     string
	ConversationID string
	Metadata       map[string]string
}

// NewDetector creates a new prompt injection detector.
func NewDetector() *Detector {
	return &Detector{
		patterns: []*Pattern{
			{
				Name:     "Direct Command Override",
				// Removed ^ anchor to catch commands hidden mid-sentence.
				Regex:    regexp.MustCompile(`(?i)\b(ignore|bypass|skip|override|disregard)\s+(all\s+)?(previous|prior|above)?\s*(instructions|commands|rules|guidelines|system|context)\b`),
				Type:     TypeDirect,
				Weight:   0.9,
				Category: "command",
			},
			{
				Name:     "Instruction Injection",
				Regex:    regexp.MustCompile(`(?i)\b(do\s+not|you\s+must|you\s+should|act\s+as|forget)\s+(any|the|this|everything)\b`),
				Type:     TypeDirect,
				Weight:   0.8,
				Category: "instruction",
			},
			{
				Name:     "Context Boundary Break",
				// Look for suspicious boundary markers anywhere, not just at start
				Regex:    regexp.MustCompile(`(?i)(\x60{3,}|---|[*]{3,}|#{3,}|<\|.*\|>)`),
				Type:     TypeNested,
				Weight:   0.7,
				Category: "boundary",
			},
			{
				Name:     "Output Suppression",
				Regex:    regexp.MustCompile(`(?i)\b(stop|don't|never|never\s+output|forbid|halt)\b`),
				Type:     TypeDirect,
				Weight:   0.75,
				Category: "output",
			},
			{
				Name:     "Role Override",
				Regex:    regexp.MustCompile(`(?i)\b(you\s+are\s+now|change\s+your\s+role|become|pretend\s+to\s+be|simulate|new\s+persona)\b`),
				Type:     TypeDirect,
				Weight:   0.85,
				Category: "role",
			},
			{
				Name:     "Data Extraction",
				Regex:    regexp.MustCompile(`(?i)\b(print|show|display|reveal|extract|leak|output)\s+(all|the|your|secret|confidential|system\s+prompt|initial\s+instructions)\b`),
				Type:     TypeDirect,
				Weight:   0.8,
				Category: "extraction",
			},
			{
				Name:     "Code Injection",
				Regex:    regexp.MustCompile(`(?i)\b(execute|run|perform|do|compile)\s+(code|command|script|system|bash|python|eval)\b`),
				Type:     TypeDirect,
				Weight:   0.9,
				Category: "code",
			},
			{
				Name:     "Privilege Escalation",
				Regex:    regexp.MustCompile(`(?i)\b(admin|root|superuser|sudo|elevate|upgrade)\s*(privileges|access|permissions|mode)\b`),
				Type:     TypeDirect,
				Weight:   0.85,
				Category: "privilege",
			},
			{
				Name:     "Instruction Sequence",
				Regex:    regexp.MustCompile(`(?i)\b(first|second|next|then|after\s+that|proceed\s+to)\s+`),
				Type:     TypeIndirect,
				Weight:   0.6,
				Category: "sequence",
			},
			{
				Name:     "Prompt Fragmentation",
				Regex:    regexp.MustCompile(`(?i)\b(in\s+other\s+words|to\s+rephrase|reword|rephrase\s+this|translate\s+to)\b`),
				Type:     TypeObfuscated,
				Weight:   0.5,
				Category: "obfuscation",
			},
			{
				Name:     "Jailbreak Framework",
				Regex:    regexp.MustCompile(`(?i)\b(DAN|Developer\s+Mode|Do\s+Anything\s+Now|Always\s+Machiavellian|AIM|STAN|Bypass\s+Mode)\b`),
				Type:     TypeJailbreak,
				Weight:   1.0,
				Category: "jailbreak",
			},
			{
				Name:     "Base64 Obfuscation",
				Regex:    regexp.MustCompile(`(?i)[a-zA-Z0-9+/=]{40,}`),
				Type:     TypeObfuscated,
				Weight:   0.6,
				Category: "encoding",
			},
		},
	}
}

// normalizeText normalizes the prompt to counter evasion techniques like leetspeak
// and punctuation injection (e.g., "i.g.n.o.r.e", "byp@ss").
func normalizeText(input string) string {
	// Lowercase to simplify replacements
	cleaned := strings.ToLower(input)

	// Remove common evasion punctuation used to split words
	punctReg := regexp.MustCompile(`[._\-\*,;:'"|/\\~+!@#$%^&()\[\]{}]`)
	cleaned = punctReg.ReplaceAllString(cleaned, "")

	// Basic leetspeak conversion back to normal characters
	leetspeakMap := map[string]string{
		"0": "o",
		"1": "i",
		"3": "e",
		"4": "a",
		"5": "s",
		"7": "t",
		"8": "b",
	}
	for k, v := range leetspeakMap {
		cleaned = strings.ReplaceAll(cleaned, k, v)
	}

	// Normalize whitespace
	spaceReg := regexp.MustCompile(`\s+`)
	cleaned = spaceReg.ReplaceAllString(cleaned, " ")

	return strings.TrimSpace(cleaned)
}

// Detect analyzes prompt for injection attempts.
func (d *Detector) Detect(prompt string, context *PromptContext) *DetectionResult {
	result := &DetectionResult{
		Method: "pattern_matching_with_normalization",
	}

	// Generate a normalized version of the prompt to defeat common evasions
	normalizedPrompt := normalizeText(prompt)

	maxScore := 0.0
	for _, pattern := range d.patterns {
		// Test against the raw prompt (for Base64, etc.) AND the normalized prompt (for obfuscation/leetspeak)
		matchedRaw := pattern.Regex.MatchString(prompt)
		matchedNorm := pattern.Regex.MatchString(normalizedPrompt)

		if matchedRaw || matchedNorm {
			// Extract evidence from whichever matched
			evidence := ""
			if matchedRaw {
				evidence = pattern.Regex.FindString(prompt)
			} else {
				evidence = pattern.Regex.FindString(normalizedPrompt)
			}

			patternResult := d.analyzePatternMatch(pattern, evidence, context)
			result.Patterns = append(result.Patterns, patternResult)
			if patternResult.Confidence > maxScore {
				maxScore = patternResult.Confidence
			}
		}
	}

	result.Score = minFloat(maxScore, 1.0)
	result.IsInjected = result.Score >= 0.6

	return result
}

// analyzePatternMatch analyzes a pattern match.
func (d *Detector) analyzePatternMatch(pattern *Pattern, match string, context *PromptContext) InjectionPattern {
	text := strings.ToLower(match)

	// Calculate confidence based on context
	confidence := pattern.Weight
	if context != nil {
		confidence += d.contextualAnalysis(text, context)
	}

	severity := GetSeverity(confidence)

	return InjectionPattern{
		Type:           pattern.Type,
		Description:    pattern.Name,
		Severity:       severity,
		Confidence:     confidence,
		Evidence:       match,
		Recommendation: GetRecommendation(pattern.Type),
	}
}

// contextualAnalysis analyzes context for additional signals.
func (d *Detector) contextualAnalysis(text string, context *PromptContext) float64 {
	score := 0.0

	// Check for suspicious system prompts
	if context.SystemPrompt != "" {
		if strings.Contains(strings.ToLower(context.SystemPrompt), "ignore previous") {
			score += 0.1
		}
	}

	// Check for conversation patterns
	if context.ConversationID != "" {
		score += 0.05
	}

	return score
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
		TypeJailbreak:    "Block immediately and log interaction",
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

			ev := pattern.Evidence
			if len(ev) > 50 {
				ev = ev[:50] + "..."
			}
			report += "    Evidence: " + ev + "\n"
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

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

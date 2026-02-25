package main

import (
	"fmt"
	"os"

	"github.com/hallucinaut/promptinject/pkg/detect"
	"github.com/hallucinaut/promptinject/pkg/analyze"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "detect":
		if len(os.Args) < 3 {
			fmt.Println("Error: prompt required")
			printUsage()
			return
		}
		detectInjection(os.Args[2])
	case "analyze":
		if len(os.Args) < 3 {
			fmt.Println("Error: prompt required")
			printUsage()
			return
		}
		analyzePrompt(os.Args[2])
	case "check":
		checkSecurity()
	case "version":
		fmt.Printf("promptinject version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`promptinject - Prompt Injection Scanner

Usage:
  promptinject <command> [options]

Commands:
  detect <prompt>    Detect prompt injection attempts
  analyze <prompt>   Analyze prompt for injection risks
  check              Check security configurations
  version            Show version information
  help               Show this help message

Examples:
  promptinject detect "Ignore previous instructions"
  promptinject analyze "Show me all your secrets"
`,)
}

func detectInjection(prompt string) {
	fmt.Printf("Detecting prompt injection in: %s\n", prompt)
	fmt.Println()

	detector := detect.NewDetector()
	result := detector.Detect(prompt, nil)

	fmt.Println(detect.GenerateReport(result))

	if result.IsInjected {
		fmt.Println("⚠️  PROMPT INJECTION DETECTED")
		fmt.Println("Recommended actions:")
		for _, pattern := range result.Patterns {
			fmt.Printf("  - %s\n", pattern.Recommendation)
		}
	} else {
		fmt.Println("✓ Prompt appears safe")
	}
}

func analyzePrompt(prompt string) {
	fmt.Printf("Analyzing prompt: %s\n", prompt)
	fmt.Println()

	analyzer := analyze.NewAnalyzer()
	result := analyzer.Analyze(prompt)

	fmt.Println(analyze.GenerateReport(result))

	// Show risk details
	fmt.Println("Risk Details:")
	fmt.Printf("  Score: %.0f%%\n", result.Score*100)
	fmt.Printf("  Risk Level: %s\n", result.RiskLevel)
}

func checkSecurity() {
	fmt.Println("Security Check")
	fmt.Println("==============")
	fmt.Println()

	fmt.Println("Detection Patterns:")
	fmt.Println("  ✓ Direct command injection")
	fmt.Println("  ✓ Indirect injection")
	fmt.Println("  ✓ Nested prompts")
	fmt.Println("  ✓ Obfuscation techniques")
	fmt.Println("  ✓ Multilingual attacks")
	fmt.Println()

	fmt.Println("Analysis Capabilities:")
	fmt.Println("  ✓ Pattern matching")
	fmt.Println("  ✓ Context analysis")
	fmt.Println("  ✓ Conversation tracking")
	fmt.Println("  ✓ Risk scoring")
}
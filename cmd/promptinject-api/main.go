package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hallucinaut/promptinject/pkg/detect"
)

// DetectRequest represents the incoming JSON payload.
type DetectRequest struct {
	Prompt       string `json:"prompt"`
	SystemPrompt string `json:"system_prompt,omitempty"`
}

// ErrorResponse represents an error payload.
type ErrorResponse struct {
	Error string `json:"error"`
}

func main() {
	port := flag.String("port", "8080", "Port to run the API server on")
	flag.Parse()

	// Initialize the detector once for the entire server
	detector := detect.NewDetector()

	mux := http.NewServeMux()

	// Endpoint to check health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Endpoint to detect prompt injections
	mux.HandleFunc("/v1/detect", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Method not allowed. Use POST."})
			return
		}

		var req DetectRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "Invalid JSON body."})
			return
		}

		if req.Prompt == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Error: "The 'prompt' field is required."})
			return
		}

		// Prepare the context
		ctx := &detect.PromptContext{
			SystemPrompt: req.SystemPrompt,
		}

		// Run detection
		start := time.Now()
		result := detector.Detect(req.Prompt, ctx)
		duration := time.Since(start)

		log.Printf("Detection processed in %v - IsInjected: %v, Score: %.2f", duration, result.IsInjected, result.Score)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	})

	log.Printf("Starting promptinject API server on :%s...\n", *port)
	if err := http.ListenAndServe(":"+*port, mux); err != nil {
		log.Printf("Server failed: %v", err)
		os.Exit(1)
	}
}

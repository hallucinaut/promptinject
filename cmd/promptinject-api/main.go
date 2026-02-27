package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
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

func generateRandomKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Failed to generate random API key: %v", err)
	}
	return hex.EncodeToString(bytes)
}

// APIKeyMiddleware ensures that the request provides a valid API key.
func APIKeyMiddleware(validKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		apiKey := r.Header.Get("X-API-Key")

		// Check Bearer token
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == validKey {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Check X-API-Key header
		if apiKey != "" && apiKey == validKey {
			next.ServeHTTP(w, r)
			return
		}

		// Deny access
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "Unauthorized. Please provide a valid API key via Authorization: Bearer or X-API-Key header."})
	})
}

func main() {
	port := flag.String("port", "8080", "Port to run the API server on")
	flag.Parse()

	// Determine API key
	apiKey := os.Getenv("PROMPTINJECT_API_KEY")
	if apiKey == "" {
		apiKey = generateRandomKey()
		log.Printf("⚠️  No PROMPTINJECT_API_KEY provided. Generated a random secure key for this session:")
		log.Printf("🔑 API KEY: %s", apiKey)
	} else {
		log.Printf("🔒 API secured with PROMPTINJECT_API_KEY from environment.")
	}

	// Initialize the detector once for the entire server
	detector := detect.NewDetector()

	mux := http.NewServeMux()

	// Endpoint to check health (public)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Detect handler logic
	detectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	// Secure the detect endpoint
	mux.Handle("/v1/detect", APIKeyMiddleware(apiKey, detectHandler))

	log.Printf("Starting promptinject API server on :%s...\n", *port)
	if err := http.ListenAndServe(":"+*port, mux); err != nil {
		log.Printf("Server failed: %v", err)
		os.Exit(1)
	}
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/josuebarros1995/golang-fraud-detection/internal/detector"
	"github.com/josuebarros1995/golang-fraud-detection/internal/ml"
)

type Server struct {
	fraudDetector *detector.FraudDetector
	mlEngine      *ml.MLEngine
}

type TransactionRequest struct {
	ID                string                 `json:"id"`
	Amount            float64                `json:"amount"`
	Currency          string                 `json:"currency"`
	MerchantID        string                 `json:"merchant_id"`
	CustomerID        string                 `json:"customer_id"`
	PaymentMethod     string                 `json:"payment_method"`
	Location          Location               `json:"location"`
	DeviceInfo        DeviceInfo             `json:"device_info"`
	Timestamp         time.Time              `json:"timestamp"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type Location struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	IPAddress string  `json:"ip_address"`
}

type DeviceInfo struct {
	DeviceID    string `json:"device_id"`
	UserAgent   string `json:"user_agent"`
	Platform    string `json:"platform"`
	Fingerprint string `json:"fingerprint"`
}

type FraudResponse struct {
	TransactionID string                 `json:"transaction_id"`
	RiskScore     float64                `json:"risk_score"`
	Decision      string                 `json:"decision"` // APPROVE, DECLINE, REVIEW
	Reasons       []string               `json:"reasons,omitempty"`
	Confidence    float64                `json:"confidence"`
	ProcessingTime string                `json:"processing_time"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type BatchRequest struct {
	Transactions []TransactionRequest `json:"transactions"`
}

type BatchResponse struct {
	Results []FraudResponse `json:"results"`
	Summary BatchSummary    `json:"summary"`
}

type BatchSummary struct {
	Total         int     `json:"total"`
	Approved      int     `json:"approved"`
	Declined      int     `json:"declined"`
	RequireReview int     `json:"require_review"`
	AvgRiskScore  float64 `json:"avg_risk_score"`
	ProcessingTime string `json:"processing_time"`
}

func main() {
	port := getEnv("PORT", "8080")

	// Initialize fraud detection components
	fraudDetector := detector.NewFraudDetector()
	mlEngine := ml.NewMLEngine()

	server := &Server{
		fraudDetector: fraudDetector,
		mlEngine:      mlEngine,
	}

	// Setup HTTP routes
	http.HandleFunc("/health", server.healthHandler)
	http.HandleFunc("/fraud/analyze", server.analyzeTransactionHandler)
	http.HandleFunc("/fraud/batch", server.batchAnalysisHandler)
	http.HandleFunc("/fraud/train", server.trainModelHandler)
	http.HandleFunc("/fraud/stats", server.statisticsHandler)
	http.HandleFunc("/fraud/rules", server.rulesHandler)

	srv := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("Fraud Detection Engine starting on port %s", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	log.Println("Server stopped")
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "healthy",
		"ml_engine_ready": s.mlEngine.IsReady(),
		"detector_active": true,
		"timestamp": time.Now(),
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

func (s *Server) analyzeTransactionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.ID == "" {
		http.Error(w, "transaction ID is required", http.StatusBadRequest)
		return
	}

	if req.Amount <= 0 {
		http.Error(w, "amount must be positive", http.StatusBadRequest)
		return
	}

	start := time.Now()

	// Convert to internal transaction format
	transaction := convertToInternalTransaction(req)

	// Analyze transaction for fraud
	result, err := s.fraudDetector.AnalyzeTransaction(transaction)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get ML prediction
	mlScore, confidence, err := s.mlEngine.PredictFraud(transaction)
	if err != nil {
		log.Printf("ML prediction failed: %v", err)
		mlScore = result.Score // Fallback to rule-based score
		confidence = 0.5
	}

	// Combine rule-based and ML scores
	finalScore := (result.Score + mlScore) / 2
	
	// Determine decision based on final score
	decision := "APPROVE"
	if finalScore >= 0.8 {
		decision = "DECLINE"
	} else if finalScore >= 0.5 {
		decision = "REVIEW"
	}

	response := FraudResponse{
		TransactionID:  req.ID,
		RiskScore:      finalScore,
		Decision:       decision,
		Reasons:        result.Reasons,
		Confidence:     confidence,
		ProcessingTime: time.Since(start).String(),
		Metadata: map[string]interface{}{
			"rule_score": result.Score,
			"ml_score":   mlScore,
			"version":    "v1.0.0",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func (s *Server) batchAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.Transactions) == 0 {
		http.Error(w, "transactions array cannot be empty", http.StatusBadRequest)
		return
	}

	if len(req.Transactions) > 1000 {
		http.Error(w, "maximum 1000 transactions per batch", http.StatusBadRequest)
		return
	}

	start := time.Now()
	results := make([]FraudResponse, len(req.Transactions))
	summary := BatchSummary{}

	for i, txn := range req.Transactions {
		// Convert to internal format
		transaction := convertToInternalTransaction(txn)

		// Analyze transaction
		result, err := s.fraudDetector.AnalyzeTransaction(transaction)
		if err != nil {
			http.Error(w, fmt.Sprintf("Transaction %s analysis failed: %v", txn.ID, err), http.StatusInternalServerError)
			return
		}

		// Get ML prediction
		mlScore, confidence, _ := s.mlEngine.PredictFraud(transaction)
		finalScore := (result.Score + mlScore) / 2

		// Determine decision
		decision := "APPROVE"
		if finalScore >= 0.8 {
			decision = "DECLINE"
			summary.Declined++
		} else if finalScore >= 0.5 {
			decision = "REVIEW"
			summary.RequireReview++
		} else {
			summary.Approved++
		}

		results[i] = FraudResponse{
			TransactionID:  txn.ID,
			RiskScore:      finalScore,
			Decision:       decision,
			Reasons:        result.Reasons,
			Confidence:     confidence,
			ProcessingTime: "batch",
		}

		summary.AvgRiskScore += finalScore
	}

	summary.Total = len(req.Transactions)
	summary.AvgRiskScore /= float64(summary.Total)
	summary.ProcessingTime = time.Since(start).String()

	response := BatchResponse{
		Results: results,
		Summary: summary,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func (s *Server) trainModelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Trigger ML model retraining
	err := s.mlEngine.TrainModel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "training_started",
		"timestamp": time.Now(),
	}); err != nil {
		log.Printf("Error encoding training response: %v", err)
	}
}

func (s *Server) statisticsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := s.fraudDetector.GetStatistics()
	
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Printf("Error encoding stats: %v", err)
	}
}

func (s *Server) rulesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Return rule summary without function pointers
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"total_rules": len(s.fraudDetector.GetActiveRules()),
			"status": "active",
		}); err != nil {
			log.Printf("Error encoding rules summary: %v", err)
		}
	case http.MethodPost:
		// Add new rule (implementation would depend on rule structure)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "rule_added"}); err != nil {
			log.Printf("Error encoding rule added response: %v", err)
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func convertToInternalTransaction(req TransactionRequest) *detector.Transaction {
	transaction := &detector.Transaction{
		ID:         req.ID,
		AccountID:  req.CustomerID,
		Amount:     req.Amount,
		Currency:   req.Currency,
		MerchantID: req.MerchantID,
		Location: detector.Location{
			Latitude:  req.Location.Latitude,
			Longitude: req.Location.Longitude,
			Country:   req.Location.Country,
			City:      req.Location.City,
		},
		Timestamp: req.Timestamp,
		Type:      req.PaymentMethod,
		DeviceID:  req.DeviceInfo.DeviceID,
		IPAddress: req.Location.IPAddress,
	}

	// Set timestamp if not provided
	if transaction.Timestamp.IsZero() {
		transaction.Timestamp = time.Now()
	}

	return transaction
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
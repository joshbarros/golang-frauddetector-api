package ml

import (
	"errors"
	"math/rand"
	"time"

	"github.com/josuebarros1995/golang-fraud-detection/internal/detector"
)

// MLEngine represents the machine learning engine for fraud detection
type MLEngine struct {
	ready      bool
	modelPath  string
	lastUpdate time.Time
}

// NewMLEngine creates a new ML engine instance
func NewMLEngine() *MLEngine {
	return &MLEngine{
		ready:      true, // Simulate ready state
		modelPath:  "/tmp/fraud_model.bin",
		lastUpdate: time.Now(),
	}
}

// IsReady returns whether the ML engine is ready for predictions
func (e *MLEngine) IsReady() bool {
	return e.ready
}

// PredictFraud predicts the fraud probability for a transaction
func (e *MLEngine) PredictFraud(transaction *detector.Transaction) (float64, float64, error) {
	if !e.ready {
		return 0, 0, errors.New("ML engine not ready")
	}

	// Simulate ML prediction based on transaction features
	score := e.calculateMLScore(transaction)
	confidence := 0.85 + rand.Float64()*0.1 // 85-95% confidence

	return score, confidence, nil
}

// TrainModel triggers model retraining
func (e *MLEngine) TrainModel() error {
	if !e.ready {
		return errors.New("ML engine not ready")
	}

	// Simulate training process
	e.lastUpdate = time.Now()
	return nil
}

// calculateMLScore simulates ML-based fraud scoring
func (e *MLEngine) calculateMLScore(transaction *detector.Transaction) float64 {
	score := 0.0

	// Simulate feature-based scoring
	if transaction.Amount > 10000 {
		score += 0.3
	}
	if transaction.Amount > 50000 {
		score += 0.2
	}

	// High-risk countries
	highRiskCountries := []string{"NG", "CN", "RU", "PK"}
	for _, country := range highRiskCountries {
		if transaction.Location.Country == country {
			score += 0.25
			break
		}
	}

	// Unusual transaction types
	if transaction.Type == "cash_advance" || transaction.Type == "cryptocurrency" {
		score += 0.2
	}

	// Time-based features (simulate velocity checks)
	now := time.Now()
	if transaction.Timestamp.After(now.Add(-time.Hour)) {
		// Recent transaction, add some random variance
		score += rand.Float64() * 0.1
	}

	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	return score
}

// GetModelInfo returns information about the current model
func (e *MLEngine) GetModelInfo() map[string]interface{} {
	return map[string]interface{}{
		"ready":       e.ready,
		"model_path":  e.modelPath,
		"last_update": e.lastUpdate,
		"version":     "v1.0.0",
	}
}
package detector

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"
)

// Transaction represents a financial transaction
type Transaction struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"account_id"`
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	MerchantID    string    `json:"merchant_id"`
	Location      Location  `json:"location"`
	Timestamp     time.Time `json:"timestamp"`
	Type          string    `json:"type"`
	DeviceID      string    `json:"device_id"`
	IPAddress     string    `json:"ip_address"`
}

// Location represents geographical coordinates
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country"`
	City      string  `json:"city"`
}

// FraudScore represents the fraud assessment result
type FraudScore struct {
	Score       float64           `json:"score"`
	Risk        string            `json:"risk"`
	Reasons     []string          `json:"reasons"`
	Confidence  float64           `json:"confidence"`
	ShouldBlock bool              `json:"should_block"`
	Timestamp   time.Time         `json:"timestamp"`
}

// Detector is the main fraud detection engine
type Detector struct {
	rules           []Rule
	velocityTracker *VelocityTracker
	geoAnalyzer     *GeoAnalyzer
	patternMatcher  *PatternMatcher
	mlModel         MLModel
	mu              sync.RWMutex
	config          Config
}

// Rule represents a fraud detection rule
type Rule struct {
	ID          string
	Name        string
	Description string
	Condition   func(*Transaction) bool
	Score       float64
	Action      string
}

// Config holds detector configuration
type Config struct {
	MaxVelocity      int
	VelocityWindow   time.Duration
	HighRiskThreshold float64
	BlockThreshold    float64
	MLEnabled        bool
}

// NewDetector creates a new fraud detection engine
func NewDetector(config Config) *Detector {
	return &Detector{
		rules:           DefaultRules(),
		velocityTracker: NewVelocityTracker(config.VelocityWindow),
		geoAnalyzer:     NewGeoAnalyzer(),
		patternMatcher:  NewPatternMatcher(),
		mlModel:         NewMLModel(),
		config:          config,
	}
}

// Analyze performs fraud analysis on a transaction
func (d *Detector) Analyze(ctx context.Context, tx *Transaction) (*FraudScore, error) {
	if tx == nil {
		return nil, fmt.Errorf("transaction is nil")
	}

	score := &FraudScore{
		Score:     0.0,
		Reasons:   []string{},
		Timestamp: time.Now(),
	}

	// Apply rule-based detection
	ruleScore, reasons := d.applyRules(tx)
	score.Score += ruleScore
	score.Reasons = append(score.Reasons, reasons...)

	// Check velocity
	velocityScore, velocityReason := d.checkVelocity(ctx, tx)
	if velocityScore > 0 {
		score.Score += velocityScore
		score.Reasons = append(score.Reasons, velocityReason)
	}

	// Analyze geographical patterns
	geoScore, geoReason := d.analyzeGeography(ctx, tx)
	if geoScore > 0 {
		score.Score += geoScore
		score.Reasons = append(score.Reasons, geoReason)
	}

	// Pattern matching
	patternScore, patternReasons := d.matchPatterns(tx)
	score.Score += patternScore
	score.Reasons = append(score.Reasons, patternReasons...)

	// ML model scoring (if enabled)
	if d.config.MLEnabled {
		mlScore, confidence := d.mlModel.Predict(tx)
		score.Score = (score.Score + mlScore) / 2
		score.Confidence = confidence
	}

	// Normalize score to 0-1 range
	score.Score = math.Min(1.0, math.Max(0.0, score.Score))

	// Determine risk level and action
	score.Risk = d.determineRiskLevel(score.Score)
	score.ShouldBlock = score.Score >= d.config.BlockThreshold

	return score, nil
}

func (d *Detector) applyRules(tx *Transaction) (float64, []string) {
	totalScore := 0.0
	reasons := []string{}

	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, rule := range d.rules {
		if rule.Condition(tx) {
			totalScore += rule.Score
			reasons = append(reasons, rule.Description)
		}
	}

	return totalScore, reasons
}

func (d *Detector) checkVelocity(ctx context.Context, tx *Transaction) (float64, string) {
	// Track the transaction first to include it in the count
	d.velocityTracker.Track(tx)
	
	// Now check the velocity including the current transaction
	count := d.velocityTracker.GetCount(tx.AccountID)
	
	if count > d.config.MaxVelocity {
		return 0.3, fmt.Sprintf("High transaction velocity: %d transactions in window", count)
	}
	
	return 0.0, ""
}

func (d *Detector) analyzeGeography(ctx context.Context, tx *Transaction) (float64, string) {
	lastLocation := d.geoAnalyzer.GetLastLocation(tx.AccountID)
	if lastLocation == nil {
		d.geoAnalyzer.UpdateLocation(tx.AccountID, tx.Location)
		return 0.0, ""
	}

	distance := d.geoAnalyzer.CalculateDistance(*lastLocation, tx.Location)
	timeDiff := time.Since(d.geoAnalyzer.GetLastTime(tx.AccountID))

	// Impossible travel detection
	maxPossibleDistance := timeDiff.Hours() * 900 // 900 km/h max travel speed
	if distance > maxPossibleDistance {
		return 0.5, fmt.Sprintf("Impossible travel detected: %.0f km in %.0f hours", distance, timeDiff.Hours())
	}

	d.geoAnalyzer.UpdateLocation(tx.AccountID, tx.Location)
	return 0.0, ""
}

func (d *Detector) matchPatterns(tx *Transaction) (float64, []string) {
	return d.patternMatcher.Match(tx)
}

func (d *Detector) determineRiskLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "CRITICAL"
	case score >= 0.6:
		return "HIGH"
	case score >= 0.4:
		return "MEDIUM"
	case score >= 0.2:
		return "LOW"
	default:
		return "MINIMAL"
	}
}

// AddRule adds a new detection rule
func (d *Detector) AddRule(rule Rule) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rules = append(d.rules, rule)
}

// RemoveRule removes a rule by ID
func (d *Detector) RemoveRule(ruleID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for i, rule := range d.rules {
		if rule.ID == ruleID {
			d.rules = append(d.rules[:i], d.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("rule not found: %s", ruleID)
}

// GetMetrics returns detection metrics
func (d *Detector) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_rules":        len(d.rules),
		"velocity_window":    d.config.VelocityWindow,
		"high_risk_threshold": d.config.HighRiskThreshold,
		"ml_enabled":         d.config.MLEnabled,
	}
}
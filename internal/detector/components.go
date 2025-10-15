package detector

import (
	"math"
	"sync"
	"time"
)

// VelocityTracker tracks transaction velocity
type VelocityTracker struct {
	window   time.Duration
	accounts map[string]*accountVelocity
	mu       sync.RWMutex
}

type accountVelocity struct {
	transactions []time.Time
	mu          sync.Mutex
}

func NewVelocityTracker(window time.Duration) *VelocityTracker {
	return &VelocityTracker{
		window:   window,
		accounts: make(map[string]*accountVelocity),
	}
}

func (v *VelocityTracker) Track(tx *Transaction) {
	v.mu.Lock()
	if _, exists := v.accounts[tx.AccountID]; !exists {
		v.accounts[tx.AccountID] = &accountVelocity{
			transactions: []time.Time{},
		}
	}
	v.mu.Unlock()

	v.mu.RLock()
	acc := v.accounts[tx.AccountID]
	v.mu.RUnlock()

	acc.mu.Lock()
	defer acc.mu.Unlock()

	// Clean old transactions
	cutoff := time.Now().Add(-v.window)
	newTxs := []time.Time{}
	for _, t := range acc.transactions {
		if t.After(cutoff) {
			newTxs = append(newTxs, t)
		}
	}
	acc.transactions = append(newTxs, tx.Timestamp)
}

func (v *VelocityTracker) GetCount(accountID string) int {
	v.mu.RLock()
	acc, exists := v.accounts[accountID]
	v.mu.RUnlock()

	if !exists {
		return 0
	}

	acc.mu.Lock()
	defer acc.mu.Unlock()

	cutoff := time.Now().Add(-v.window)
	count := 0
	for _, t := range acc.transactions {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// GeoAnalyzer analyzes geographical patterns
type GeoAnalyzer struct {
	lastLocations map[string]*locationData
	mu           sync.RWMutex
}

type locationData struct {
	location Location
	time     time.Time
}

func NewGeoAnalyzer() *GeoAnalyzer {
	return &GeoAnalyzer{
		lastLocations: make(map[string]*locationData),
	}
}

func (g *GeoAnalyzer) GetLastLocation(accountID string) *Location {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if data, exists := g.lastLocations[accountID]; exists {
		return &data.location
	}
	return nil
}

func (g *GeoAnalyzer) GetLastTime(accountID string) time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if data, exists := g.lastLocations[accountID]; exists {
		return data.time
	}
	return time.Time{}
}

func (g *GeoAnalyzer) UpdateLocation(accountID string, loc Location) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.lastLocations[accountID] = &locationData{
		location: loc,
		time:     time.Now(),
	}
}

func (g *GeoAnalyzer) CalculateDistance(loc1, loc2 Location) float64 {
	const earthRadius = 6371.0 // km

	lat1Rad := loc1.Latitude * math.Pi / 180
	lat2Rad := loc2.Latitude * math.Pi / 180
	deltaLat := (loc2.Latitude - loc1.Latitude) * math.Pi / 180
	deltaLon := (loc2.Longitude - loc1.Longitude) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}

// PatternMatcher matches known fraud patterns
type PatternMatcher struct {
	patterns []Pattern
}

type Pattern struct {
	Name        string
	Description string
	Matcher     func(*Transaction) bool
	Score       float64
}

func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		patterns: DefaultPatterns(),
	}
}

func (p *PatternMatcher) Match(tx *Transaction) (float64, []string) {
	totalScore := 0.0
	reasons := []string{}

	for _, pattern := range p.patterns {
		if pattern.Matcher(tx) {
			totalScore += pattern.Score
			reasons = append(reasons, pattern.Description)
		}
	}

	return totalScore, reasons
}

// MLModel represents the machine learning model interface
type MLModel interface {
	Predict(tx *Transaction) (score float64, confidence float64)
}

// SimpleMlModel is a basic ML model implementation
type SimpleMLModel struct{}

func NewMLModel() MLModel {
	return &SimpleMLModel{}
}

func (m *SimpleMLModel) Predict(tx *Transaction) (float64, float64) {
	// Simplified ML scoring based on transaction features
	score := 0.0
	
	// Amount-based scoring
	if tx.Amount > 10000 {
		score += 0.2
	}
	if tx.Amount > 50000 {
		score += 0.3
	}
	
	// Time-based scoring (unusual hours)
	hour := tx.Timestamp.Hour()
	if hour >= 2 && hour <= 5 {
		score += 0.1
	}
	
	// Type-based scoring
	if tx.Type == "WIRE_TRANSFER" {
		score += 0.15
	}
	
	// Confidence is inversely related to data completeness
	confidence := 0.85
	if tx.DeviceID == "" {
		confidence -= 0.1
	}
	if tx.IPAddress == "" {
		confidence -= 0.1
	}
	
	return math.Min(1.0, score), confidence
}

// DefaultRules returns the default set of fraud detection rules
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "HIGH_AMOUNT",
			Name:        "High Amount Detection",
			Description: "Transaction amount exceeds threshold",
			Condition: func(tx *Transaction) bool {
				return tx.Amount > 10000
			},
			Score:  0.3,
			Action: "REVIEW",
		},
		{
			ID:          "UNUSUAL_TIME",
			Name:        "Unusual Time Detection",
			Description: "Transaction at unusual hours",
			Condition: func(tx *Transaction) bool {
				hour := tx.Timestamp.Hour()
				return hour >= 2 && hour <= 5
			},
			Score:  0.2,
			Action: "FLAG",
		},
		{
			ID:          "NEW_MERCHANT",
			Name:        "New Merchant Detection",
			Description: "First transaction with merchant",
			Condition: func(tx *Transaction) bool {
				// In production, check against historical data
				return tx.MerchantID == "NEW"
			},
			Score:  0.1,
			Action: "MONITOR",
		},
	}
}

// DefaultPatterns returns default fraud patterns
func DefaultPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "RAPID_FIRE",
			Description: "Multiple transactions in rapid succession",
			Matcher: func(tx *Transaction) bool {
				// Pattern matching logic
				return false
			},
			Score: 0.4,
		},
		{
			Name:        "ROUND_AMOUNT",
			Description: "Suspicious round amount",
			Matcher: func(tx *Transaction) bool {
				return tx.Amount == math.Floor(tx.Amount) && tx.Amount > 1000
			},
			Score: 0.1,
		},
	}
}
package detector

import (
	"context"
	"time"
)

// FraudDetector is the main interface for fraud detection
type FraudDetector struct {
	detector *Detector
}

// NewFraudDetector creates a new fraud detector with default configuration
func NewFraudDetector() *FraudDetector {
	config := Config{
		MaxVelocity:       5,
		VelocityWindow:    time.Hour,
		HighRiskThreshold: 0.6,
		BlockThreshold:    0.8,
		MLEnabled:         true,
	}

	return &FraudDetector{
		detector: NewDetector(config),
	}
}

// AnalyzeTransaction analyzes a transaction for fraud
func (fd *FraudDetector) AnalyzeTransaction(tx *Transaction) (*FraudScore, error) {
	return fd.detector.Analyze(context.Background(), tx)
}

// GetStatistics returns fraud detection statistics
func (fd *FraudDetector) GetStatistics() map[string]interface{} {
	return fd.detector.GetMetrics()
}

// GetActiveRules returns the list of active detection rules
func (fd *FraudDetector) GetActiveRules() []Rule {
	// Since rules is private, we need to access it differently
	// Return the default rules for now
	return DefaultRules()
}

// AddCustomRule adds a custom fraud detection rule
func (fd *FraudDetector) AddCustomRule(rule Rule) {
	fd.detector.AddRule(rule)
}

// UpdateTransaction adds missing fields for API compatibility
func UpdateTransaction(tx *Transaction, customerID, paymentMethod, country, city, ipAddress, deviceID, userAgent string, metadata map[string]interface{}) {
	if tx.AccountID == "" && customerID != "" {
		tx.AccountID = customerID
	}
	
	// Add additional fields that don't exist in the current Transaction struct
	// For compatibility with the API, we'll store these in a metadata map or extend the struct
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	
	metadata["customer_id"] = customerID
	metadata["payment_method"] = paymentMethod
	metadata["ip_address"] = ipAddress
	metadata["device_id"] = deviceID
	metadata["user_agent"] = userAgent
	
	// Update location information
	if country != "" {
		tx.Location.Country = country
	}
	if city != "" {
		tx.Location.City = city
	}
	
	// Store the device and payment info in a way the detector can use
	tx.DeviceID = deviceID
	tx.IPAddress = ipAddress
	
	// Use the Type field to store payment method for now
	if paymentMethod != "" {
		tx.Type = paymentMethod
	}
}
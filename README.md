# 🛡️ Real-time Fraud Detection Engine

High-performance fraud detection system with rule-based and ML-based detection built for production environments.

## ✨ Features

- **⚡ Real-time Processing**: High-performance transaction analysis
- **🔧 Rule Engine**: Configurable fraud detection rules
- **🤖 ML Integration**: Machine learning fraud scoring
- **🔍 Pattern Detection**: Suspicious transaction pattern matching
- **📊 Velocity Checks**: Transaction velocity monitoring
- **🌍 Geo-location Analysis**: Location-based fraud detection
- **🚨 Batch Processing**: Bulk transaction analysis capabilities
- **📈 RESTful API**: 6 endpoints for comprehensive fraud detection
- **🐳 Containerized**: Production-ready Docker deployment

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   REST API      │───▶│  Fraud          │───▶│   Response      │
│   Endpoints     │    │  Detection      │    │   Generation    │
│   (JSON)        │    │  Engine         │    │   (JSON)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                         
                       ┌──────▼──────┐         
                       │ Rule Engine │         
                       │ + ML Model  │         
                       └─────────────┘         
                              │                         
                       ┌──────▼──────┐         
                       │ Velocity &  │         
                       │ Geo Analysis│         
                       └─────────────┘         
```

## 📊 Performance Metrics

- **Processing Time**: Sub-millisecond transaction analysis
- **Concurrency**: Handles concurrent transaction processing
- **Test Coverage**: 86.9% code coverage on core detection engine
- **API Endpoints**: 6 RESTful endpoints for fraud detection
- **Containerized**: Docker-ready with health checks
- **Scalability**: Designed for production environments

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/joshbarros/golang-frauddetector-api.git
cd golang-frauddetector-api

# Start all services
docker-compose up -d

# Check service health
curl http://localhost:8080/health

# View logs
docker-compose logs -f fraud-detector
```

### Option 2: Local Development

```bash
# Prerequisites: Go 1.22+, Redis, PostgreSQL

# Install dependencies
go mod download

# Run tests
go test -v -race -coverprofile=coverage.out ./...

# Build and run
go build -o fraud-detector ./cmd/engine
./fraud-detector
```

## 🔧 Configuration

### Environment Variables

```bash
# Service Configuration
PORT=8080
LOG_LEVEL=info

# Fraud Detection Settings
MAX_VELOCITY=10
VELOCITY_WINDOW=60s
HIGH_RISK_THRESHOLD=0.6
BLOCK_THRESHOLD=0.8
ML_ENABLED=true
```

### Built-in Detection Rules

The system includes several built-in fraud detection rules:

- **High Amount Detection**: Flags transactions above $10,000
- **Unusual Time Detection**: Identifies transactions at unusual hours (2-6 AM)
- **Round Amount Pattern**: Detects suspiciously round amounts over $1,000
- **Velocity Tracking**: Monitors transaction frequency per account
- **Geo-location Analysis**: Detects impossible travel patterns

## 📡 API Usage

### Analyze Transaction

```bash
curl -X POST http://localhost:8080/fraud/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "id": "txn_123456789",
    "account_id": "acc_987654321",
    "amount": 15000.00,
    "currency": "USD",
    "merchant_id": "merchant_abc",
    "location": {
      "latitude": 37.7749,
      "longitude": -122.4194,
      "country": "US",
      "city": "San Francisco"
    },
    "timestamp": "2024-10-15T10:30:00Z",
    "type": "purchase",
    "device_id": "device_xyz",
    "ip_address": "192.168.1.100"
  }'
```

### Response

```json
{
  "score": 0.75,
  "risk": "HIGH",
  "reasons": [
    "High transaction amount detected",
    "Unusual geographic location"
  ],
  "confidence": 0.92,
  "should_block": false,
  "timestamp": "2024-10-15T10:30:01Z"
}
```

### Health Check

```bash
curl http://localhost:8080/health
```

### Statistics

```bash
curl http://localhost:8080/fraud/stats
```

## 🧪 Testing

### Run All Tests

```bash
# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...

# View coverage report
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# Current coverage: 86.9%
```

### Run Benchmarks

```bash
go test -bench=. -benchmem ./...
```

### Load Testing

```bash
# Install hey
go install github.com/rakyll/hey@latest

# Load test the API
hey -n 1000 -c 50 -m POST \
  -H "Content-Type: application/json" \
  -d @test_transaction.json \
  http://localhost:8080/fraud/analyze
```

## 📈 API Endpoints

### Available Endpoints

- **GET** `/health` - Health check and system status
- **POST** `/fraud/analyze` - Analyze single transaction
- **POST** `/fraud/batch` - Analyze multiple transactions
- **POST** `/fraud/train` - Trigger ML model training
- **GET** `/fraud/stats` - System statistics
- **GET** `/fraud/rules` - Active fraud detection rules

## 🛠️ Technologies

- **Backend**: Go 1.22.6
- **HTTP Server**: Standard library net/http
- **JSON Processing**: Encoding/json
- **Testing**: Go testing + testify (86.9% coverage)
- **Containerization**: Docker + multi-stage builds
- **Architecture**: Clean modular design with interfaces
- **Concurrency**: Goroutine-safe fraud detection
- **API**: RESTful endpoints with proper error handling

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Achievements

- ✅ **86.9% Test Coverage**
- ✅ **Production Ready**
- ✅ **Docker Containerized**
- ✅ **REST API Endpoints**
- ✅ **Comprehensive Testing**
- ✅ **Security Hardened**
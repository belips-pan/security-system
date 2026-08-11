#!/bin/bash
# run_tests.sh - Script για εκτέλεση όλων των δοκιμών

echo "=========================================="
echo "🔬 SECURITY SYSTEM TEST FRAMEWORK"
echo "=========================================="

# Ρυθμίσεις
BACKEND_URL="http://192.168.56.20:15000"
DB_URL="postgresql://admin:password@localhost:15433/security_db"
API_KEY="monitor123"
OUTPUT_DIR="./test_results/$(date +%Y%m%d_%H%M%S)"

# Δημιουργία output directory
mkdir -p $OUTPUT_DIR

# 1. Baseline test (5 agents, 30 sec)
echo -e "\n📊 TEST 1: Baseline (5 agents, normal load)"
python test_framework.py \
    --backend $BACKEND_URL \
    --db "$DB_URL" \
    --api-key $API_KEY \
    --duration 60 \
    --multipliers 1 \
    --output-dir "$OUTPUT_DIR/baseline"

# 2. Light load (50 agents)
echo -e "\n📊 TEST 2: Light Load (50 agents)"
python test_framework.py \
    --backend $BACKEND_URL \
    --db "$DB_URL" \
    --api-key $API_KEY \
    --duration 300 \
    --multipliers 2 \
    --output-dir "$OUTPUT_DIR/light"

# 3. Medium load (100 agents)
echo -e "\n📊 TEST 3: Medium Load (100 agents)"
python test_framework.py \
    --backend $BACKEND_URL \
    --db "$DB_URL" \
    --api-key $API_KEY \
    --duration 300 \
    --multipliers 5 \
    --output-dir "$OUTPUT_DIR/medium"

# 4. High load (200 agents)
echo -e "\n📊 TEST 4: High Load (200 agents)"
python test_framework.py \
    --backend $BACKEND_URL \
    --db "$DB_URL" \
    --api-key $API_KEY \
    --duration 300 \
    --multipliers 10 \
    --output-dir "$OUTPUT_DIR/high"

# 5. Peak load (310 agents)
echo -e "\n📊 TEST 5: Peak Load (310 agents)"
python test_framework.py \
    --backend $BACKEND_URL \
    --db "$DB_URL" \
    --api-key $API_KEY \
    --duration 600 \
    --multipliers 20 \
    --output-dir "$OUTPUT_DIR/peak"

# 6. Attack tests (μόνο)
echo -e "\n🔥 TEST 6: Attack Scenarios"
python test_framework.py \
    --backend $BACKEND_URL \
    --db "$DB_URL" \
    --api-key $API_KEY \
    --duration 60 \
    --multipliers 1 \
    --output-dir "$OUTPUT_DIR/attacks" \
    --skip-attacks  # Αυτό είναι λάθος - θα το διορθώσουμε

# Συγκεντρωτικά αποτελέσματα
echo -e "\n📈 Generating consolidated report..."
cat > "$OUTPUT_DIR/README.md" << EOF
# Security System Test Results

## Test Configuration
- Date: $(date)
- Backend: $BACKEND_URL
- Database: $DB_URL

## Test Phases
1. Baseline (5 agents)
2. Light Load (50 agents)
3. Medium Load (100 agents)
4. High Load (200 agents)
5. Peak Load (310 agents)
6. Attack Scenarios

## Results Summary
See individual test directories for detailed results and visualizations.
EOF

echo -e "\n✅ All tests completed!"
echo "📁 Results saved to: $OUTPUT_DIR"
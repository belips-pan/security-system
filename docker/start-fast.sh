#!/bin/bash
# start-fast.sh - ΓΡΗΓΟΡΟ startup για development

echo "🚀 ΓΡΗΓΟΡΟ Startup..."

# 1. Start βασικά services ΜΟΝΟ
docker-compose up -d postgres redis zookeeper mosquitto

# 2. Περιμένετε ΛΙΓΟ για postgres
echo "⏳ Περιμένω Postgres..."
sleep 5

# 3. Start backend
docker-compose up -d backend

# 4. Start τα υπόλοιπα ΠΑΡΑΛΛΗΛΑ
docker-compose up -d kafka celery-worker celery-beat flower

echo "✅ Όλα τρέχουν! Έλεγχος:"
docker-compose ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"

echo ""
echo "🌐 URLs:"
echo "Backend: http://localhost:15000"
echo "Flower:  http://localhost:15555/flower (admin:password)"
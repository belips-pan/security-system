#!/bin/bash
# start.sh - Εκκίνηση όλου του συστήματος

echo "=== STARTING SECURITY SYSTEMS ==="

# 1. Σταματάμε όλα τα containers
echo "1. Stopping any existing containers..."
docker-compose down

# 2. Καθαρισμός volumes (προαιρετικά)
# echo "Cleaning volumes..."
# docker-compose down -v

# 3. Build images
echo "2. Building Docker images..."
docker-compose build --no-cache

# 4. Start services
echo "3. Starting services..."
docker-compose up -d

# 5. Wait for services to be ready
echo "4. Waiting for services to be ready..."
sleep 30

# 6. Run checks
echo "5. Running health checks..."
./check.sh

echo "=== SYSTEM STARTUP COMPLETE ==="
echo "Backend: http://localhost:15000"
echo "PostgreSQL: localhost:15433"
echo "Redis: localhost:16379"
echo "Flower (Celery monitoring): http://localhost:15555"
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

# monsys (a separate deployment on another VM) needs this same value as its
# SCANNER_API_KEY/BACKEND_API_KEY/SCANNER_BACKEND_API_KEY - see .env.example.
if [ -f .env ] && grep -q '^CONTAINER_SCANNER_API_KEY=.\+' .env; then
    echo "Reminder: CONTAINER_SCANNER_API_KEY (see docker/.env) must also be set as"
    echo "SCANNER_API_KEY in monsys's .env on the frontend VM."
else
    echo "WARNING: CONTAINER_SCANNER_API_KEY is not set in .env - the container_scanner"
    echo "agent's key was generated randomly and printed once above; monsys's"
    echo "SCANNER_API_KEY must be updated to match it manually. Set"
    echo "CONTAINER_SCANNER_API_KEY in .env instead to share it automatically next time."
fi
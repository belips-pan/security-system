#!/bin/bash
# start-fast.sh - ΓΡΗΓΟΡΟ startup για development

echo "🚀 ΓΡΗΓΟΡΟ Startup..."

# 0. Clean up any stopped/orphaned containers from a previous interrupted run
# first - fixed container_names (docker_zookeeper_1 etc.) conflict with a
# fresh `up` otherwise, even though `docker ps` won't show them (they're
# stopped, not running).
docker compose down --remove-orphans 2>/dev/null || true

# 1. Start βασικά services ΜΟΝΟ
docker compose up -d postgres redis zookeeper mosquitto

# 2. Περιμένετε ΛΙΓΟ για postgres
echo "⏳ Περιμένω Postgres..."
sleep 5

# 3. Start backend
docker compose up -d backend

# 4. Start τα υπόλοιπα ΠΑΡΑΛΛΗΛΑ
docker compose up -d kafka celery-worker celery-beat flower

echo "✅ Όλα τρέχουν! Έλεγχος:"
docker compose ps --format "table {{.Name}}\t{{.State}}\t{{.Status}}"

echo ""
echo "🌐 URLs:"
echo "Backend: http://localhost:15000"
echo "Flower:  http://localhost:15555 (admin:\$FLOWER_PASSWORD, see .env)"

# monsys (a separate deployment on another VM) needs this same value as its
# SCANNER_API_KEY/BACKEND_API_KEY/SCANNER_BACKEND_API_KEY - see .env.example.
if [ -f .env ] && grep -q '^CONTAINER_SCANNER_API_KEY=.\+' .env; then
    echo "Reminder: CONTAINER_SCANNER_API_KEY (see docker/.env) must also be set as"
    echo "SCANNER_API_KEY in monsys's .env on the frontend VM."
else
    echo "WARNING: CONTAINER_SCANNER_API_KEY is not set in .env - set it to share the"
    echo "container_scanner agent's key with monsys automatically instead of copying"
    echo "a randomly generated key out of backend startup logs by hand."
fi
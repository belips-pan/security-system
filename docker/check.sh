#!/bin/bash

echo "=== DOCKER CONTAINERS STATUS ==="
docker-compose ps

echo -e "\n=== BACKEND HEALTH ==="
curl -s -f http://localhost:15000/health && echo "✅ Backend is healthy" || echo "❌ Backend health check failed"

echo -e "\n=== DATABASE CONNECTION ==="
export PGPASSWORD=password
psql -h localhost -p 15433 -U admin -d security_db -c "SELECT '✅ Database connected', current_timestamp;" 2>/dev/null || echo "❌ Database connection failed"

echo -e "\n=== REDIS CONNECTION ==="
redis-cli -h localhost -p 16379 ping 2>/dev/null && echo "✅ Redis is responding" || echo "❌ Redis connection failed"

echo -e "\n=== CELERY WORKERS ==="
docker-compose exec -T celery-worker celery -A src.backend.celery_tasks.app inspect ping 2>/dev/null | grep -q "pong" && echo "✅ Celery workers are running" || echo "❌ Celery workers not responding"

echo -e "\n=== DOCKER SOCKET ACCESS ==="
docker-compose exec backend python3 -c "
import docker
try:
    client = docker.from_env()
    print('✅ Docker client OK:', client.version()['Version'][:15])
except Exception as e:
    print('❌ Docker client error:', str(e)[:80])
"
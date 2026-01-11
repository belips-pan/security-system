#!/bin/bash
echo "=== BACKEND COMPLETE CHECK ==="

echo "1. Testing endpoints..."
ENDPOINTS=(
    "/health"
    "/api/security-scanner/health"
    "/api/v2/security/health"
    "/api/agents"
    "/api/alerts"
)

for endpoint in "${ENDPOINTS[@]}"; do
    echo -n "$endpoint: "
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://192.168.56.20:15000$endpoint)
    if [ "$STATUS" = "200" ] || [ "$STATUS" = "401" ]; then
        echo "✅ $STATUS"
    else
        echo "❌ $STATUS"
    fi
done

echo -e "\n2. Checking Celery..."
docker exec docker_backend_1 python3 -c "
import sys
sys.path.append('/app/src/backend')
try:
    from celery_tasks import app as celery_app
    print('✅ Celery module loaded')
    from celery_tasks import scanner
    print(f'✅ Docker scanner available: {scanner.docker_client is not None}')
except Exception as e:
    print(f'❌ Error: {e}')
"

echo -e "\n3. Checking database..."
docker exec docker_backend_1 python3 -c "
import sys
sys.path.append('/app/src/backend')
from app import app, db

with app.app_context():
    from sqlalchemy import inspect
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()
    print(f'✅ Database accessible, {len(tables)} tables found')
    for table in tables:
        print(f'   - {table}')
    
    # Check if we have data
    try:
        from models import Agent
        agents = Agent.query.count()
        print(f'✅ Agents in database: {agents}')
    except Exception as e:
        print(f'⚠️ Could not query agents: {e}')
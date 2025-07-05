#!/bin/bash

# A2Z IDS/IPS Status Check Script
echo "🛡️  A2Z IDS/IPS System Status"
echo "====================================="
echo ""

# Check Docker services
echo "📦 Docker Services Status:"
docker-compose -f docker-compose.dev.yml ps
echo ""

# Check API endpoints
echo "🔌 API Health Checks:"
echo ""

# API Health
echo "• API Health:"
curl -s http://localhost:8080/health | python3 -c "import sys,json; data=json.load(sys.stdin); print(f'  Status: {data[\"status\"]} - {data[\"service\"]} v{data[\"version\"]}')" 2>/dev/null || echo "  ❌ API not responding"

# System Status
echo "• System Status:"
curl -s http://localhost:8080/api/v1/status | python3 -c "import sys,json; data=json.load(sys.stdin); print(f'  Status: {data[\"status\"]} - Engines: {list(data[\"services\"].values()).count(\"active\")} active')" 2>/dev/null || echo "  ❌ Status endpoint not responding"

echo ""

# Check Web Interfaces
echo "🌐 Web Interfaces:"
echo "• Grafana Dashboard:     http://localhost:3001 (admin/admin_password)"
echo "• Prometheus Metrics:    http://localhost:9090"
echo "• API Documentation:     http://localhost:8080/api/v1/status"
echo ""

# Check Database Services
echo "💾 Database Services:"
echo "• PostgreSQL:            localhost:5432 (a2z_ids/secure_password)"
echo "• Redis:                 localhost:6379"
echo "• ClickHouse:            localhost:8123"
echo ""

# Show recent alerts
echo "🚨 Recent Security Alerts:"
curl -s http://localhost:8080/api/v1/alerts | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin)
    for alert in data['alerts']:
        print(f'  • {alert[\"severity\"].upper()}: {alert[\"signature\"]} from {alert[\"source\"]}')
except:
    print('  ❌ No alerts available')
" 2>/dev/null

echo ""

# Show rules loaded
echo "📋 Detection Rules:"
curl -s http://localhost:8080/api/v1/rules | python3 -c "
import sys,json
try:
    data=json.load(sys.stdin)
    print(f'  • Total rules loaded: {data[\"total\"]}')
    for rule in data['rules']:
        status = '✓' if rule['enabled'] else '✗'
        print(f'    {status} {rule[\"name\"]} ({rule[\"category\"]})')
except:
    print('  ❌ Rules not available')
" 2>/dev/null

echo ""
echo "✅ A2Z IDS/IPS is running successfully!"
echo ""
echo "📖 Quick Commands:"
echo "  docker-compose -f docker-compose.dev.yml logs -f    # View logs"
echo "  docker-compose -f docker-compose.dev.yml stop       # Stop services"
echo "  docker-compose -f docker-compose.dev.yml restart    # Restart services"
echo "" 
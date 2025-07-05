#!/bin/bash

# Production health check for all services
echo "🔍 Running comprehensive health check..."

# Check Nginx
if ! curl -f -s http://localhost:80/health >/dev/null 2>&1; then
    echo "❌ Nginx health check failed"
    exit 1
fi

# Check API
if ! curl -f -s http://localhost:3001/health >/dev/null 2>&1; then
    echo "❌ API health check failed"
    exit 1
fi

# Check Network Agent
if ! curl -f -s http://localhost:5200/health >/dev/null 2>&1; then
    echo "❌ Network Agent health check failed"
    exit 1
fi

# Check IDS Management API
if ! curl -f -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "❌ IDS API health check failed"
    exit 1
fi

# Check IDS Core Process
if ! pgrep -f "a2z-ids-core" >/dev/null 2>&1; then
    echo "❌ IDS Core not running"
    exit 1
fi

# Check Suricata Process
if ! pgrep suricata >/dev/null 2>&1; then
    echo "⚠️  Suricata not running (non-critical)"
fi

echo "✅ All production services healthy"
exit 0 
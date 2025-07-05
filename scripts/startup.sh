#!/bin/bash
set -e

echo "🚀 Starting A2Z SOC SaaS Platform - Production Ready..."

# Ensure log directories exist
mkdir -p /var/log/supervisor /var/log/a2z-soc /var/log/nginx

# Set production environment
export NODE_ENV=production
export API_PORT=3001
export NETWORK_AGENT_PORT=5200
export IDS_API_PORT=8080
export A2Z_CONFIG_PATH=/app/ids/config/production.yaml
export A2Z_RULES_PATH=/app/ids/rules
export A2Z_MODELS_PATH=/app/ids/models

# Start system services
echo "✅ Starting system services..."

# Wait for dependencies
echo "🔄 Waiting for database connections..."
sleep 10

echo "✅ All production services configured - starting supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/a2z-soc-production.conf 
#!/bin/bash
set -e

echo "🚀 Starting A2Z SOC Services..."

# Start PostgreSQL
echo "📊 Starting PostgreSQL..."
su-exec postgres pg_ctl -D /var/lib/postgresql/data -o "-k /run/postgresql" start

# Start Redis
echo "📦 Starting Redis..."
redis-server /etc/redis.conf --daemonize yes

# Wait for databases to be ready
echo "⏳ Waiting for databases..."
sleep 10

# Set environment variables
export NODE_ENV="development"
export DATABASE_URL="postgresql://postgres@localhost:5432/a2z_soc"
export REDIS_URL="redis://localhost:6379/0"

# Start API Server
echo "🔧 Starting API Server..."
cd /app/api
node index.js &
API_PID=$!

# Start Frontend with custom SPA server (handles client-side routing properly)
echo "🎨 Starting Frontend Server..."
cd /app
node spa-server.js &
FRONTEND_PID=$!

echo "✅ Core services started!"
echo "🌍 Frontend: http://localhost:8080"
echo "🔧 API: http://localhost:3001"

# Function to handle shutdown
cleanup() {
    echo "🛑 Shutting down..."
    kill $API_PID $FRONTEND_PID 2>/dev/null || true
    redis-cli shutdown 2>/dev/null || true
    su-exec postgres pg_ctl -D /var/lib/postgresql/data stop 2>/dev/null || true
    exit 0
}

trap cleanup SIGTERM SIGINT

# Keep container running
wait $API_PID $FRONTEND_PID

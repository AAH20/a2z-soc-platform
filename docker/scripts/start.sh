#!/bin/bash

# Start script for A2Z SOC Unified Container
set -e

echo "🚀 Starting A2Z SOC Unified Container..."

# Start PostgreSQL
echo "📊 Starting PostgreSQL..."
su-exec postgres pg_ctl -D /var/lib/postgresql/data -o "-k /run/postgresql" start

# Wait for PostgreSQL
echo "⏳ Waiting for PostgreSQL to be ready..."
for i in {1..30}; do
    if su-exec postgres psql -h localhost -U postgres -d a2z_soc -c "SELECT 1" >/dev/null 2>&1; then
        echo "✅ PostgreSQL is ready"
        break
    fi
    echo "⏳ Waiting for PostgreSQL... ($i/30)"
    sleep 2
done

# Start Redis
echo "📦 Starting Redis..."
redis-server /etc/redis.conf --daemonize yes

# Wait for Redis
echo "⏳ Waiting for Redis to be ready..."
for i in {1..10}; do
    if redis-cli ping >/dev/null 2>&1; then
        echo "✅ Redis is ready"
        break
    fi
    echo "⏳ Waiting for Redis... ($i/10)"
    sleep 1
done

# Set environment variables
export NODE_ENV="development"
export PORT="3001"
export DATABASE_URL="postgresql://postgres@localhost:5432/a2z_soc"
export REDIS_URL="redis://localhost:6379/0"

# Start API in background
echo "🔧 Starting API Server..."
cd /app/api
nohup node index.js > /var/log/api.log 2>&1 &
API_PID=$!
echo "✅ API Server started with PID: $API_PID"

# Start Network Agent in background
echo "🌐 Starting Network Agent..."
cd /app/agents/network-agent
export A2Z_INTERFACE="any"
export A2Z_STANDALONE="true"
nohup node standalone-server.js > /var/log/network-agent.log 2>&1 &
AGENT_PID=$!
echo "✅ Network Agent started with PID: $AGENT_PID"

# Build frontend first
echo "🎨 Building Frontend..."
cd /app
npm run build

# Start frontend server (production build served via simple HTTP server)
echo "🌐 Starting Frontend Server..."
cd /app/dist
nohup python3 -m http.server 8080 > /var/log/frontend.log 2>&1 &
FRONTEND_PID=$!
echo "✅ Frontend Server started with PID: $FRONTEND_PID"

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

echo "🎉 All services started successfully!"
echo "📊 PostgreSQL: Running"
echo "📦 Redis: Running" 
echo "🔧 API Server: Running on port 3001 (PID: $API_PID)"
echo "🌐 Network Agent: Running on port 5200 (PID: $AGENT_PID)"
echo "🎨 Frontend: Running on port 8080 (PID: $FRONTEND_PID)"
echo ""
echo "🌍 Access the application at: http://localhost:8080"
echo "🔧 API endpoint available at: http://localhost:3001"
echo ""
echo "📝 Logs available at:"
echo "   - API: /var/log/api.log"
echo "   - Network Agent: /var/log/network-agent.log"
echo "   - Frontend: /var/log/frontend.log"

# Function to handle shutdown
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    kill $API_PID 2>/dev/null || true
    kill $AGENT_PID 2>/dev/null || true  
    kill $FRONTEND_PID 2>/dev/null || true
    redis-cli shutdown 2>/dev/null || true
    su-exec postgres pg_ctl -D /var/lib/postgresql/data stop 2>/dev/null || true
    echo "✅ All services stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Keep the container running and monitor services
echo "🔄 Container is running. Press Ctrl+C to stop."
while true; do
    # Check if API is still running
    if ! kill -0 $API_PID 2>/dev/null; then
        echo "❌ API Server stopped unexpectedly. Restarting..."
        cd /app/api
        nohup node index.js > /var/log/api.log 2>&1 &
        API_PID=$!
        echo "✅ API Server restarted with PID: $API_PID"
    fi
    
    # Check if Network Agent is still running
    if ! kill -0 $AGENT_PID 2>/dev/null; then
        echo "❌ Network Agent stopped unexpectedly. Restarting..."
        cd /app/agents/network-agent
        nohup node standalone-server.js > /var/log/network-agent.log 2>&1 &
        AGENT_PID=$!
        echo "✅ Network Agent restarted with PID: $AGENT_PID"
    fi
    
    # Check if Frontend is still running
    if ! kill -0 $FRONTEND_PID 2>/dev/null; then
        echo "❌ Frontend Server stopped unexpectedly. Restarting..."
        cd /app/dist
        nohup python3 -m http.server 8080 > /var/log/frontend.log 2>&1 &
        FRONTEND_PID=$!
        echo "✅ Frontend Server restarted with PID: $FRONTEND_PID"
    fi
    
    sleep 30
done 
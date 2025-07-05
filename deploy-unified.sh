#!/bin/bash

# A2Z SOC Unified Platform - Simple Deploy Script
set -e

IMAGE_NAME="a2z-soc-unified"
CONTAINER_NAME="a2z-soc-unified"

echo "🚀 Deploying A2Z SOC Unified Platform..."

# Stop and remove existing container if it exists
if docker ps -a | grep -q $CONTAINER_NAME; then
    echo "🛑 Stopping existing container..."
    docker stop $CONTAINER_NAME || true
    docker rm $CONTAINER_NAME || true
fi

# Run the new container
echo "🌐 Starting new container..."
docker run -d \
    --name $CONTAINER_NAME \
    -p 8080:8080 \
    -p 3001:3001 \
    -p 5200:5200 \
    -p 6379:6379 \
    -p 5432:5432 \
    $IMAGE_NAME

echo "✅ Deployment completed successfully!"
echo ""
echo "🌍 Frontend: http://localhost:8080"
echo "🔧 API: http://localhost:3001"
echo "🌐 Network Agent: http://localhost:5200"
echo ""
echo "📊 Check status: docker logs $CONTAINER_NAME"
echo "🛑 Stop: docker stop $CONTAINER_NAME"

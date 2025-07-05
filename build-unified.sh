#!/bin/bash

# A2Z SOC Unified Platform - Simple Build Script
set -e

# Configuration
IMAGE_NAME="a2z-soc-unified"
BUILD_TIME=$(date +%Y%m%d-%H%M%S)

echo "🚀 Building A2Z SOC Unified Container..."

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker daemon is not running"
    exit 1
fi

# Build the Docker image
echo "🔨 Building Docker image: $IMAGE_NAME"
docker build --no-cache -t $IMAGE_NAME .

echo "✅ Build completed successfully!"
echo "📦 Image: $IMAGE_NAME"
echo "🕒 Build time: $BUILD_TIME"
echo ""
echo "To run the container:"
echo "docker run -d --name a2z-soc-unified -p 8080:8080 -p 3001:3001 $IMAGE_NAME"
echo ""
echo "To access the application:"
echo "🌍 Frontend: http://localhost:8080"
echo "🔧 API: http://localhost:3001"

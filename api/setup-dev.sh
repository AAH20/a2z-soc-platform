#!/bin/bash

# A2Z SOC Development Setup Script
# This script helps set up the development environment

set -e

echo "🚀 A2Z SOC SaaS Development Setup"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if we're in the API directory
if [[ ! -f "package.json" ]]; then
    print_error "Please run this script from the api/ directory"
    exit 1
fi

# Check for required tools
print_info "Checking required tools..."

command -v node >/dev/null 2>&1 || { 
    print_error "Node.js is required but not installed. Please install Node.js 18 or higher."
    exit 1
}

command -v npm >/dev/null 2>&1 || { 
    print_error "npm is required but not installed. Please install npm."
    exit 1
}

command -v psql >/dev/null 2>&1 || { 
    print_warning "PostgreSQL client not found. Make sure PostgreSQL is installed and accessible."
}

print_status "Required tools check completed"

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [[ $NODE_VERSION -lt 18 ]]; then
    print_error "Node.js version 18 or higher is required. Current version: $(node --version)"
    exit 1
fi

print_status "Node.js version is compatible: $(node --version)"

# Install dependencies
print_info "Installing npm dependencies..."
npm install
print_status "Dependencies installed"

# Set up environment file
if [[ ! -f ".env" ]]; then
    print_info "Setting up environment file..."
    if [[ -f ".env.development" ]]; then
        cp .env.development .env
        print_status "Environment file created from .env.development"
    elif [[ -f ".env.example" ]]; then
        cp .env.example .env
        print_status "Environment file created from .env.example"
        print_warning "Please update the .env file with your actual configuration"
    else
        print_error "No template environment file found"
        exit 1
    fi
else
    print_warning "Environment file already exists, skipping..."
fi

# Check database connection
print_info "Checking database connection..."

if [[ -f ".env" ]]; then
    source .env
    
    if [[ -z "$DATABASE_URL" ]]; then
        print_error "DATABASE_URL not set in .env file"
        exit 1
    fi
    
    # Extract database info from URL
    DB_HOST=$(echo $DATABASE_URL | sed 's/.*@\([^:]*\).*/\1/')
    DB_PORT=$(echo $DATABASE_URL | sed 's/.*:\([0-9]*\)\/.*/\1/')
    DB_NAME=$(echo $DATABASE_URL | sed 's/.*\/\([^?]*\).*/\1/')
    
    print_info "Database: $DB_NAME on $DB_HOST:$DB_PORT"
    
    # Test database connection
    if command -v psql >/dev/null 2>&1; then
        if psql "$DATABASE_URL" -c '\l' >/dev/null 2>&1; then
            print_status "Database connection successful"
        else
            print_warning "Could not connect to database. Please ensure PostgreSQL is running and the DATABASE_URL is correct."
            print_info "You can create the database with: createdb a2z_soc_dev"
        fi
    else
        print_warning "PostgreSQL client not available, skipping connection test"
    fi
else
    print_error "Environment file not found"
    exit 1
fi

# Run migrations
print_info "Running database migrations..."
if npm run migrate 2>/dev/null; then
    print_status "Database migrations completed"
else
    print_warning "Database migrations failed. Make sure the database exists and is accessible."
    print_info "Try creating the database: createdb a2z_soc_dev"
    print_info "Then run: npm run migrate"
fi

# Create uploads directory
print_info "Creating uploads directory..."
mkdir -p uploads
print_status "Uploads directory created"

# Generate JWT secret if needed
if grep -q "your-super-secret-jwt-key" .env 2>/dev/null; then
    print_info "Generating JWT secret..."
    JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
    sed -i.bak "s/your-super-secret-jwt-key-at-least-32-characters-long/$JWT_SECRET/" .env
    print_status "JWT secret generated"
fi

# Setup summary
echo ""
echo "📋 Setup Summary"
echo "================"
print_status "Dependencies installed"
print_status "Environment configuration ready"
print_status "Uploads directory created"

if command -v psql >/dev/null 2>&1 && psql "$DATABASE_URL" -c '\l' >/dev/null 2>&1; then
    print_status "Database connection verified"
else
    print_warning "Database connection needs attention"
fi

echo ""
echo "🎯 Next Steps"
echo "============="
echo "1. Start the development server:"
echo -e "   ${BLUE}npm run dev${NC}"
echo ""
echo "2. Test the setup:"
echo -e "   ${BLUE}node test-setup.js${NC}"
echo ""
echo "3. View API documentation:"
echo -e "   ${BLUE}http://localhost:3001/api/docs${NC}"
echo ""
echo "4. Test the health endpoint:"
echo -e "   ${BLUE}curl http://localhost:3001/health${NC}"
echo ""

echo "🔗 Useful URLs"
echo "=============="
echo "API Server: http://localhost:3001"
echo "Health Check: http://localhost:3001/health"
echo "API Base: http://localhost:3001/api"
echo "API Docs: http://localhost:3001/api/docs"
echo ""

print_info "Setup completed! You're ready to start developing the A2Z SOC SaaS platform."

# Optional: Ask if user wants to start the server
read -p "Would you like to start the development server now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_info "Starting development server..."
    npm run dev
fi 
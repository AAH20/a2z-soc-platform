# A2Z SOC Platform - Unified Production Container
FROM node:18-alpine

# Install system dependencies including build tools
RUN apk add --no-cache \
    curl wget bash tini su-exec \
    tcpdump net-tools \
    postgresql postgresql-contrib \
    redis \
    python3 \
    nginx \
    make g++ python3-dev

# Create users for services
RUN addgroup -g 998 redis 2>/dev/null || true && \
    adduser -D -u 998 -G redis redis 2>/dev/null || true

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY api/package*.json ./api/

# Install main dependencies and API dependencies
RUN npm ci && \
    cd api && npm ci && \
    cd ..

# Copy source code
COPY . .

# Build frontend
RUN npm run build

# Create necessary directories
RUN mkdir -p \
    /var/lib/postgresql/data /run/postgresql \
    /var/lib/redis /var/log/redis \
    /var/log

# Initialize PostgreSQL
RUN chown -R postgres:postgres /var/lib/postgresql/data /run/postgresql && \
    su-exec postgres initdb -D /var/lib/postgresql/data

# Copy and apply database schema
COPY database/schema.sql /tmp/schema.sql
RUN su-exec postgres pg_ctl -D /var/lib/postgresql/data -o "-k /run/postgresql" start && \
    sleep 5 && \
    su-exec postgres createdb -h localhost a2z_soc && \
    su-exec postgres psql -h localhost -d a2z_soc -f /tmp/schema.sql && \
    su-exec postgres pg_ctl -D /var/lib/postgresql/data stop

# Setup Redis configuration
RUN echo "bind 127.0.0.1" > /etc/redis.conf && \
    echo "port 6379" >> /etc/redis.conf && \
    echo "dir /var/lib/redis" >> /etc/redis.conf

# Copy startup script
COPY startup-simple.sh /app/startup.sh
RUN chmod +x /app/startup.sh

# Set proper permissions
RUN chown -R postgres:postgres /var/lib/postgresql /run/postgresql && \
    chown -R redis:redis /var/lib/redis /var/log/redis

# Expose ports
EXPOSE 8080 3001 6379 5432

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# Use tini for signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start the application
CMD ["/app/startup.sh"]

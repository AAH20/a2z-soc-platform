#!/bin/bash

# A2Z IDS/IPS Backup and Restore Script
# Comprehensive backup solution for all system components

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/a2z-ids}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="a2z-ids-backup-${TIMESTAMP}"
LOG_FILE="/var/log/a2z-ids/backup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" | tee -a "$LOG_FILE" >&2
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $1" | tee -a "$LOG_FILE"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script requires root privileges for backup operations"
        print_status "Try: sudo $0 $*"
        exit 1
    fi
}

# Create backup directory
create_backup_dir() {
    local backup_path="$BACKUP_DIR/$BACKUP_NAME"
    mkdir -p "$backup_path"
    echo "$backup_path"
}

# Backup configuration files
backup_configuration() {
    local backup_path="$1"
    print_status "Backing up configuration files..."
    
    # Create configuration backup directory
    mkdir -p "$backup_path/config"
    
    # Backup main configuration
    if [[ -d "$PROJECT_DIR/config" ]]; then
        cp -r "$PROJECT_DIR/config/"* "$backup_path/config/" 2>/dev/null || true
        log_info "Configuration files backed up"
    fi
    
    # Backup Docker Compose files
    cp "$PROJECT_DIR/docker-compose"*.yml "$backup_path/" 2>/dev/null || true
    
    # Backup Makefiles
    cp "$PROJECT_DIR/Makefile"* "$backup_path/" 2>/dev/null || true
    
    # Backup environment files
    cp "$PROJECT_DIR/.env"* "$backup_path/" 2>/dev/null || true
    
    print_success "Configuration backup completed"
}

# Backup rules and models
backup_rules_and_models() {
    local backup_path="$1"
    print_status "Backing up rules and ML models..."
    
    # Backup detection rules
    if [[ -d "$PROJECT_DIR/rules" ]]; then
        cp -r "$PROJECT_DIR/rules" "$backup_path/"
        log_info "Detection rules backed up"
    fi
    
    # Backup ML models
    if [[ -d "$PROJECT_DIR/models" ]]; then
        cp -r "$PROJECT_DIR/models" "$backup_path/"
        log_info "ML models backed up"
    fi
    
    # Backup custom scripts
    if [[ -d "$PROJECT_DIR/scripts" ]]; then
        cp -r "$PROJECT_DIR/scripts" "$backup_path/"
        log_info "Scripts backed up"
    fi
    
    print_success "Rules and models backup completed"
}

# Backup PostgreSQL database
backup_postgres() {
    local backup_path="$1"
    print_status "Backing up PostgreSQL database..."
    
    local postgres_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q postgres 2>/dev/null || echo "")
    
    if [[ -n "$postgres_container" ]]; then
        # Create database backup
        mkdir -p "$backup_path/database"
        
        docker exec "$postgres_container" pg_dump -U a2z_ids -d a2z_ids > "$backup_path/database/postgres_backup.sql" 2>/dev/null
        
        if [[ $? -eq 0 ]]; then
            print_success "PostgreSQL database backed up"
            log_info "PostgreSQL backup completed: $(stat -c%s "$backup_path/database/postgres_backup.sql" 2>/dev/null || echo "unknown") bytes"
        else
            print_warning "PostgreSQL backup failed or container not running"
        fi
    else
        print_warning "PostgreSQL container not found"
    fi
}

# Backup Redis data
backup_redis() {
    local backup_path="$1"
    print_status "Backing up Redis data..."
    
    local redis_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q redis 2>/dev/null || echo "")
    
    if [[ -n "$redis_container" ]]; then
        mkdir -p "$backup_path/redis"
        
        # Save Redis snapshot
        docker exec "$redis_container" redis-cli BGSAVE >/dev/null 2>&1
        sleep 2  # Wait for background save to complete
        
        # Copy Redis dump file
        docker cp "$redis_container:/data/dump.rdb" "$backup_path/redis/" 2>/dev/null
        
        if [[ -f "$backup_path/redis/dump.rdb" ]]; then
            print_success "Redis data backed up"
            log_info "Redis backup completed: $(stat -c%s "$backup_path/redis/dump.rdb" 2>/dev/null || echo "unknown") bytes"
        else
            print_warning "Redis backup failed"
        fi
    else
        print_warning "Redis container not found"
    fi
}

# Backup ClickHouse data
backup_clickhouse() {
    local backup_path="$1"
    print_status "Backing up ClickHouse data..."
    
    local clickhouse_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q clickhouse 2>/dev/null || echo "")
    
    if [[ -n "$clickhouse_container" ]]; then
        mkdir -p "$backup_path/clickhouse"
        
        # Export ClickHouse data
        docker exec "$clickhouse_container" clickhouse-client --query="SHOW TABLES" > "$backup_path/clickhouse/tables.list" 2>/dev/null || true
        
        # Backup each table
        if [[ -f "$backup_path/clickhouse/tables.list" ]]; then
            while read -r table; do
                if [[ -n "$table" ]]; then
                    docker exec "$clickhouse_container" clickhouse-client --query="SELECT * FROM $table FORMAT TSV" > "$backup_path/clickhouse/${table}.tsv" 2>/dev/null || true
                fi
            done < "$backup_path/clickhouse/tables.list"
            
            print_success "ClickHouse data backed up"
            log_info "ClickHouse backup completed"
        else
            print_warning "ClickHouse backup failed"
        fi
    else
        print_warning "ClickHouse container not found"
    fi
}

# Backup logs
backup_logs() {
    local backup_path="$1"
    print_status "Backing up system logs..."
    
    mkdir -p "$backup_path/logs"
    
    # Backup log files
    if [[ -d "/var/log/a2z-ids" ]]; then
        cp -r /var/log/a2z-ids/* "$backup_path/logs/" 2>/dev/null || true
    fi
    
    # Backup Docker logs
    docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" logs > "$backup_path/logs/docker-compose.log" 2>/dev/null || true
    
    print_success "Logs backup completed"
}

# Backup Docker volumes
backup_docker_volumes() {
    local backup_path="$1"
    print_status "Backing up Docker volumes..."
    
    mkdir -p "$backup_path/volumes"
    
    # Get list of volumes
    local volumes=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" config --volumes 2>/dev/null || true)
    
    for volume in $volumes; do
        if [[ -n "$volume" ]]; then
            print_status "Backing up volume: $volume"
            docker run --rm -v "${volume}:/data" -v "$backup_path/volumes:/backup" alpine tar czf "/backup/${volume}.tar.gz" -C /data . 2>/dev/null || true
        fi
    done
    
    print_success "Docker volumes backup completed"
}

# Create backup metadata
create_backup_metadata() {
    local backup_path="$1"
    print_status "Creating backup metadata..."
    
    cat > "$backup_path/backup_info.json" << EOF
{
    "backup_name": "$BACKUP_NAME",
    "timestamp": "$(date -Iseconds)",
    "version": "1.0.0",
    "hostname": "$(hostname)",
    "system": "$(uname -a)",
    "docker_version": "$(docker --version 2>/dev/null || echo 'Not installed')",
    "backup_size": "$(du -sh "$backup_path" | cut -f1)",
    "components": {
        "configuration": $(test -d "$backup_path/config" && echo "true" || echo "false"),
        "rules": $(test -d "$backup_path/rules" && echo "true" || echo "false"),
        "models": $(test -d "$backup_path/models" && echo "true" || echo "false"),
        "postgres": $(test -f "$backup_path/database/postgres_backup.sql" && echo "true" || echo "false"),
        "redis": $(test -f "$backup_path/redis/dump.rdb" && echo "true" || echo "false"),
        "clickhouse": $(test -d "$backup_path/clickhouse" && echo "true" || echo "false"),
        "logs": $(test -d "$backup_path/logs" && echo "true" || echo "false"),
        "volumes": $(test -d "$backup_path/volumes" && echo "true" || echo "false")
    }
}
EOF
    
    print_success "Backup metadata created"
}

# Compress backup
compress_backup() {
    local backup_path="$1"
    print_status "Compressing backup..."
    
    cd "$BACKUP_DIR"
    tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
    
    if [[ $? -eq 0 ]]; then
        rm -rf "$backup_path"
        print_success "Backup compressed: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
        log_info "Backup compressed successfully: $(stat -c%s "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" 2>/dev/null || echo "unknown") bytes"
    else
        print_error "Backup compression failed"
        exit 1
    fi
}

# Full backup function
perform_backup() {
    log_info "Starting A2Z IDS/IPS backup"
    print_status "Starting backup process..."
    
    # Create backup directory
    local backup_path=$(create_backup_dir)
    print_status "Backup directory: $backup_path"
    
    # Perform backup components
    backup_configuration "$backup_path"
    backup_rules_and_models "$backup_path"
    backup_postgres "$backup_path"
    backup_redis "$backup_path"
    backup_clickhouse "$backup_path"
    backup_logs "$backup_path"
    backup_docker_volumes "$backup_path"
    create_backup_metadata "$backup_path"
    
    # Compress backup
    compress_backup "$backup_path"
    
    # Cleanup old backups
    cleanup_old_backups
    
    print_success "Backup completed successfully!"
    log_info "Backup process completed: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
}

# Restore configuration
restore_configuration() {
    local backup_path="$1"
    print_status "Restoring configuration files..."
    
    if [[ -d "$backup_path/config" ]]; then
        mkdir -p "$PROJECT_DIR/config"
        cp -r "$backup_path/config/"* "$PROJECT_DIR/config/"
        print_success "Configuration files restored"
    fi
    
    # Restore Docker Compose files
    cp "$backup_path/docker-compose"*.yml "$PROJECT_DIR/" 2>/dev/null || true
    
    # Restore Makefiles
    cp "$backup_path/Makefile"* "$PROJECT_DIR/" 2>/dev/null || true
    
    # Restore environment files
    cp "$backup_path/.env"* "$PROJECT_DIR/" 2>/dev/null || true
}

# Restore rules and models
restore_rules_and_models() {
    local backup_path="$1"
    print_status "Restoring rules and models..."
    
    if [[ -d "$backup_path/rules" ]]; then
        cp -r "$backup_path/rules" "$PROJECT_DIR/"
        print_success "Rules restored"
    fi
    
    if [[ -d "$backup_path/models" ]]; then
        cp -r "$backup_path/models" "$PROJECT_DIR/"
        print_success "Models restored"
    fi
    
    if [[ -d "$backup_path/scripts" ]]; then
        cp -r "$backup_path/scripts" "$PROJECT_DIR/"
        chmod +x "$PROJECT_DIR/scripts/"*.sh
        print_success "Scripts restored"
    fi
}

# Restore PostgreSQL
restore_postgres() {
    local backup_path="$1"
    print_status "Restoring PostgreSQL database..."
    
    if [[ -f "$backup_path/database/postgres_backup.sql" ]]; then
        local postgres_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q postgres 2>/dev/null || echo "")
        
        if [[ -n "$postgres_container" ]]; then
            docker exec -i "$postgres_container" psql -U a2z_ids -d a2z_ids < "$backup_path/database/postgres_backup.sql"
            print_success "PostgreSQL database restored"
        else
            print_warning "PostgreSQL container not found"
        fi
    fi
}

# Restore Redis
restore_redis() {
    local backup_path="$1"
    print_status "Restoring Redis data..."
    
    if [[ -f "$backup_path/redis/dump.rdb" ]]; then
        local redis_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q redis 2>/dev/null || echo "")
        
        if [[ -n "$redis_container" ]]; then
            docker cp "$backup_path/redis/dump.rdb" "$redis_container:/data/"
            docker restart "$redis_container"
            print_success "Redis data restored"
        else
            print_warning "Redis container not found"
        fi
    fi
}

# Restore ClickHouse
restore_clickhouse() {
    local backup_path="$1"
    print_status "Restoring ClickHouse data..."
    
    if [[ -d "$backup_path/clickhouse" ]]; then
        local clickhouse_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q clickhouse 2>/dev/null || echo "")
        
        if [[ -n "$clickhouse_container" ]]; then
            # Restore each table
            for tsv_file in "$backup_path/clickhouse/"*.tsv; do
                if [[ -f "$tsv_file" ]]; then
                    local table_name=$(basename "$tsv_file" .tsv)
                    docker exec -i "$clickhouse_container" clickhouse-client --query="INSERT INTO $table_name FORMAT TSV" < "$tsv_file" 2>/dev/null || true
                fi
            done
            print_success "ClickHouse data restored"
        else
            print_warning "ClickHouse container not found"
        fi
    fi
}

# Restore Docker volumes
restore_docker_volumes() {
    local backup_path="$1"
    print_status "Restoring Docker volumes..."
    
    if [[ -d "$backup_path/volumes" ]]; then
        for volume_file in "$backup_path/volumes/"*.tar.gz; do
            if [[ -f "$volume_file" ]]; then
                local volume_name=$(basename "$volume_file" .tar.gz)
                docker run --rm -v "${volume_name}:/data" -v "$backup_path/volumes:/backup" alpine tar xzf "/backup/${volume_name}.tar.gz" -C /data 2>/dev/null || true
            fi
        done
        print_success "Docker volumes restored"
    fi
}

# Full restore function
perform_restore() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    log_info "Starting A2Z IDS/IPS restore from: $backup_file"
    print_status "Starting restore process..."
    
    # Extract backup
    local restore_dir="/tmp/a2z-ids-restore-$$"
    mkdir -p "$restore_dir"
    tar -xzf "$backup_file" -C "$restore_dir"
    
    local backup_path=$(find "$restore_dir" -maxdepth 1 -type d -name "a2z-ids-backup-*" | head -1)
    
    if [[ ! -d "$backup_path" ]]; then
        print_error "Invalid backup file format"
        rm -rf "$restore_dir"
        exit 1
    fi
    
    # Stop services before restore
    print_status "Stopping services..."
    docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" down || true
    
    # Perform restore
    restore_configuration "$backup_path"
    restore_rules_and_models "$backup_path"
    restore_docker_volumes "$backup_path"
    
    # Start services
    print_status "Starting services..."
    docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" up -d
    
    # Wait for services to be ready
    sleep 10
    
    # Restore databases
    restore_postgres "$backup_path"
    restore_redis "$backup_path"
    restore_clickhouse "$backup_path"
    
    # Cleanup
    rm -rf "$restore_dir"
    
    print_success "Restore completed successfully!"
    log_info "Restore process completed from: $backup_file"
}

# List available backups
list_backups() {
    print_status "Available backups in $BACKUP_DIR:"
    echo
    
    if [[ -d "$BACKUP_DIR" ]]; then
        for backup in "$BACKUP_DIR"/a2z-ids-backup-*.tar.gz; do
            if [[ -f "$backup" ]]; then
                local filename=$(basename "$backup")
                local size=$(du -h "$backup" | cut -f1)
                local date=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
                printf "  %-40s %-10s %s\n" "$filename" "$size" "$date"
            fi
        done
    else
        print_warning "Backup directory does not exist: $BACKUP_DIR"
    fi
}

# Cleanup old backups
cleanup_old_backups() {
    print_status "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
    
    if [[ -d "$BACKUP_DIR" ]]; then
        find "$BACKUP_DIR" -name "a2z-ids-backup-*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete
        local remaining=$(find "$BACKUP_DIR" -name "a2z-ids-backup-*.tar.gz" -type f | wc -l)
        print_success "Cleanup completed. $remaining backups remaining."
    fi
}

# Verify backup integrity
verify_backup() {
    local backup_file="$1"
    
    if [[ ! -f "$backup_file" ]]; then
        print_error "Backup file not found: $backup_file"
        exit 1
    fi
    
    print_status "Verifying backup integrity..."
    
    # Test tar file
    if tar -tzf "$backup_file" >/dev/null 2>&1; then
        print_success "Backup file is valid"
    else
        print_error "Backup file is corrupted"
        exit 1
    fi
    
    # Extract and check metadata
    local temp_dir="/tmp/a2z-ids-verify-$$"
    mkdir -p "$temp_dir"
    tar -xzf "$backup_file" -C "$temp_dir"
    
    local backup_path=$(find "$temp_dir" -maxdepth 1 -type d -name "a2z-ids-backup-*" | head -1)
    
    if [[ -f "$backup_path/backup_info.json" ]]; then
        print_status "Backup metadata:"
        cat "$backup_path/backup_info.json"
        print_success "Backup verification completed"
    else
        print_warning "Backup metadata not found"
    fi
    
    rm -rf "$temp_dir"
}

# Usage information
usage() {
    cat << EOF
A2Z IDS/IPS Backup and Restore Tool

Usage: $0 [OPTIONS] COMMAND

COMMANDS:
    backup              Create a full system backup
    restore FILE        Restore from backup file
    list               List available backups
    cleanup            Remove old backups
    verify FILE        Verify backup integrity

OPTIONS:
    --backup-dir DIR   Backup directory (default: /var/backups/a2z-ids)
    --retention DAYS   Backup retention period (default: 30)
    -h, --help         Show this help

EXAMPLES:
    $0 backup                                    # Create backup
    $0 restore /var/backups/a2z-ids/backup.tar.gz # Restore from file
    $0 list                                      # List backups
    $0 verify backup.tar.gz                     # Verify backup

EOF
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --retention)
                RETENTION_DAYS="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            backup)
                check_privileges
                mkdir -p "$BACKUP_DIR"
                mkdir -p "$(dirname "$LOG_FILE")"
                perform_backup
                exit 0
                ;;
            restore)
                if [[ -z "$2" ]]; then
                    print_error "Restore command requires a backup file"
                    usage
                    exit 1
                fi
                check_privileges
                perform_restore "$2"
                exit 0
                ;;
            list)
                list_backups
                exit 0
                ;;
            cleanup)
                check_privileges
                cleanup_old_backups
                exit 0
                ;;
            verify)
                if [[ -z "$2" ]]; then
                    print_error "Verify command requires a backup file"
                    usage
                    exit 1
                fi
                verify_backup "$2"
                exit 0
                ;;
            *)
                print_error "Unknown command: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Default to showing usage
    usage
}

# Run main function
main "$@" 
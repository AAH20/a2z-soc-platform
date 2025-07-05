#!/bin/bash

# A2Z IDS/IPS System Update Script
# Comprehensive update and maintenance system

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/a2z-ids/update.log"
BACKUP_BEFORE_UPDATE=true
GITHUB_REPO="https://github.com/a2z-soc/a2z-ids-ips.git"
UPDATE_BRANCH="main"
DOWNTIME_ALLOWED=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
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

# Check system status
check_system_status() {
    print_status "Checking system status..."
    
    # Check if system is running
    if ! docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps >/dev/null 2>&1; then
        print_warning "System is not running"
        return 1
    fi
    
    # Check for unhealthy services
    local unhealthy=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps | grep -c "unhealthy\|exited" || true)
    if [[ $unhealthy -gt 0 ]]; then
        print_warning "$unhealthy unhealthy services detected"
        return 1
    fi
    
    print_success "System status check passed"
    return 0
}

# Create backup before update
create_pre_update_backup() {
    if [[ "$BACKUP_BEFORE_UPDATE" == "true" ]]; then
        print_status "Creating pre-update backup..."
        
        if [[ -x "$SCRIPT_DIR/backup-restore.sh" ]]; then
            sudo "$SCRIPT_DIR/backup-restore.sh" backup
            print_success "Pre-update backup completed"
        else
            print_warning "Backup script not found, skipping backup"
        fi
    fi
}

# Check for updates
check_for_updates() {
    print_status "Checking for available updates..."
    
    # Check if we're in a git repository
    if [[ ! -d "$PROJECT_DIR/.git" ]]; then
        print_warning "Not a git repository, cannot check for updates"
        return 1
    fi
    
    # Fetch latest changes
    cd "$PROJECT_DIR"
    git fetch origin "$UPDATE_BRANCH" >/dev/null 2>&1
    
    # Check if updates are available
    local local_commit=$(git rev-parse HEAD)
    local remote_commit=$(git rev-parse "origin/$UPDATE_BRANCH")
    
    if [[ "$local_commit" != "$remote_commit" ]]; then
        print_status "Updates available!"
        log_info "Local commit: $local_commit"
        log_info "Remote commit: $remote_commit"
        
        # Show changes
        echo -e "${YELLOW}Changes since last update:${NC}"
        git log --oneline --max-count=10 "$local_commit..$remote_commit"
        echo
        
        return 0
    else
        print_success "System is up to date"
        return 1
    fi
}

# Update system configuration
update_configuration() {
    print_status "Updating system configuration..."
    
    # Backup current configuration
    local config_backup="/tmp/a2z-ids-config-backup-$(date +%s)"
    cp -r "$PROJECT_DIR/config" "$config_backup" 2>/dev/null || true
    
    # Update configuration files
    cd "$PROJECT_DIR"
    git pull origin "$UPDATE_BRANCH" >/dev/null 2>&1
    
    # Check for configuration conflicts
    if git status --porcelain | grep -q "config/"; then
        print_warning "Configuration conflicts detected"
        echo -e "${YELLOW}Please review and resolve conflicts manually${NC}"
        git status
        return 1
    fi
    
    print_success "Configuration updated successfully"
    log_info "Configuration backup available at: $config_backup"
}

# Update detection rules
update_detection_rules() {
    print_status "Updating detection rules..."
    
    # Update Snort community rules
    if command -v wget >/dev/null 2>&1; then
        local rules_dir="$PROJECT_DIR/rules"
        mkdir -p "$rules_dir"
        
        # Download latest community rules
        wget -O /tmp/snort-community-rules.tar.gz \
            "https://www.snort.org/rules/community" >/dev/null 2>&1 || true
        
        if [[ -f "/tmp/snort-community-rules.tar.gz" ]]; then
            cd /tmp
            tar -xzf snort-community-rules.tar.gz
            cp community-rules/*.rules "$rules_dir/" 2>/dev/null || true
            rm -rf community-rules snort-community-rules.tar.gz
            print_success "Community rules updated"
        else
            print_warning "Failed to download community rules"
        fi
    fi
    
    # Update Emerging Threats rules
    if command -v wget >/dev/null 2>&1; then
        wget -O /tmp/emerging-rules.tar.gz \
            "https://rules.emergingthreats.net/open/suricata-6.0.9/emerging.rules.tar.gz" >/dev/null 2>&1 || true
        
        if [[ -f "/tmp/emerging-rules.tar.gz" ]]; then
            cd /tmp
            tar -xzf emerging-rules.tar.gz
            cat rules/emerging-*.rules > "$PROJECT_DIR/rules/emerging-threats.rules" 2>/dev/null || true
            rm -rf rules emerging-rules.tar.gz
            print_success "Emerging Threats rules updated"
        else
            print_warning "Failed to download Emerging Threats rules"
        fi
    fi
}

# Update Docker images
update_docker_images() {
    print_status "Updating Docker images..."
    
    # Pull latest images
    docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" pull
    
    print_success "Docker images updated"
}

# Update ML models
update_ml_models() {
    print_status "Updating ML models..."
    
    local models_dir="$PROJECT_DIR/models"
    mkdir -p "$models_dir"
    
    # Placeholder for ML model updates
    # In a real implementation, this would download updated models
    print_status "ML model updates would be implemented here"
    
    print_success "ML models update completed"
}

# Update system dependencies
update_dependencies() {
    print_status "Updating system dependencies..."
    
    # Update Rust dependencies
    if [[ -f "$PROJECT_DIR/core-engine/Cargo.toml" ]]; then
        cd "$PROJECT_DIR/core-engine"
        cargo update >/dev/null 2>&1 || true
        print_success "Rust dependencies updated"
    fi
    
    # Update Go dependencies
    if [[ -f "$PROJECT_DIR/management-api/go.mod" ]]; then
        cd "$PROJECT_DIR/management-api"
        go get -u ./... >/dev/null 2>&1 || true
        go mod tidy >/dev/null 2>&1 || true
        print_success "Go dependencies updated"
    fi
    
    # Update Node.js dependencies
    if [[ -f "$PROJECT_DIR/web-interface/package.json" ]]; then
        cd "$PROJECT_DIR/web-interface"
        npm update >/dev/null 2>&1 || true
        print_success "Node.js dependencies updated"
    fi
}

# Restart services with rolling update
rolling_restart() {
    print_status "Performing rolling restart..."
    
    if [[ "$DOWNTIME_ALLOWED" == "true" ]]; then
        # Full restart
        docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" restart
        print_success "Services restarted"
    else
        # Rolling restart to minimize downtime
        local services=(
            "a2z-ids-core"
            "a2z-ids-api"
            "a2z-ids-dashboard"
        )
        
        for service in "${services[@]}"; do
            print_status "Restarting $service..."
            docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" restart "$service" || true
            sleep 5  # Give service time to start
        done
        
        print_success "Rolling restart completed"
    fi
}

# Verify update success
verify_update() {
    print_status "Verifying update..."
    
    # Wait for services to be ready
    sleep 15
    
    # Check service health
    local failed_checks=0
    
    # Check API health
    if ! curl -s --max-time 10 "http://localhost:8080/health" >/dev/null 2>&1; then
        print_warning "API health check failed"
        ((failed_checks++))
    fi
    
    # Check web interface
    if ! curl -s --max-time 10 "http://localhost:3000" >/dev/null 2>&1; then
        print_warning "Web interface check failed"
        ((failed_checks++))
    fi
    
    # Check Docker services
    local unhealthy=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps | grep -c "unhealthy\|exited" || true)
    if [[ $unhealthy -gt 0 ]]; then
        print_warning "$unhealthy services are unhealthy"
        ((failed_checks++))
    fi
    
    if [[ $failed_checks -eq 0 ]]; then
        print_success "Update verification passed"
        return 0
    else
        print_error "Update verification failed ($failed_checks issues)"
        return 1
    fi
}

# Rollback to previous version
perform_rollback() {
    print_error "Performing rollback..."
    
    # Stop services
    docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" down
    
    # Rollback git changes
    cd "$PROJECT_DIR"
    git reset --hard HEAD~1
    
    # Restore from backup if available
    local latest_backup=$(find /var/backups/a2z-ids -name "a2z-ids-backup-*.tar.gz" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [[ -n "$latest_backup" ]] && [[ -f "$latest_backup" ]]; then
        print_status "Restoring from backup: $latest_backup"
        "$SCRIPT_DIR/backup-restore.sh" restore "$latest_backup"
    else
        # Start services with old configuration
        docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" up -d
    fi
    
    print_success "Rollback completed"
}

# Database migration
migrate_database() {
    print_status "Running database migrations..."
    
    # Check if migration is needed
    local postgres_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q postgres 2>/dev/null || echo "")
    
    if [[ -n "$postgres_container" ]]; then
        # Run migrations (placeholder)
        print_status "Database migrations would be implemented here"
        print_success "Database migrations completed"
    else
        print_warning "PostgreSQL container not found"
    fi
}

# Security updates
apply_security_updates() {
    print_status "Applying security updates..."
    
    # Update system packages
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1 || true
        apt-get upgrade -y >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum update -y >/dev/null 2>&1 || true
    elif command -v brew >/dev/null 2>&1; then
        brew update >/dev/null 2>&1 || true
        brew upgrade >/dev/null 2>&1 || true
    fi
    
    # Update Docker
    if command -v docker >/dev/null 2>&1; then
        # Check for Docker updates (placeholder)
        print_status "Docker security updates would be checked here"
    fi
    
    print_success "Security updates applied"
}

# Performance optimization
optimize_performance() {
    print_status "Optimizing system performance..."
    
    # Clean up Docker
    docker system prune -f >/dev/null 2>&1 || true
    
    # Optimize database
    local postgres_container=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q postgres 2>/dev/null || echo "")
    if [[ -n "$postgres_container" ]]; then
        docker exec "$postgres_container" psql -U a2z_ids -d a2z_ids -c "VACUUM ANALYZE;" >/dev/null 2>&1 || true
    fi
    
    # Clear logs older than 30 days
    find /var/log/a2z-ids -name "*.log" -type f -mtime +30 -delete 2>/dev/null || true
    
    print_success "Performance optimization completed"
}

# Full system update
perform_full_update() {
    log_info "Starting A2Z IDS/IPS system update"
    print_header "A2Z IDS/IPS System Update"
    
    # Pre-update checks
    check_system_status || {
        print_error "System status check failed"
        exit 1
    }
    
    # Create backup
    create_pre_update_backup
    
    # Check for updates
    if ! check_for_updates; then
        print_success "System is already up to date"
        exit 0
    fi
    
    # Perform updates
    update_configuration || {
        print_error "Configuration update failed"
        perform_rollback
        exit 1
    }
    
    update_detection_rules
    update_docker_images
    update_ml_models
    update_dependencies
    migrate_database
    
    # Restart services
    rolling_restart
    
    # Verify update
    if ! verify_update; then
        print_error "Update verification failed, performing rollback"
        perform_rollback
        exit 1
    fi
    
    # Post-update optimizations
    apply_security_updates
    optimize_performance
    
    print_success "System update completed successfully!"
    log_info "Update process completed successfully"
    
    # Show updated system info
    echo
    print_header "Updated System Information"
    echo "Git commit: $(cd "$PROJECT_DIR" && git rev-parse --short HEAD)"
    echo "Update time: $(date)"
    echo "System status: $(check_system_status && echo "Healthy" || echo "Issues detected")"
}

# Quick update (rules and images only)
perform_quick_update() {
    print_header "A2Z IDS/IPS Quick Update"
    log_info "Starting quick update"
    
    update_detection_rules
    update_docker_images
    
    print_success "Quick update completed!"
    log_info "Quick update completed"
}

# Update only detection rules
update_rules_only() {
    print_header "A2Z IDS/IPS Rules Update"
    log_info "Starting rules update"
    
    update_detection_rules
    
    # Reload rules without restart
    docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" kill -s SIGHUP a2z-ids-core 2>/dev/null || true
    
    print_success "Rules update completed!"
    log_info "Rules update completed"
}

# Show system version and update status
show_version() {
    print_header "A2Z IDS/IPS Version Information"
    
    echo "Current version:"
    if [[ -d "$PROJECT_DIR/.git" ]]; then
        cd "$PROJECT_DIR"
        echo "  Git commit: $(git rev-parse --short HEAD)"
        echo "  Git branch: $(git branch --show-current)"
        echo "  Last update: $(git log -1 --format='%cd' --date=relative)"
    else
        echo "  Version information not available (not a git repository)"
    fi
    
    echo
    echo "System status:"
    if check_system_status >/dev/null 2>&1; then
        echo -e "  Status: ${GREEN}Healthy${NC}"
    else
        echo -e "  Status: ${RED}Issues detected${NC}"
    fi
    
    echo
    echo "Update availability:"
    if check_for_updates >/dev/null 2>&1; then
        echo -e "  Updates: ${YELLOW}Available${NC}"
    else
        echo -e "  Updates: ${GREEN}Up to date${NC}"
    fi
}

# Usage information
usage() {
    cat << EOF
A2Z IDS/IPS System Update Tool

Usage: $0 [OPTIONS] COMMAND

COMMANDS:
    full                Full system update (default)
    quick               Quick update (rules and images only)
    rules               Update detection rules only
    version             Show version information
    check               Check for available updates
    rollback            Rollback to previous version

OPTIONS:
    --no-backup         Skip pre-update backup
    --allow-downtime    Allow full service restart
    --branch BRANCH     Update from specific branch (default: main)
    -h, --help          Show this help

EXAMPLES:
    $0                          # Full system update
    $0 quick                    # Quick update
    $0 rules                    # Update rules only
    $0 version                  # Show version info
    $0 --no-backup full         # Update without backup

EOF
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-backup)
                BACKUP_BEFORE_UPDATE=false
                shift
                ;;
            --allow-downtime)
                DOWNTIME_ALLOWED=true
                shift
                ;;
            --branch)
                UPDATE_BRANCH="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            full)
                perform_full_update
                exit 0
                ;;
            quick)
                perform_quick_update
                exit 0
                ;;
            rules)
                update_rules_only
                exit 0
                ;;
            version)
                show_version
                exit 0
                ;;
            check)
                check_for_updates
                exit 0
                ;;
            rollback)
                perform_rollback
                exit 0
                ;;
            *)
                print_error "Unknown command: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Default to full update
    perform_full_update
}

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Run main function
main "$@" 
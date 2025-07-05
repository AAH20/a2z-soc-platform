#!/bin/bash

# A2Z IDS/IPS Health Monitoring Script
# Continuous monitoring with alerting capabilities

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/var/log/a2z-ids/health-monitor.log"
PID_FILE="/var/run/a2z-ids-health-monitor.pid"
CHECK_INTERVAL=30  # seconds
ALERT_THRESHOLD=3  # consecutive failures before alert
EMAIL_ALERTS=""
WEBHOOK_URL=""
SLACK_WEBHOOK=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Global variables
FAILURE_COUNTS=()
LAST_STATUS=()
MONITORING_ACTIVE=false

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - WARNING: $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO: $1" | tee -a "$LOG_FILE"
}

# Signal handlers
cleanup() {
    log_info "Health monitor stopping..."
    MONITORING_ACTIVE=false
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGTERM SIGINT

# Health check functions
check_docker_services() {
    local service_name="docker_services"
    local status=0
    
    if ! docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps >/dev/null 2>&1; then
        status=1
    else
        local unhealthy=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps | grep -c "unhealthy\|exited" || true)
        if [[ $unhealthy -gt 0 ]]; then
            status=1
        fi
    fi
    
    update_service_status "$service_name" $status
    return $status
}

check_api_health() {
    local service_name="api_health"
    local status=0
    
    if ! curl -s --max-time 10 "http://localhost:8080/health" >/dev/null 2>&1; then
        status=1
    fi
    
    update_service_status "$service_name" $status
    return $status
}

check_web_interface() {
    local service_name="web_interface"
    local status=0
    
    if ! curl -s --max-time 10 "http://localhost:3000" >/dev/null 2>&1; then
        status=1
    fi
    
    update_service_status "$service_name" $status
    return $status
}

check_database_health() {
    local service_name="database_health"
    local status=0
    
    # Check PostgreSQL
    if ! docker exec -it $(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q postgres) pg_isready >/dev/null 2>&1; then
        status=1
    fi
    
    # Check Redis
    if ! docker exec -it $(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps -q redis) redis-cli ping >/dev/null 2>&1; then
        status=1
    fi
    
    update_service_status "$service_name" $status
    return $status
}

check_disk_space() {
    local service_name="disk_space"
    local status=0
    
    # Check if disk usage is above 85%
    local disk_usage=$(df "$PROJECT_DIR" | tail -1 | awk '{print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 85 ]]; then
        status=1
        log_warning "Disk usage is at ${disk_usage}%"
    fi
    
    update_service_status "$service_name" $status
    return $status
}

check_memory_usage() {
    local service_name="memory_usage"
    local status=0
    
    # Check system memory usage
    if command -v free >/dev/null 2>&1; then
        local memory_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')
        if [[ $memory_usage -gt 90 ]]; then
            status=1
            log_warning "Memory usage is at ${memory_usage}%"
        fi
    elif command -v vm_stat >/dev/null 2>&1; then
        # macOS memory check
        local memory_pressure=$(memory_pressure | grep "System-wide memory free percentage" | awk '{print $5}' | sed 's/%//')
        if [[ $memory_pressure -lt 10 ]]; then
            status=1
            log_warning "Memory pressure is high (${memory_pressure}% free)"
        fi
    fi
    
    update_service_status "$service_name" $status
    return $status
}

check_log_errors() {
    local service_name="log_errors"
    local status=0
    
    # Check for recent errors in logs
    local error_count=$(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" logs --since="5m" 2>&1 | grep -i "error\|exception\|fatal" | wc -l)
    if [[ $error_count -gt 10 ]]; then
        status=1
        log_warning "High error count in logs: $error_count errors in last 5 minutes"
    fi
    
    update_service_status "$service_name" $status
    return $status
}

# Service status management
update_service_status() {
    local service_name="$1"
    local current_status="$2"
    local index=$(get_service_index "$service_name")
    
    # Initialize arrays if needed
    if [[ ${#FAILURE_COUNTS[@]} -le $index ]]; then
        FAILURE_COUNTS[$index]=0
        LAST_STATUS[$index]=0
    fi
    
    if [[ $current_status -eq 0 ]]; then
        # Service is healthy
        if [[ ${LAST_STATUS[$index]} -ne 0 ]]; then
            log_info "Service $service_name recovered"
            send_recovery_alert "$service_name"
        fi
        FAILURE_COUNTS[$index]=0
        LAST_STATUS[$index]=0
    else
        # Service is unhealthy
        FAILURE_COUNTS[$index]=$((${FAILURE_COUNTS[$index]} + 1))
        LAST_STATUS[$index]=1
        
        log_warning "Service $service_name failed (attempt ${FAILURE_COUNTS[$index]})"
        
        # Send alert if threshold reached
        if [[ ${FAILURE_COUNTS[$index]} -ge $ALERT_THRESHOLD ]]; then
            send_failure_alert "$service_name" "${FAILURE_COUNTS[$index]}"
        fi
    fi
}

get_service_index() {
    local service_name="$1"
    case "$service_name" in
        "docker_services") echo 0 ;;
        "api_health") echo 1 ;;
        "web_interface") echo 2 ;;
        "database_health") echo 3 ;;
        "disk_space") echo 4 ;;
        "memory_usage") echo 5 ;;
        "log_errors") echo 6 ;;
        *) echo 7 ;;  # Default
    esac
}

# Alert functions
send_failure_alert() {
    local service_name="$1"
    local failure_count="$2"
    local message="ALERT: A2Z IDS/IPS service '$service_name' has failed $failure_count consecutive times"
    
    log_error "$message"
    
    # Send email alert
    if [[ -n "$EMAIL_ALERTS" ]]; then
        send_email_alert "$message"
    fi
    
    # Send webhook alert
    if [[ -n "$WEBHOOK_URL" ]]; then
        send_webhook_alert "$message"
    fi
    
    # Send Slack alert
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        send_slack_alert "$message"
    fi
}

send_recovery_alert() {
    local service_name="$1"
    local message="RECOVERY: A2Z IDS/IPS service '$service_name' has recovered"
    
    log_info "$message"
    
    # Send email alert
    if [[ -n "$EMAIL_ALERTS" ]]; then
        send_email_alert "$message"
    fi
    
    # Send webhook alert
    if [[ -n "$WEBHOOK_URL" ]]; then
        send_webhook_alert "$message"
    fi
    
    # Send Slack alert
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        send_slack_alert "$message"
    fi
}

send_email_alert() {
    local message="$1"
    if command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "A2Z IDS/IPS Alert" "$EMAIL_ALERTS"
    elif command -v sendmail >/dev/null 2>&1; then
        {
            echo "To: $EMAIL_ALERTS"
            echo "Subject: A2Z IDS/IPS Alert"
            echo ""
            echo "$message"
        } | sendmail "$EMAIL_ALERTS"
    fi
}

send_webhook_alert() {
    local message="$1"
    curl -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"$message\", \"timestamp\": \"$(date -Iseconds)\"}" \
        >/dev/null 2>&1 || true
}

send_slack_alert() {
    local message="$1"
    curl -X POST "$SLACK_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{\"text\": \"$message\"}" \
        >/dev/null 2>&1 || true
}

# System metrics collection
collect_metrics() {
    local metrics_file="/tmp/a2z-ids-metrics.json"
    
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"docker_services\": $(docker-compose -f "$PROJECT_DIR/docker-compose.standalone.yml" ps | grep -c "Up" || echo 0),"
        echo "  \"disk_usage\": \"$(df "$PROJECT_DIR" | tail -1 | awk '{print $5}')\","
        echo "  \"memory_usage\": \"$(free 2>/dev/null | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' || echo 'N/A')%\","
        echo "  \"api_response_time\": $(curl -s -w "%{time_total}" -o /dev/null "http://localhost:8080/health" 2>/dev/null || echo 0),"
        echo "  \"uptime\": \"$(uptime | awk '{print $3,$4}' | sed 's/,//')\""
        echo "}"
    } > "$metrics_file"
}

# Status dashboard
show_status() {
    clear
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}       A2Z IDS/IPS Health Monitor${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo "Last updated: $(date)"
    echo "Monitor PID: $$"
    echo "Check interval: ${CHECK_INTERVAL}s"
    echo
    
    # Service status
    echo -e "${YELLOW}Service Status:${NC}"
    check_docker_services && echo -e "  Docker Services: ${GREEN}✓ Healthy${NC}" || echo -e "  Docker Services: ${RED}✗ Failed${NC}"
    check_api_health && echo -e "  API Health: ${GREEN}✓ Healthy${NC}" || echo -e "  API Health: ${RED}✗ Failed${NC}"
    check_web_interface && echo -e "  Web Interface: ${GREEN}✓ Healthy${NC}" || echo -e "  Web Interface: ${RED}✗ Failed${NC}"
    check_database_health && echo -e "  Database Health: ${GREEN}✓ Healthy${NC}" || echo -e "  Database Health: ${RED}✗ Failed${NC}"
    check_disk_space && echo -e "  Disk Space: ${GREEN}✓ OK${NC}" || echo -e "  Disk Space: ${RED}✗ Critical${NC}"
    check_memory_usage && echo -e "  Memory Usage: ${GREEN}✓ OK${NC}" || echo -e "  Memory Usage: ${RED}✗ High${NC}"
    check_log_errors && echo -e "  Log Errors: ${GREEN}✓ Normal${NC}" || echo -e "  Log Errors: ${RED}✗ High${NC}"
    
    echo
    echo -e "${YELLOW}System Metrics:${NC}"
    echo "  Disk Usage: $(df "$PROJECT_DIR" | tail -1 | awk '{print $5}')"
    echo "  Memory Usage: $(free 2>/dev/null | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' || echo 'N/A')%"
    echo "  Uptime: $(uptime | awk '{print $3,$4}' | sed 's/,//')"
    echo "  Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    
    echo
    echo -e "${YELLOW}Recent Activity:${NC}"
    tail -5 "$LOG_FILE" 2>/dev/null || echo "  No recent activity"
    
    echo
    echo "Press Ctrl+C to stop monitoring"
}

# Main monitoring loop
start_monitoring() {
    log_info "Starting A2Z IDS/IPS health monitor (PID: $$)"
    echo $$ > "$PID_FILE"
    
    MONITORING_ACTIVE=true
    
    while $MONITORING_ACTIVE; do
        # Run health checks
        check_docker_services
        check_api_health
        check_web_interface
        check_database_health
        check_disk_space
        check_memory_usage
        check_log_errors
        
        # Collect metrics
        collect_metrics
        
        # Show status if running interactively
        if [[ -t 1 ]]; then
            show_status
        fi
        
        # Wait for next check
        sleep "$CHECK_INTERVAL"
    done
}

# Command line interface
usage() {
    cat << EOF
A2Z IDS/IPS Health Monitor

Usage: $0 [OPTIONS] COMMAND

COMMANDS:
    start           Start continuous monitoring
    status          Show current status
    test            Run single health check
    stop            Stop monitoring daemon

OPTIONS:
    -i, --interval SECONDS      Check interval (default: 30)
    -e, --email EMAIL           Email address for alerts
    -w, --webhook URL           Webhook URL for alerts
    -s, --slack URL             Slack webhook URL for alerts
    -d, --daemon                Run as daemon
    -h, --help                  Show this help

EXAMPLES:
    $0 start                                    # Start interactive monitoring
    $0 start --daemon --email admin@company.com # Start as daemon with email alerts
    $0 status                                   # Show current status
    $0 test                                     # Run single health check

EOF
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            -e|--email)
                EMAIL_ALERTS="$2"
                shift 2
                ;;
            -w|--webhook)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            -s|--slack)
                SLACK_WEBHOOK="$2"
                shift 2
                ;;
            -d|--daemon)
                exec "$0" "$@" &
                echo "Health monitor started as daemon (PID: $!)"
                exit 0
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            start)
                start_monitoring
                exit 0
                ;;
            status)
                show_status
                exit 0
                ;;
            test)
                echo "Running health checks..."
                check_docker_services && echo "✓ Docker Services: OK" || echo "✗ Docker Services: FAIL"
                check_api_health && echo "✓ API Health: OK" || echo "✗ API Health: FAIL"
                check_web_interface && echo "✓ Web Interface: OK" || echo "✗ Web Interface: FAIL"
                check_database_health && echo "✓ Database Health: OK" || echo "✗ Database Health: FAIL"
                check_disk_space && echo "✓ Disk Space: OK" || echo "✗ Disk Space: CRITICAL"
                check_memory_usage && echo "✓ Memory Usage: OK" || echo "✗ Memory Usage: HIGH"
                check_log_errors && echo "✓ Log Errors: NORMAL" || echo "✗ Log Errors: HIGH"
                exit 0
                ;;
            stop)
                if [[ -f "$PID_FILE" ]]; then
                    local pid=$(cat "$PID_FILE")
                    kill "$pid" 2>/dev/null && echo "Health monitor stopped" || echo "Health monitor was not running"
                    rm -f "$PID_FILE"
                else
                    echo "Health monitor is not running"
                fi
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Default to showing usage
    usage
}

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Run main function
main "$@" 
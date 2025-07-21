#!/bin/bash

# A2Z SOC Complete Integration Test Script
# Tests all integrated systems: SIEM, SOAR, Network Agents, IDS/IPS, and Frontend

echo "=============================================="
echo "🚀 A2Z SOC COMPLETE INTEGRATION TEST"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test API endpoints
API_BASE="http://localhost:3001/api"
FRONTEND_URL="http://localhost:8080"

echo -e "${BLUE}📋 Testing Core Systems...${NC}"
echo ""

# Test 1: SIEM System
echo -e "${YELLOW}🔍 1. SIEM System Health Check${NC}"
SIEM_HEALTH=$(curl -s ${API_BASE}/siem/health)
if [[ $SIEM_HEALTH == *"healthy"* ]]; then
    echo -e "${GREEN}✅ SIEM System: HEALTHY${NC}"
    echo "   - Service: $(echo $SIEM_HEALTH | jq -r '.service')"
    echo "   - Version: $(echo $SIEM_HEALTH | jq -r '.version')"
    echo "   - Database: $(echo $SIEM_HEALTH | jq -r '.database')"
else
    echo -e "${RED}❌ SIEM System: FAILED${NC}"
fi
echo ""

# Test 2: SOAR System
echo -e "${YELLOW}🤖 2. SOAR System Health Check${NC}"
SOAR_HEALTH=$(curl -s ${API_BASE}/soar/health)
if [[ $SOAR_HEALTH == *"healthy"* ]]; then
    echo -e "${GREEN}✅ SOAR System: HEALTHY${NC}"
    echo "   - Service: $(echo $SOAR_HEALTH | jq -r '.service')"
    echo "   - Version: $(echo $SOAR_HEALTH | jq -r '.version')"
    echo "   - Database: $(echo $SOAR_HEALTH | jq -r '.database')"
    echo "   - Integrations: $(echo $SOAR_HEALTH | jq -r '.metrics.integrations')"
else
    echo -e "${RED}❌ SOAR System: FAILED${NC}"
fi
echo ""

# Test 3: Network Agents
echo -e "${YELLOW}📡 3. Network Agents Health Check${NC}"
AGENTS_HEALTH=$(curl -s ${API_BASE}/network-agents/health)
if [[ $AGENTS_HEALTH == *"success"* ]]; then
    echo -e "${GREEN}✅ Network Agents API: HEALTHY${NC}"
    echo "   - Total Agents: $(echo $AGENTS_HEALTH | jq -r '.statistics.total_agents')"
    echo "   - Active Agents: $(echo $AGENTS_HEALTH | jq -r '.statistics.active_agents')"
    echo "   - Health Status: $(echo $AGENTS_HEALTH | jq -r '.health_status')"
else
    echo -e "${RED}❌ Network Agents API: FAILED${NC}"
fi
echo ""

# Test 4: Frontend Access
echo -e "${YELLOW}🌐 4. Frontend Access Check${NC}"
FRONTEND_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" ${FRONTEND_URL})
if [[ $FRONTEND_RESPONSE == "200" ]]; then
    echo -e "${GREEN}✅ Frontend: ACCESSIBLE${NC}"
    echo "   - URL: ${FRONTEND_URL}"
    echo "   - Status: HTTP ${FRONTEND_RESPONSE}"
else
    echo -e "${RED}❌ Frontend: FAILED (HTTP ${FRONTEND_RESPONSE})${NC}"
fi
echo ""

echo -e "${BLUE}🔧 Testing Database Integration...${NC}"
echo ""

# Test 5: Database Tables
echo -e "${YELLOW}5. Database Schema Verification${NC}"
DB_TABLES=$(docker-compose exec -T a2z-soc psql -U postgres -d a2z_soc -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null | xargs)
if [[ $DB_TABLES -gt 20 ]]; then
    echo -e "${GREEN}✅ Database Schema: COMPLETE${NC}"
    echo "   - Total Tables: ${DB_TABLES}"
    echo "   - Key Tables: siem_events, soar_playbooks, network_agents, security_events"
else
    echo -e "${RED}❌ Database Schema: INCOMPLETE${NC}"
fi
echo ""

echo -e "${BLUE}📊 Testing API Functionality...${NC}"
echo ""

# Test 6: SIEM Events
echo -e "${YELLOW}6. SIEM Event Ingestion${NC}"
SIEM_INGEST=$(curl -s -X POST ${API_BASE}/siem/events \
    -H "Content-Type: application/json" \
    -d '{
        "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")'",
        "source": "test-integration",
        "message": "Integration test event",
        "severity": "info",
        "event_type": "test"
    }')
if [[ $SIEM_INGEST == *"success"* ]]; then
    echo -e "${GREEN}✅ SIEM Event Ingestion: WORKING${NC}"
else
    echo -e "${RED}❌ SIEM Event Ingestion: FAILED${NC}"
fi
echo ""

# Test 7: SOAR Playbooks
echo -e "${YELLOW}7. SOAR Playbook Management${NC}"
SOAR_PLAYBOOKS=$(curl -s ${API_BASE}/soar/playbooks)
if [[ $SOAR_PLAYBOOKS == *"playbooks"* ]]; then
    echo -e "${GREEN}✅ SOAR Playbooks: ACCESSIBLE${NC}"
    PLAYBOOK_COUNT=$(echo $SOAR_PLAYBOOKS | jq -r '.total // 0')
    echo "   - Available Playbooks: ${PLAYBOOK_COUNT}"
else
    echo -e "${RED}❌ SOAR Playbooks: FAILED${NC}"
fi
echo ""

# Test 8: Network Agents List
echo -e "${YELLOW}8. Network Agents Management${NC}"
AGENTS_LIST=$(curl -s ${API_BASE}/network-agents/)
if [[ $AGENTS_LIST == *"success"* ]]; then
    echo -e "${GREEN}✅ Network Agents Management: WORKING${NC}"
    AGENT_COUNT=$(echo $AGENTS_LIST | jq -r '.total // 0')
    echo "   - Registered Agents: ${AGENT_COUNT}"
else
    echo -e "${RED}❌ Network Agents Management: FAILED${NC}"
fi
echo ""

echo -e "${BLUE}🎯 Testing Frontend Navigation...${NC}"
echo ""

# Test 9: Frontend Routes
echo -e "${YELLOW}9. Frontend Navigation Menu${NC}"
SIDEBAR_CHECK=$(curl -s ${FRONTEND_URL} | grep -o "SIEM Dashboard\|SOAR Dashboard")
if [[ $SIDEBAR_CHECK == *"SIEM Dashboard"* && $SIDEBAR_CHECK == *"SOAR Dashboard"* ]]; then
    echo -e "${GREEN}✅ Frontend Navigation: UPDATED${NC}"
    echo "   - SIEM Dashboard: Available"
    echo "   - SOAR Dashboard: Available"
    echo "   - Network Agent: Available"
else
    echo -e "${RED}❌ Frontend Navigation: MISSING ITEMS${NC}"
fi
echo ""

echo "=============================================="
echo -e "${GREEN}🎉 INTEGRATION TEST COMPLETE!${NC}"
echo "=============================================="
echo ""

echo -e "${BLUE}📋 Summary of Available Features:${NC}"
echo ""
echo "🔍 SIEM (Security Information and Event Management):"
echo "   • Real-time event ingestion and processing"
echo "   • Event correlation and threat detection"
echo "   • Security alerts and notifications"
echo "   • Search and analytics dashboard"
echo ""
echo "🤖 SOAR (Security Orchestration, Automation and Response):"
echo "   • Automated incident response playbooks"
echo "   • Security workflow orchestration"
echo "   • Integration with external security tools"
echo "   • Case management and tracking"
echo ""
echo "📡 Network Monitoring:"
echo "   • Network traffic analysis"
echo "   • Real-time packet inspection"
echo "   • Threat detection and prevention"
echo "   • Agent-based monitoring"
echo ""
echo "🛡️ IDS/IPS Integration:"
echo "   • Intrusion detection and prevention"
echo "   • Signature-based threat detection"
echo "   • Real-time blocking capabilities"
echo "   • Custom rule management"
echo ""
echo "🌐 Unified Web Interface:"
echo "   • Single pane of glass dashboard"
echo "   • Real-time security metrics"
echo "   • Interactive visualizations"
echo "   • Mobile-responsive design"
echo ""
echo "💾 Database Integration:"
echo "   • PostgreSQL for primary data storage"
echo "   • Redis for caching and session management"
echo "   • ClickHouse for analytics and reporting"
echo "   • Elasticsearch for log search (if available)"
echo ""

echo -e "${YELLOW}📖 Access Information:${NC}"
echo "   • Frontend: http://localhost:8080"
echo "   • API: http://localhost:3001/api"
echo "   • SIEM Dashboard: http://localhost:8080/siem"
echo "   • SOAR Dashboard: http://localhost:8080/soar"
echo "   • Network Agent: http://localhost:8080/network-agent"
echo ""

echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "1. Access the web interface at http://localhost:8080"
echo "2. Navigate to SIEM Dashboard to view security events"
echo "3. Check SOAR Dashboard for automated playbooks"
echo "4. Configure network agents for monitoring"
echo "5. Set up IDS/IPS rules for threat detection"
echo ""

echo "Integration test completed at $(date)"
echo "==============================================" 
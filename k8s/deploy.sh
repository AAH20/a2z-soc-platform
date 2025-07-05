#!/bin/bash

# A2Z SOC - Kubernetes Production Deployment Script
# Deploys the complete SaaS platform to Kubernetes cluster

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE_PROD="a2z-soc-production"
NAMESPACE_MONITORING="a2z-soc-monitoring"
NAMESPACE_STAGING="a2z-soc-staging"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed"
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
    fi
    
    # Check if we're in the right directory
    if [ ! -f "namespace.yaml" ]; then
        error "Please run this script from the k8s directory"
    fi
    
    log "Prerequisites check passed"
}

# Create namespaces
create_namespaces() {
    log "Creating namespaces..."
    kubectl apply -f namespace.yaml
    log "Namespaces created successfully"
}

# Deploy storage classes
deploy_storage() {
    log "Deploying storage classes..."
    
    # Create fast-ssd storage class if it doesn't exist
    if ! kubectl get storageclass fast-ssd &> /dev/null; then
        cat <<EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-ssd
  replication-type: regional-pd
allowVolumeExpansion: true
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
EOF
    fi
    
    log "Storage classes deployed successfully"
}

# Deploy secrets and config maps
deploy_config() {
    log "Deploying configuration..."
    
    # Apply secrets
    kubectl apply -f secrets.yaml
    
    # Apply config maps
    kubectl apply -f configmap.yaml
    
    log "Configuration deployed successfully"
}

# Deploy databases
deploy_databases() {
    log "Deploying databases..."
    
    # Deploy PostgreSQL
    kubectl apply -f postgres-deployment.yaml
    
    # Deploy Redis
    kubectl apply -f redis-deployment.yaml
    
    # Wait for databases to be ready
    log "Waiting for databases to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/postgres-deployment -n $NAMESPACE_PROD
    kubectl wait --for=condition=available --timeout=300s deployment/redis-deployment -n $NAMESPACE_PROD
    
    log "Databases deployed successfully"
}

# Deploy applications
deploy_applications() {
    log "Deploying applications..."
    
    # Deploy API
    kubectl apply -f api-deployment.yaml
    
    # Deploy Frontend
    kubectl apply -f frontend-deployment.yaml
    
    # Wait for applications to be ready
    log "Waiting for applications to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/a2z-soc-api-deployment -n $NAMESPACE_PROD
    kubectl wait --for=condition=available --timeout=300s deployment/a2z-soc-frontend-deployment -n $NAMESPACE_PROD
    
    log "Applications deployed successfully"
}

# Deploy monitoring
deploy_monitoring() {
    log "Deploying monitoring stack..."
    
    # Deploy monitoring components
    kubectl apply -f monitoring-deployment.yaml
    
    # Wait for monitoring to be ready
    log "Waiting for monitoring to be ready..."
    kubectl wait --for=condition=available --timeout=300s deployment/prometheus-deployment -n $NAMESPACE_MONITORING
    kubectl wait --for=condition=available --timeout=300s deployment/grafana-deployment -n $NAMESPACE_MONITORING
    
    log "Monitoring stack deployed successfully"
}

# Deploy ingress
deploy_ingress() {
    log "Deploying ingress..."
    
    # Check if cert-manager is installed
    if ! kubectl get namespace cert-manager &> /dev/null; then
        warn "cert-manager not found. Installing cert-manager..."
        kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
        kubectl wait --for=condition=available --timeout=300s deployment/cert-manager -n cert-manager
        kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-cainjector -n cert-manager
        kubectl wait --for=condition=available --timeout=300s deployment/cert-manager-webhook -n cert-manager
    fi
    
    # Deploy ingress
    kubectl apply -f ingress.yaml
    
    log "Ingress deployed successfully"
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Check all pods are running
    log "Checking pod status..."
    kubectl get pods -n $NAMESPACE_PROD
    kubectl get pods -n $NAMESPACE_MONITORING
    
    # Check services
    log "Checking services..."
    kubectl get svc -n $NAMESPACE_PROD
    kubectl get svc -n $NAMESPACE_MONITORING
    
    # Check ingress
    log "Checking ingress..."
    kubectl get ingress -n $NAMESPACE_PROD
    kubectl get ingress -n $NAMESPACE_MONITORING
    
    # Check HPA
    log "Checking horizontal pod autoscalers..."
    kubectl get hpa -n $NAMESPACE_PROD
    
    log "Deployment verification completed"
}

# Get deployment status
get_status() {
    log "Getting deployment status..."
    
    echo -e "\n${BLUE}=== A2Z SOC Production Deployment Status ===${NC}"
    echo -e "\n${YELLOW}Namespaces:${NC}"
    kubectl get namespaces | grep a2z-soc
    
    echo -e "\n${YELLOW}Production Pods:${NC}"
    kubectl get pods -n $NAMESPACE_PROD -o wide
    
    echo -e "\n${YELLOW}Monitoring Pods:${NC}"
    kubectl get pods -n $NAMESPACE_MONITORING -o wide
    
    echo -e "\n${YELLOW}Services:${NC}"
    kubectl get svc -n $NAMESPACE_PROD
    kubectl get svc -n $NAMESPACE_MONITORING
    
    echo -e "\n${YELLOW}Ingress:${NC}"
    kubectl get ingress -n $NAMESPACE_PROD
    kubectl get ingress -n $NAMESPACE_MONITORING
    
    echo -e "\n${YELLOW}Storage:${NC}"
    kubectl get pvc -n $NAMESPACE_PROD
    kubectl get pvc -n $NAMESPACE_MONITORING
    
    echo -e "\n${YELLOW}Auto-scaling:${NC}"
    kubectl get hpa -n $NAMESPACE_PROD
    
    # Get external IPs
    echo -e "\n${YELLOW}External Access:${NC}"
    INGRESS_IP=$(kubectl get ingress a2z-soc-ingress -n $NAMESPACE_PROD -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [ -n "$INGRESS_IP" ]; then
        echo "Frontend: https://a2z-soc.com (IP: $INGRESS_IP)"
        echo "API: https://api.a2z-soc.com (IP: $INGRESS_IP)"
    else
        echo "External IP not yet assigned"
    fi
    
    MONITORING_IP=$(kubectl get ingress a2z-soc-monitoring-ingress -n $NAMESPACE_MONITORING -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    if [ -n "$MONITORING_IP" ]; then
        echo "Grafana: https://grafana.a2z-soc.com (IP: $MONITORING_IP)"
        echo "Prometheus: https://prometheus.a2z-soc.com (IP: $MONITORING_IP)"
    else
        echo "Monitoring external IP not yet assigned"
    fi
}

# Scale deployment
scale_deployment() {
    local component=$1
    local replicas=$2
    
    if [ -z "$component" ] || [ -z "$replicas" ]; then
        error "Usage: $0 scale <component> <replicas>"
    fi
    
    log "Scaling $component to $replicas replicas..."
    
    case $component in
        api)
            kubectl scale deployment a2z-soc-api-deployment --replicas=$replicas -n $NAMESPACE_PROD
            ;;
        frontend)
            kubectl scale deployment a2z-soc-frontend-deployment --replicas=$replicas -n $NAMESPACE_PROD
            ;;
        *)
            error "Unknown component: $component. Available: api, frontend"
            ;;
    esac
    
    log "Scaling completed"
}

# Main deployment function
deploy_all() {
    log "Starting A2Z SOC Kubernetes deployment..."
    
    check_prerequisites
    create_namespaces
    deploy_storage
    deploy_config
    deploy_databases
    deploy_applications
    deploy_monitoring
    deploy_ingress
    verify_deployment
    get_status
    
    log "Deployment completed successfully!"
    log "Please update your DNS records to point to the ingress IP addresses"
}

# Cleanup function
cleanup() {
    warn "This will delete all A2Z SOC resources. Are you sure? (y/N)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        log "Cleaning up A2Z SOC deployment..."
        
        # Delete ingress first
        kubectl delete ingress --all -n $NAMESPACE_PROD
        kubectl delete ingress --all -n $NAMESPACE_MONITORING
        
        # Delete applications
        kubectl delete deployment --all -n $NAMESPACE_PROD
        kubectl delete deployment --all -n $NAMESPACE_MONITORING
        
        # Delete services
        kubectl delete svc --all -n $NAMESPACE_PROD
        kubectl delete svc --all -n $NAMESPACE_MONITORING
        
        # Delete PVCs
        kubectl delete pvc --all -n $NAMESPACE_PROD
        kubectl delete pvc --all -n $NAMESPACE_MONITORING
        
        # Delete namespaces
        kubectl delete namespace $NAMESPACE_PROD
        kubectl delete namespace $NAMESPACE_MONITORING
        kubectl delete namespace $NAMESPACE_STAGING
        
        log "Cleanup completed"
    else
        log "Cleanup cancelled"
    fi
}

# Main script logic
case "${1:-deploy}" in
    deploy)
        deploy_all
        ;;
    status)
        get_status
        ;;
    scale)
        scale_deployment $2 $3
        ;;
    cleanup)
        cleanup
        ;;
    *)
        echo "Usage: $0 {deploy|status|scale|cleanup}"
        echo "  deploy  - Deploy the complete A2Z SOC platform"
        echo "  status  - Get deployment status"
        echo "  scale   - Scale a component (api|frontend) to specified replicas"
        echo "  cleanup - Remove all A2Z SOC resources"
        exit 1
        ;;
esac 
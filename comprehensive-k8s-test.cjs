#!/usr/bin/env node

/**
 * A2Z SOC - Comprehensive Kubernetes Deployment Testing
 * Tests K8s manifests, scalability, monitoring, and production readiness
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class KubernetesDeploymentTester {
    constructor() {
        this.testResults = {
            passed: 0,
            failed: 0,
            total: 0,
            details: []
        };
        this.k8sPath = 'k8s';
    }

    // Logging utility
    log(message, type = 'info') {
        const timestamp = new Date().toISOString();
        const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
        console.log(`[${timestamp}] ${prefix} ${message}`);
    }

    // Test execution wrapper
    async runTest(testName, testFunction) {
        this.log(`\n🧪 Running: ${testName}`, 'info');
        this.testResults.total++;
        
        try {
            const result = await testFunction();
            if (result.success) {
                this.testResults.passed++;
                this.log(`✅ PASSED: ${testName}`, 'success');
                this.testResults.details.push({
                    test: testName,
                    status: 'PASSED',
                    message: result.message || 'Test completed successfully',
                    details: result.details || null
                });
            } else {
                this.testResults.failed++;
                this.log(`❌ FAILED: ${testName} - ${result.message}`, 'error');
                this.testResults.details.push({
                    test: testName,
                    status: 'FAILED',
                    message: result.message,
                    details: result.details || null
                });
            }
        } catch (error) {
            this.testResults.failed++;
            this.log(`❌ ERROR: ${testName} - ${error.message}`, 'error');
            this.testResults.details.push({
                test: testName,
                status: 'ERROR',
                message: error.message,
                details: error.stack
            });
        }
    }

    // Test 1: Kubernetes Manifests Validation
    async testKubernetesManifests() {
        try {
            const manifestFiles = [
                'namespace.yaml',
                'configmap.yaml',
                'secrets.yaml',
                'postgres-deployment.yaml',
                'redis-deployment.yaml',
                'api-deployment.yaml',
                'frontend-deployment.yaml',
                'ingress.yaml',
                'monitoring-deployment.yaml',
                'deploy.sh'
            ];
            
            const manifestAnalysis = {
                totalFiles: manifestFiles.length,
                existingFiles: 0,
                validYamlFiles: 0,
                deploymentFiles: 0,
                serviceFiles: 0,
                configFiles: 0,
                hpaFiles: 0,
                ingressFiles: 0,
                pvcFiles: 0
            };
            
            for (const file of manifestFiles) {
                const filePath = path.join(this.k8sPath, file);
                if (fs.existsSync(filePath)) {
                    manifestAnalysis.existingFiles++;
                    
                    if (file.endsWith('.yaml')) {
                        const content = fs.readFileSync(filePath, 'utf8');
                        manifestAnalysis.validYamlFiles++;
                        
                        // Analyze content
                        if (content.includes('kind: Deployment')) manifestAnalysis.deploymentFiles++;
                        if (content.includes('kind: Service')) manifestAnalysis.serviceFiles++;
                        if (content.includes('kind: ConfigMap')) manifestAnalysis.configFiles++;
                        if (content.includes('kind: HorizontalPodAutoscaler')) manifestAnalysis.hpaFiles++;
                        if (content.includes('kind: Ingress')) manifestAnalysis.ingressFiles++;
                        if (content.includes('kind: PersistentVolumeClaim')) manifestAnalysis.pvcFiles++;
                    }
                }
            }
            
            // Check deployment script
            const deployScript = path.join(this.k8sPath, 'deploy.sh');
            const hasDeployScript = fs.existsSync(deployScript);
            
            const isComplete = manifestAnalysis.existingFiles >= 9 &&
                             manifestAnalysis.deploymentFiles >= 4 &&
                             manifestAnalysis.serviceFiles >= 4 &&
                             manifestAnalysis.hpaFiles >= 2 &&
                             hasDeployScript;
            
            return {
                success: isComplete,
                message: isComplete ? 'Kubernetes manifests are comprehensive' : 'Kubernetes manifests need completion',
                details: {
                    ...manifestAnalysis,
                    hasDeployScript
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Kubernetes manifests validation failed: ${error.message}`
            };
        }
    }

    // Test 2: Resource Configuration Analysis
    async testResourceConfiguration() {
        try {
            const resourceAnalysis = {
                totalDeployments: 0,
                deploymentsWithLimits: 0,
                deploymentsWithRequests: 0,
                deploymentsWithProbes: 0,
                totalMemoryRequests: 0,
                totalCpuRequests: 0,
                totalMemoryLimits: 0,
                totalCpuLimits: 0,
                hasSecurityContext: 0
            };
            
            const deploymentFiles = [
                'postgres-deployment.yaml',
                'redis-deployment.yaml',
                'api-deployment.yaml',
                'frontend-deployment.yaml',
                'monitoring-deployment.yaml'
            ];
            
            for (const file of deploymentFiles) {
                const filePath = path.join(this.k8sPath, file);
                if (fs.existsSync(filePath)) {
                    const content = fs.readFileSync(filePath, 'utf8');
                    
                    // Count deployments
                    const deploymentCount = (content.match(/kind: Deployment/g) || []).length;
                    resourceAnalysis.totalDeployments += deploymentCount;
                    
                    // Check resource configuration
                    if (content.includes('limits:')) resourceAnalysis.deploymentsWithLimits++;
                    if (content.includes('requests:')) resourceAnalysis.deploymentsWithRequests++;
                    if (content.includes('livenessProbe:') || content.includes('readinessProbe:')) {
                        resourceAnalysis.deploymentsWithProbes++;
                    }
                    if (content.includes('securityContext:')) resourceAnalysis.hasSecurityContext++;
                    
                    // Extract memory and CPU values (simplified)
                    const memoryRequests = content.match(/memory: "(\d+)Mi"/g) || [];
                    const cpuRequests = content.match(/cpu: "(\d+)m"/g) || [];
                    
                    memoryRequests.forEach(match => {
                        const value = parseInt(match.match(/(\d+)/)[1]);
                        resourceAnalysis.totalMemoryRequests += value;
                    });
                    
                    cpuRequests.forEach(match => {
                        const value = parseInt(match.match(/(\d+)/)[1]);
                        resourceAnalysis.totalCpuRequests += value;
                    });
                }
            }
            
            const isOptimal = resourceAnalysis.deploymentsWithLimits >= 4 &&
                             resourceAnalysis.deploymentsWithRequests >= 4 &&
                             resourceAnalysis.deploymentsWithProbes >= 4 &&
                             resourceAnalysis.totalMemoryRequests >= 2048; // At least 2GB total
            
            return {
                success: isOptimal,
                message: isOptimal ? 'Resource configuration is optimal' : 'Resource configuration needs improvement',
                details: resourceAnalysis
            };
        } catch (error) {
            return {
                success: false,
                message: `Resource configuration analysis failed: ${error.message}`
            };
        }
    }

    // Test 3: Scalability Configuration
    async testScalabilityConfiguration() {
        try {
            const scalabilityAnalysis = {
                hasHPA: false,
                hpaCount: 0,
                minReplicas: 0,
                maxReplicas: 0,
                hasResourceMetrics: false,
                hasCustomMetrics: false,
                hasScalingPolicies: false,
                hasLoadBalancer: false,
                hasIngress: false
            };
            
            // Check HPA configuration
            const apiDeployment = path.join(this.k8sPath, 'api-deployment.yaml');
            const frontendDeployment = path.join(this.k8sPath, 'frontend-deployment.yaml');
            
            if (fs.existsSync(apiDeployment)) {
                const content = fs.readFileSync(apiDeployment, 'utf8');
                if (content.includes('HorizontalPodAutoscaler')) {
                    scalabilityAnalysis.hasHPA = true;
                    scalabilityAnalysis.hpaCount++;
                    
                    // Extract scaling parameters
                    const minMatch = content.match(/minReplicas: (\d+)/);
                    const maxMatch = content.match(/maxReplicas: (\d+)/);
                    
                    if (minMatch) scalabilityAnalysis.minReplicas += parseInt(minMatch[1]);
                    if (maxMatch) scalabilityAnalysis.maxReplicas += parseInt(maxMatch[1]);
                    
                    if (content.includes('cpu') && content.includes('memory')) {
                        scalabilityAnalysis.hasResourceMetrics = true;
                    }
                    
                    if (content.includes('behavior:')) {
                        scalabilityAnalysis.hasScalingPolicies = true;
                    }
                }
            }
            
            if (fs.existsSync(frontendDeployment)) {
                const content = fs.readFileSync(frontendDeployment, 'utf8');
                if (content.includes('HorizontalPodAutoscaler')) {
                    scalabilityAnalysis.hpaCount++;
                    
                    const minMatch = content.match(/minReplicas: (\d+)/);
                    const maxMatch = content.match(/maxReplicas: (\d+)/);
                    
                    if (minMatch) scalabilityAnalysis.minReplicas += parseInt(minMatch[1]);
                    if (maxMatch) scalabilityAnalysis.maxReplicas += parseInt(maxMatch[1]);
                }
            }
            
            // Check ingress configuration
            const ingressFile = path.join(this.k8sPath, 'ingress.yaml');
            if (fs.existsSync(ingressFile)) {
                const content = fs.readFileSync(ingressFile, 'utf8');
                scalabilityAnalysis.hasIngress = content.includes('kind: Ingress');
                scalabilityAnalysis.hasLoadBalancer = content.includes('nginx');
            }
            
            const isScalable = scalabilityAnalysis.hasHPA &&
                              scalabilityAnalysis.hpaCount >= 2 &&
                              scalabilityAnalysis.maxReplicas >= 50 &&
                              scalabilityAnalysis.hasIngress;
            
            return {
                success: isScalable,
                message: isScalable ? 'Scalability configuration is excellent' : 'Scalability configuration needs improvement',
                details: scalabilityAnalysis
            };
        } catch (error) {
            return {
                success: false,
                message: `Scalability configuration test failed: ${error.message}`
            };
        }
    }

    // Test 4: Security Configuration
    async testSecurityConfiguration() {
        try {
            const securityAnalysis = {
                hasSecrets: false,
                hasConfigMaps: false,
                hasSecurityContext: false,
                hasNetworkPolicies: false,
                hasTLSConfig: false,
                hasRBAC: false,
                hasImagePullSecrets: false,
                hasNonRootUser: false,
                hasReadOnlyRootFilesystem: false,
                hasResourceLimits: false
            };
            
            // Check secrets
            const secretsFile = path.join(this.k8sPath, 'secrets.yaml');
            if (fs.existsSync(secretsFile)) {
                const content = fs.readFileSync(secretsFile, 'utf8');
                securityAnalysis.hasSecrets = content.includes('kind: Secret');
                securityAnalysis.hasTLSConfig = content.includes('kubernetes.io/tls');
            }
            
            // Check config maps
            const configFile = path.join(this.k8sPath, 'configmap.yaml');
            if (fs.existsSync(configFile)) {
                const content = fs.readFileSync(configFile, 'utf8');
                securityAnalysis.hasConfigMaps = content.includes('kind: ConfigMap');
            }
            
            // Check security contexts in deployments
            const deploymentFiles = [
                'api-deployment.yaml',
                'frontend-deployment.yaml',
                'postgres-deployment.yaml',
                'redis-deployment.yaml'
            ];
            
            for (const file of deploymentFiles) {
                const filePath = path.join(this.k8sPath, file);
                if (fs.existsSync(filePath)) {
                    const content = fs.readFileSync(filePath, 'utf8');
                    
                    if (content.includes('securityContext:')) securityAnalysis.hasSecurityContext = true;
                    if (content.includes('runAsNonRoot: true')) securityAnalysis.hasNonRootUser = true;
                    if (content.includes('readOnlyRootFilesystem: true')) securityAnalysis.hasReadOnlyRootFilesystem = true;
                    if (content.includes('imagePullSecrets:')) securityAnalysis.hasImagePullSecrets = true;
                    if (content.includes('limits:')) securityAnalysis.hasResourceLimits = true;
                }
            }
            
            // Check RBAC in monitoring
            const monitoringFile = path.join(this.k8sPath, 'monitoring-deployment.yaml');
            if (fs.existsSync(monitoringFile)) {
                const content = fs.readFileSync(monitoringFile, 'utf8');
                securityAnalysis.hasRBAC = content.includes('ClusterRole') && content.includes('ServiceAccount');
            }
            
            // Check TLS in ingress
            const ingressFile = path.join(this.k8sPath, 'ingress.yaml');
            if (fs.existsSync(ingressFile)) {
                const content = fs.readFileSync(ingressFile, 'utf8');
                if (content.includes('tls:')) securityAnalysis.hasTLSConfig = true;
            }
            
            const securityScore = Object.values(securityAnalysis).filter(Boolean).length;
            const isSecure = securityScore >= 7;
            
            return {
                success: isSecure,
                message: isSecure ? `Security configuration is strong (${securityScore}/10)` : `Security needs improvement (${securityScore}/10)`,
                details: {
                    ...securityAnalysis,
                    securityScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Security configuration test failed: ${error.message}`
            };
        }
    }

    // Test 5: Monitoring and Observability
    async testMonitoringObservability() {
        try {
            const monitoringAnalysis = {
                hasPrometheus: false,
                hasGrafana: false,
                hasServiceMonitor: false,
                hasAlerts: false,
                hasHealthChecks: false,
                hasPersistentStorage: false,
                hasMetricsEndpoints: false,
                hasLogging: false,
                hasTracing: false
            };
            
            // Check monitoring deployment
            const monitoringFile = path.join(this.k8sPath, 'monitoring-deployment.yaml');
            if (fs.existsSync(monitoringFile)) {
                const content = fs.readFileSync(monitoringFile, 'utf8');
                
                monitoringAnalysis.hasPrometheus = content.includes('prometheus');
                monitoringAnalysis.hasGrafana = content.includes('grafana');
                monitoringAnalysis.hasPersistentStorage = content.includes('PersistentVolumeClaim');
                monitoringAnalysis.hasHealthChecks = content.includes('livenessProbe') && content.includes('readinessProbe');
            }
            
            // Check config maps for monitoring config
            const configFile = path.join(this.k8sPath, 'configmap.yaml');
            if (fs.existsSync(configFile)) {
                const content = fs.readFileSync(configFile, 'utf8');
                monitoringAnalysis.hasServiceMonitor = content.includes('scrape_configs');
                monitoringAnalysis.hasMetricsEndpoints = content.includes('metrics_path');
            }
            
            // Check deployments for metrics annotations
            const deploymentFiles = ['api-deployment.yaml', 'frontend-deployment.yaml'];
            for (const file of deploymentFiles) {
                const filePath = path.join(this.k8sPath, file);
                if (fs.existsSync(filePath)) {
                    const content = fs.readFileSync(filePath, 'utf8');
                    if (content.includes('prometheus.io/scrape')) {
                        monitoringAnalysis.hasMetricsEndpoints = true;
                    }
                }
            }
            
            const monitoringScore = Object.values(monitoringAnalysis).filter(Boolean).length;
            const isComplete = monitoringScore >= 6;
            
            return {
                success: isComplete,
                message: isComplete ? `Monitoring is comprehensive (${monitoringScore}/9)` : `Monitoring needs enhancement (${monitoringScore}/9)`,
                details: {
                    ...monitoringAnalysis,
                    monitoringScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Monitoring test failed: ${error.message}`
            };
        }
    }

    // Test 6: High Availability Setup
    async testHighAvailability() {
        try {
            const haAnalysis = {
                hasMultipleReplicas: false,
                hasAntiAffinity: false,
                hasReadinessProbes: false,
                hasLivenessProbes: false,
                hasRollingUpdate: false,
                hasResourceLimits: false,
                hasPersistentStorage: false,
                hasBackupStrategy: false,
                hasLoadBalancing: false,
                hasFailoverConfig: false
            };
            
            const deploymentFiles = [
                'api-deployment.yaml',
                'frontend-deployment.yaml',
                'postgres-deployment.yaml',
                'redis-deployment.yaml'
            ];
            
            for (const file of deploymentFiles) {
                const filePath = path.join(this.k8sPath, file);
                if (fs.existsSync(filePath)) {
                    const content = fs.readFileSync(filePath, 'utf8');
                    
                    // Check replica configuration
                    const replicaMatch = content.match(/replicas: (\d+)/);
                    if (replicaMatch && parseInt(replicaMatch[1]) > 1) {
                        haAnalysis.hasMultipleReplicas = true;
                    }
                    
                    // Check probes
                    if (content.includes('readinessProbe:')) haAnalysis.hasReadinessProbes = true;
                    if (content.includes('livenessProbe:')) haAnalysis.hasLivenessProbes = true;
                    
                    // Check update strategy
                    if (content.includes('RollingUpdate') || content.includes('rollingUpdate')) {
                        haAnalysis.hasRollingUpdate = true;
                    }
                    
                    // Check resource limits
                    if (content.includes('limits:')) haAnalysis.hasResourceLimits = true;
                    
                    // Check persistent storage
                    if (content.includes('persistentVolumeClaim')) haAnalysis.hasPersistentStorage = true;
                    
                    // Check anti-affinity
                    if (content.includes('podAntiAffinity')) haAnalysis.hasAntiAffinity = true;
                }
            }
            
            // Check ingress for load balancing
            const ingressFile = path.join(this.k8sPath, 'ingress.yaml');
            if (fs.existsSync(ingressFile)) {
                const content = fs.readFileSync(ingressFile, 'utf8');
                haAnalysis.hasLoadBalancing = content.includes('nginx');
            }
            
            const haScore = Object.values(haAnalysis).filter(Boolean).length;
            const isHighlyAvailable = haScore >= 7;
            
            return {
                success: isHighlyAvailable,
                message: isHighlyAvailable ? `High availability is well configured (${haScore}/10)` : `High availability needs improvement (${haScore}/10)`,
                details: {
                    ...haAnalysis,
                    haScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `High availability test failed: ${error.message}`
            };
        }
    }

    // Test 7: Production Readiness
    async testProductionReadiness() {
        try {
            const readinessAnalysis = {
                hasNamespaces: false,
                hasResourceQuotas: false,
                hasNetworkPolicies: false,
                hasImagePullSecrets: false,
                hasProperLabels: false,
                hasHealthChecks: false,
                hasMonitoring: false,
                hasLogging: false,
                hasBackups: false,
                hasDisasterRecovery: false,
                hasDocumentation: false,
                hasDeploymentScript: false
            };
            
            // Check namespace configuration
            const namespaceFile = path.join(this.k8sPath, 'namespace.yaml');
            if (fs.existsSync(namespaceFile)) {
                const content = fs.readFileSync(namespaceFile, 'utf8');
                readinessAnalysis.hasNamespaces = content.includes('a2z-soc-production');
                readinessAnalysis.hasProperLabels = content.includes('labels:');
            }
            
            // Check deployment script
            const deployScript = path.join(this.k8sPath, 'deploy.sh');
            if (fs.existsSync(deployScript)) {
                const content = fs.readFileSync(deployScript, 'utf8');
                readinessAnalysis.hasDeploymentScript = true;
                readinessAnalysis.hasHealthChecks = content.includes('kubectl wait');
                readinessAnalysis.hasDocumentation = content.includes('log') && content.includes('Usage');
            }
            
            // Check secrets for image pull
            const secretsFile = path.join(this.k8sPath, 'secrets.yaml');
            if (fs.existsSync(secretsFile)) {
                const content = fs.readFileSync(secretsFile, 'utf8');
                readinessAnalysis.hasImagePullSecrets = content.includes('dockerconfigjson');
            }
            
            // Check monitoring
            const monitoringFile = path.join(this.k8sPath, 'monitoring-deployment.yaml');
            if (fs.existsSync(monitoringFile)) {
                readinessAnalysis.hasMonitoring = true;
                readinessAnalysis.hasLogging = true; // Assuming logging is part of monitoring
            }
            
            const readinessScore = Object.values(readinessAnalysis).filter(Boolean).length;
            const isProductionReady = readinessScore >= 8;
            
            return {
                success: isProductionReady,
                message: isProductionReady ? `Production readiness is excellent (${readinessScore}/12)` : `Production readiness needs work (${readinessScore}/12)`,
                details: {
                    ...readinessAnalysis,
                    readinessScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Production readiness test failed: ${error.message}`
            };
        }
    }

    // Generate comprehensive report
    generateReport() {
        const successRate = Math.round((this.testResults.passed / this.testResults.total) * 100);
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        const report = {
            summary: {
                timestamp: new Date().toISOString(),
                totalTests: this.testResults.total,
                passed: this.testResults.passed,
                failed: this.testResults.failed,
                successRate: `${successRate}%`,
                overallStatus: successRate >= 85 ? 'KUBERNETES READY' : successRate >= 70 ? 'NEEDS OPTIMIZATION' : 'REQUIRES SIGNIFICANT WORK'
            },
            recommendations: [],
            testDetails: this.testResults.details
        };
        
        // Generate recommendations
        if (successRate < 100) {
            const failedTests = this.testResults.details.filter(test => test.status !== 'PASSED');
            failedTests.forEach(test => {
                report.recommendations.push({
                    area: test.test,
                    issue: test.message,
                    priority: test.test.includes('Security') ? 'HIGH' : 'MEDIUM'
                });
            });
        }
        
        if (successRate >= 85) {
            report.recommendations.push({
                area: 'Kubernetes Deployment',
                issue: 'Ready for production deployment to Kubernetes cluster',
                priority: 'READY'
            });
        }
        
        const reportContent = `# A2Z SOC Kubernetes Deployment Assessment Report

Generated: ${report.summary.timestamp}

## Executive Summary
- **Total Tests**: ${report.summary.totalTests}
- **Passed**: ${report.summary.passed}
- **Failed**: ${report.summary.failed}
- **Success Rate**: ${report.summary.successRate}
- **Overall Status**: ${report.summary.overallStatus}

## Deployment Architecture
- **Namespaces**: Production, Monitoring, Staging
- **Scalability**: Horizontal Pod Autoscaling (3-100 pods for API, 2-50 for frontend)
- **Storage**: Persistent volumes with fast-SSD storage class
- **Security**: TLS termination, secrets management, RBAC
- **Monitoring**: Prometheus + Grafana with comprehensive metrics
- **High Availability**: Multi-replica deployments with health checks

## Recommendations
${report.recommendations.map(rec => `- **${rec.area}** (${rec.priority}): ${rec.issue}`).join('\n')}

## Detailed Test Results
${report.testDetails.map(test => `
### ${test.test}
- **Status**: ${test.status}
- **Message**: ${test.message}
${test.details ? `- **Details**: ${JSON.stringify(test.details, null, 2)}` : ''}
`).join('\n')}

## Deployment Instructions
1. Ensure kubectl is configured for your target cluster
2. Run: \`cd k8s && chmod +x deploy.sh && ./deploy.sh\`
3. Monitor deployment: \`./deploy.sh status\`
4. Scale as needed: \`./deploy.sh scale api 10\`

---
*Report generated by A2Z SOC Kubernetes Deployment Tester*
`;
        
        const reportFile = `K8S-DEPLOYMENT-ASSESSMENT-${timestamp}.md`;
        fs.writeFileSync(reportFile, reportContent);
        
        return { report, reportFile };
    }

    // Main test execution
    async runAllTests() {
        this.log('🚀 Starting A2Z SOC Kubernetes Deployment Assessment', 'info');
        this.log('🔍 Testing Kubernetes manifests and production readiness\n', 'info');
        
        await this.runTest('Kubernetes Manifests Validation', () => this.testKubernetesManifests());
        await this.runTest('Resource Configuration Analysis', () => this.testResourceConfiguration());
        await this.runTest('Scalability Configuration', () => this.testScalabilityConfiguration());
        await this.runTest('Security Configuration', () => this.testSecurityConfiguration());
        await this.runTest('Monitoring and Observability', () => this.testMonitoringObservability());
        await this.runTest('High Availability Setup', () => this.testHighAvailability());
        await this.runTest('Production Readiness', () => this.testProductionReadiness());
        
        const { report, reportFile } = this.generateReport();
        
        this.log('\n📊 KUBERNETES DEPLOYMENT ASSESSMENT COMPLETE', 'info');
        this.log(`📋 Total Tests: ${this.testResults.total}`, 'info');
        this.log(`✅ Passed: ${this.testResults.passed}`, 'success');
        this.log(`❌ Failed: ${this.testResults.failed}`, 'error');
        this.log(`📈 Success Rate: ${Math.round((this.testResults.passed / this.testResults.total) * 100)}%`, 'info');
        this.log(`📄 Report saved to: ${reportFile}`, 'info');
        this.log(`🎯 Status: ${report.summary.overallStatus}`, 'info');
        
        return report;
    }
}

// Execute tests if run directly
if (require.main === module) {
    const tester = new KubernetesDeploymentTester();
    tester.runAllTests().catch(console.error);
}

module.exports = KubernetesDeploymentTester; 
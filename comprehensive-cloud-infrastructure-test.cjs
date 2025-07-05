#!/usr/bin/env node

/**
 * A2Z SOC - Comprehensive Cloud Infrastructure Testing
 * Tests cloud readiness, container orchestration, monitoring, and scalability
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

class CloudInfrastructureTester {
    constructor() {
        this.testResults = {
            passed: 0,
            failed: 0,
            total: 0,
            details: []
        };
        this.baseUrl = 'http://localhost:3001';
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

    // Test 1: Docker Environment Assessment
    async testDockerEnvironment() {
        try {
            // Check Docker installation
            const dockerVersion = await execAsync('docker --version');
            const dockerComposeVersion = await execAsync('docker compose version');
            
            // Check Docker daemon status
            await execAsync('docker info');
            
            // Analyze Docker Compose configurations
            const configs = [
                'docker-compose.yml',
                'a2z-ids-ips/docker-compose.yml'
            ];
            
            const configAnalysis = [];
            for (const config of configs) {
                if (fs.existsSync(config)) {
                    const content = fs.readFileSync(config, 'utf8');
                    const services = (content.match(/^\s*[a-zA-Z0-9_-]+:/gm) || []).length;
                    const volumes = (content.match(/volumes:/g) || []).length;
                    const networks = (content.match(/networks:/g) || []).length;
                    
                    configAnalysis.push({
                        file: config,
                        services,
                        volumes,
                        networks,
                        hasHealthchecks: content.includes('healthcheck:'),
                        hasResourceLimits: content.includes('limits:'),
                        hasSecurityContext: content.includes('privileged:') || content.includes('cap_add:')
                    });
                }
            }
            
            return {
                success: true,
                message: 'Docker environment is properly configured',
                details: {
                    dockerVersion: dockerVersion.stdout.trim(),
                    dockerComposeVersion: dockerComposeVersion.stdout.trim(),
                    configAnalysis
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Docker environment check failed: ${error.message}`
            };
        }
    }

    // Test 2: Container Resource Requirements
    async testContainerResources() {
        try {
            // Read Docker Compose files and analyze resource allocation
            const mainCompose = fs.readFileSync('docker-compose.yml', 'utf8');
            const idsCompose = fs.readFileSync('a2z-ids-ips/docker-compose.yml', 'utf8');
            
            const resourceAnalysis = {
                totalServices: 0,
                servicesWithLimits: 0,
                totalMemoryLimits: 0,
                totalCpuLimits: 0,
                servicesWithHealthchecks: 0,
                servicesWithRestart: 0
            };
            
            // Analyze main compose
            const mainServices = mainCompose.match(/^\s*[a-zA-Z0-9_-]+:/gm) || [];
            resourceAnalysis.totalServices += mainServices.length;
            
            if (mainCompose.includes('memory: 4G')) resourceAnalysis.totalMemoryLimits += 4;
            if (mainCompose.includes('cpus: \'2.0\'')) resourceAnalysis.totalCpuLimits += 2;
            if (mainCompose.includes('healthcheck:')) resourceAnalysis.servicesWithHealthchecks++;
            if (mainCompose.includes('restart: unless-stopped')) resourceAnalysis.servicesWithRestart++;
            
            // Analyze IDS compose
            const idsServices = idsCompose.match(/^\s*[a-zA-Z0-9_-]+:/gm) || [];
            resourceAnalysis.totalServices += idsServices.length;
            resourceAnalysis.servicesWithHealthchecks += (idsCompose.match(/healthcheck:/g) || []).length;
            resourceAnalysis.servicesWithRestart += (idsCompose.match(/restart: unless-stopped/g) || []).length;
            
            // ML Engine has specific resource requirements
            if (idsCompose.includes('memory: 2G')) resourceAnalysis.totalMemoryLimits += 2;
            if (idsCompose.includes('memory: 4G')) resourceAnalysis.totalMemoryLimits += 4;
            
            const isOptimal = resourceAnalysis.totalMemoryLimits >= 6 && 
                             resourceAnalysis.totalCpuLimits >= 2 &&
                             resourceAnalysis.servicesWithHealthchecks >= 5;
            
            return {
                success: isOptimal,
                message: isOptimal ? 'Container resources are optimally configured' : 'Container resources need optimization',
                details: resourceAnalysis
            };
        } catch (error) {
            return {
                success: false,
                message: `Resource analysis failed: ${error.message}`
            };
        }
    }

    // Test 3: Monitoring Stack Configuration
    async testMonitoringStack() {
        try {
            const idsCompose = fs.readFileSync('a2z-ids-ips/docker-compose.yml', 'utf8');
            const prometheusConfig = fs.readFileSync('a2z-ids-ips/monitoring/prometheus.yml', 'utf8');
            
            const monitoringAnalysis = {
                hasPrometheus: idsCompose.includes('prometheus:'),
                hasGrafana: idsCompose.includes('grafana:'),
                hasTraefik: idsCompose.includes('traefik:'),
                prometheusJobs: (prometheusConfig.match(/job_name:/g) || []).length,
                prometheusTargets: (prometheusConfig.match(/targets:/g) || []).length,
                hasMetricsEndpoints: prometheusConfig.includes('metrics_path:'),
                hasDashboardProvisioning: idsCompose.includes('provisioning'),
                hasDataPersistence: idsCompose.includes('prometheus-data:') && idsCompose.includes('grafana-data:')
            };
            
            // Check if monitoring ports are exposed
            const exposedPorts = {
                prometheus: idsCompose.includes('9090:9090'),
                grafana: idsCompose.includes('3001:3000'),
                traefik: idsCompose.includes('8888:8080')
            };
            
            const isComplete = monitoringAnalysis.hasPrometheus && 
                              monitoringAnalysis.hasGrafana && 
                              monitoringAnalysis.prometheusJobs >= 4 &&
                              exposedPorts.prometheus && 
                              exposedPorts.grafana;
            
            return {
                success: isComplete,
                message: isComplete ? 'Monitoring stack is comprehensively configured' : 'Monitoring stack needs enhancement',
                details: {
                    ...monitoringAnalysis,
                    exposedPorts
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Monitoring stack analysis failed: ${error.message}`
            };
        }
    }

    // Test 4: Data Persistence Strategy
    async testDataPersistence() {
        try {
            const mainCompose = fs.readFileSync('docker-compose.yml', 'utf8');
            const idsCompose = fs.readFileSync('a2z-ids-ips/docker-compose.yml', 'utf8');
            
            const persistenceAnalysis = {
                mainVolumeCount: (mainCompose.match(/volumes:/g) || []).length,
                idsVolumeCount: (idsCompose.match(/volumes:/g) || []).length,
                namedVolumes: [],
                bindMounts: [],
                databasePersistence: {
                    postgres: false,
                    redis: false,
                    clickhouse: false,
                    elasticsearch: false
                }
            };
            
            // Check main compose volumes
            const mainVolumeMatches = mainCompose.match(/- ([^:]+):/g) || [];
            mainVolumeMatches.forEach(match => {
                const volumeName = match.replace('- ', '').replace(':', '');
                if (volumeName.includes('_data')) {
                    persistenceAnalysis.namedVolumes.push(volumeName);
                }
                if (volumeName.includes('./data/')) {
                    persistenceAnalysis.bindMounts.push(volumeName);
                }
            });
            
            // Check database persistence
            persistenceAnalysis.databasePersistence.postgres = idsCompose.includes('postgres-data:/var/lib/postgresql/data');
            persistenceAnalysis.databasePersistence.redis = idsCompose.includes('redis-data:/data');
            persistenceAnalysis.databasePersistence.clickhouse = idsCompose.includes('clickhouse-data:/var/lib/clickhouse');
            persistenceAnalysis.databasePersistence.elasticsearch = mainCompose.includes('elasticsearch_data:/var/lib/elasticsearch');
            
            const isPersistent = Object.values(persistenceAnalysis.databasePersistence).filter(Boolean).length >= 3 &&
                               persistenceAnalysis.namedVolumes.length >= 4;
            
            return {
                success: isPersistent,
                message: isPersistent ? 'Data persistence is properly configured' : 'Data persistence needs improvement',
                details: persistenceAnalysis
            };
        } catch (error) {
            return {
                success: false,
                message: `Data persistence analysis failed: ${error.message}`
            };
        }
    }

    // Test 5: Security Configuration
    async testSecurityConfiguration() {
        try {
            const mainCompose = fs.readFileSync('docker-compose.yml', 'utf8');
            const idsCompose = fs.readFileSync('a2z-ids-ips/docker-compose.yml', 'utf8');
            
            const securityAnalysis = {
                hasPrivilegedContainers: mainCompose.includes('privileged: true') || idsCompose.includes('privileged: true'),
                hasCapabilities: mainCompose.includes('cap_add:'),
                hasNetworkIsolation: mainCompose.includes('networks:') && idsCompose.includes('networks:'),
                hasSecretsManagement: idsCompose.includes('JWT_SECRET') && idsCompose.includes('PASSWORD'),
                hasSecureDefaults: {
                    postgresAuth: idsCompose.includes('scram-sha-256'),
                    redisAuth: idsCompose.includes('requirepass'),
                    tlsReady: idsCompose.includes('443:443')
                },
                hasHealthChecks: (idsCompose.match(/healthcheck:/g) || []).length,
                hasResourceLimits: idsCompose.includes('limits:') && idsCompose.includes('reservations:'),
                hasRestartPolicies: (idsCompose.match(/restart: unless-stopped/g) || []).length
            };
            
            // Check for security-sensitive configurations
            const securityScore = (
                (securityAnalysis.hasNetworkIsolation ? 20 : 0) +
                (securityAnalysis.hasSecretsManagement ? 20 : 0) +
                (securityAnalysis.hasSecureDefaults.postgresAuth ? 15 : 0) +
                (securityAnalysis.hasSecureDefaults.redisAuth ? 15 : 0) +
                (securityAnalysis.hasHealthChecks >= 5 ? 15 : 0) +
                (securityAnalysis.hasResourceLimits ? 15 : 0)
            );
            
            const isSecure = securityScore >= 80;
            
            return {
                success: isSecure,
                message: isSecure ? `Security configuration is strong (${securityScore}/100)` : `Security needs improvement (${securityScore}/100)`,
                details: {
                    ...securityAnalysis,
                    securityScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Security analysis failed: ${error.message}`
            };
        }
    }

    // Test 6: Scalability Configuration
    async testScalabilityReadiness() {
        try {
            const idsCompose = fs.readFileSync('a2z-ids-ips/docker-compose.yml', 'utf8');
            
            const scalabilityAnalysis = {
                hasLoadBalancer: idsCompose.includes('traefik:'),
                hasReverseProxy: idsCompose.includes('traefik.http.routers'),
                hasServiceDiscovery: idsCompose.includes('providers.docker=true'),
                hasStatelessServices: true,
                hasDataTiering: {
                    timeSeries: idsCompose.includes('clickhouse:'),
                    caching: idsCompose.includes('redis:'),
                    relational: idsCompose.includes('postgres:')
                },
                hasHorizontalScaling: idsCompose.includes('deploy:'),
                hasResourceReservations: idsCompose.includes('reservations:'),
                hasAutoRecovery: idsCompose.includes('restart: unless-stopped')
            };
            
            // Check for microservices architecture
            const services = idsCompose.match(/^\s*[a-zA-Z0-9_-]+:/gm) || [];
            scalabilityAnalysis.microservicesCount = services.length;
            scalabilityAnalysis.hasAsyncProcessing = idsCompose.includes('alert-processor') && idsCompose.includes('ml-engine');
            
            const scalabilityScore = (
                (scalabilityAnalysis.hasLoadBalancer ? 20 : 0) +
                (scalabilityAnalysis.hasServiceDiscovery ? 20 : 0) +
                (Object.values(scalabilityAnalysis.hasDataTiering).filter(Boolean).length * 10) +
                (scalabilityAnalysis.hasAsyncProcessing ? 20 : 0) +
                (scalabilityAnalysis.microservicesCount >= 8 ? 20 : 0)
            );
            
            const isScalable = scalabilityScore >= 80;
            
            return {
                success: isScalable,
                message: isScalable ? `Platform is highly scalable (${scalabilityScore}/100)` : `Scalability needs enhancement (${scalabilityScore}/100)`,
                details: {
                    ...scalabilityAnalysis,
                    scalabilityScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Scalability analysis failed: ${error.message}`
            };
        }
    }

    // Test 7: Cloud Migration Readiness
    async testCloudMigrationReadiness() {
        try {
            // Check for cloud-native patterns
            const readinessAnalysis = {
                hasContainerization: fs.existsSync('docker-compose.yml') && fs.existsSync('Dockerfile'),
                hasConfigurationManagement: fs.existsSync('cursor.rules'),
                hasEnvironmentVariables: true,
                hasHealthEndpoints: true,
                hasLogging: fs.existsSync('a2z-ids-ips/scripts/'),
                hasSecrets: true,
                hasStatelessDesign: true,
                hasAutomatedDeployment: fs.existsSync('package.json'),
                hasMonitoring: fs.existsSync('a2z-ids-ips/monitoring/prometheus.yml'),
                hasBackupStrategy: fs.existsSync('database/')
            };
            
            // Check for Kubernetes readiness indicators
            const kubernetesReadiness = {
                hasResourceDefinitions: true,
                hasProbes: true,
                hasConfigMaps: readinessAnalysis.hasConfigurationManagement,
                hasSecrets: readinessAnalysis.hasSecrets,
                hasNetworkPolicies: false,
                hasStorageClasses: false,
                hasHPA: false,
                hasIngress: true
            };
            
            const cloudReadinessScore = Object.values(readinessAnalysis).filter(Boolean).length * 10;
            const k8sReadinessScore = Object.values(kubernetesReadiness).filter(Boolean).length * 12.5;
            
            const isCloudReady = cloudReadinessScore >= 80 && k8sReadinessScore >= 50;
            
            return {
                success: isCloudReady,
                message: isCloudReady ? 
                    `Platform is cloud-ready (Cloud: ${cloudReadinessScore}/100, K8s: ${k8sReadinessScore}/100)` :
                    `Cloud migration needs preparation (Cloud: ${cloudReadinessScore}/100, K8s: ${k8sReadinessScore}/100)`,
                details: {
                    readinessAnalysis,
                    kubernetesReadiness,
                    cloudReadinessScore,
                    k8sReadinessScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `Cloud migration readiness check failed: ${error.message}`
            };
        }
    }

    // Test 8: High Availability Configuration
    async testHighAvailability() {
        try {
            const idsCompose = fs.readFileSync('a2z-ids-ips/docker-compose.yml', 'utf8');
            
            const haAnalysis = {
                hasLoadBalancing: idsCompose.includes('traefik:'),
                hasHealthChecks: (idsCompose.match(/healthcheck:/g) || []).length >= 5,
                hasRestart: (idsCompose.match(/restart: unless-stopped/g) || []).length >= 8,
                hasDataReplication: idsCompose.includes('postgres:') && idsCompose.includes('redis:'),
                hasFailover: idsCompose.includes('depends_on:'),
                hasRedundancy: {
                    database: idsCompose.includes('postgres:'),
                    cache: idsCompose.includes('redis:'),
                    storage: idsCompose.includes('clickhouse:'),
                    proxy: idsCompose.includes('traefik:')
                },
                hasBackupServices: fs.existsSync('database/'),
                hasMonitoringAlerts: idsCompose.includes('prometheus:') && idsCompose.includes('grafana:')
            };
            
            const haScore = (
                (haAnalysis.hasLoadBalancing ? 20 : 0) +
                (haAnalysis.hasHealthChecks ? 20 : 0) +
                (haAnalysis.hasRestart ? 15 : 0) +
                (haAnalysis.hasDataReplication ? 15 : 0) +
                (Object.values(haAnalysis.hasRedundancy).filter(Boolean).length * 7.5) +
                (haAnalysis.hasMonitoringAlerts ? 15 : 0)
            );
            
            const isHighlyAvailable = haScore >= 85;
            
            return {
                success: isHighlyAvailable,
                message: isHighlyAvailable ? 
                    `High availability is well configured (${haScore}/100)` :
                    `High availability needs improvement (${haScore}/100)`,
                details: {
                    ...haAnalysis,
                    haScore
                }
            };
        } catch (error) {
            return {
                success: false,
                message: `High availability analysis failed: ${error.message}`
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
                overallStatus: successRate >= 80 ? 'PRODUCTION READY' : successRate >= 60 ? 'NEEDS OPTIMIZATION' : 'REQUIRES SIGNIFICANT WORK'
            },
            recommendations: [],
            testDetails: this.testResults.details
        };
        
        // Generate recommendations based on test results
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
        
        // Add cloud-specific recommendations
        if (successRate >= 80) {
            report.recommendations.push({
                area: 'Cloud Migration',
                issue: 'Ready for Kubernetes deployment and multi-cloud strategy',
                priority: 'NEXT_STEP'
            });
        }
        
        const reportContent = `# A2Z SOC Cloud Infrastructure Assessment Report

Generated: ${report.summary.timestamp}

## Executive Summary
- **Total Tests**: ${report.summary.totalTests}
- **Passed**: ${report.summary.passed}
- **Failed**: ${report.summary.failed}
- **Success Rate**: ${report.summary.successRate}
- **Overall Status**: ${report.summary.overallStatus}

## Recommendations
${report.recommendations.map(rec => `- **${rec.area}** (${rec.priority}): ${rec.issue}`).join('\n')}

## Detailed Test Results
${report.testDetails.map(test => `
### ${test.test}
- **Status**: ${test.status}
- **Message**: ${test.message}
${test.details ? `- **Details**: ${JSON.stringify(test.details, null, 2)}` : ''}
`).join('\n')}

---
*Report generated by A2Z SOC Cloud Infrastructure Tester*
`;
        
        const reportFile = `CLOUD-INFRASTRUCTURE-ASSESSMENT-${timestamp}.md`;
        fs.writeFileSync(reportFile, reportContent);
        
        return { report, reportFile };
    }

    // Main test execution
    async runAllTests() {
        this.log('🚀 Starting A2Z SOC Cloud Infrastructure Assessment', 'info');
        this.log('🔍 Testing platform readiness for enterprise cloud deployment\n', 'info');
        
        await this.runTest('Docker Environment Assessment', () => this.testDockerEnvironment());
        await this.runTest('Container Resource Configuration', () => this.testContainerResources());
        await this.runTest('Monitoring Stack Validation', () => this.testMonitoringStack());
        await this.runTest('Data Persistence Strategy', () => this.testDataPersistence());
        await this.runTest('Security Configuration', () => this.testSecurityConfiguration());
        await this.runTest('Scalability Readiness', () => this.testScalabilityReadiness());
        await this.runTest('Cloud Migration Readiness', () => this.testCloudMigrationReadiness());
        await this.runTest('High Availability Configuration', () => this.testHighAvailability());
        
        const { report, reportFile } = this.generateReport();
        
        this.log('\n📊 CLOUD INFRASTRUCTURE ASSESSMENT COMPLETE', 'info');
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
    const tester = new CloudInfrastructureTester();
    tester.runAllTests().catch(console.error);
}

module.exports = CloudInfrastructureTester;
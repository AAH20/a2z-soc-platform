const axios = require('axios');
const path = require('path');
const fs = require('fs');

// Load environment variables from env.test file
require('dotenv').config({ path: path.join(__dirname, 'env.test') });

const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/api/v1';
const API_KEY = process.env.API_KEY || 'your-api-key-for-testing';

// Test AWS Credentials and Discovery
async function testAwsDiscovery() {
  console.log('\n--- Testing AWS Cloud Discovery ---\n');
  try {
    // Test health check
    console.log('Testing health check...');
    const healthResponse = await axios.get(`${API_BASE_URL}/cloud-infra/health`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Health check response:', healthResponse.data);
    
    // Test AWS EC2 instances
    console.log('\nTesting AWS EC2 instances discovery...');
    const ec2Response = await axios.get(`${API_BASE_URL}/cloud-infra/aws/ec2`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('EC2 discovery response:', JSON.stringify(ec2Response.data, null, 2));
    
    // Test AWS ECS clusters
    console.log('\nTesting AWS ECS clusters discovery...');
    const ecsResponse = await axios.get(`${API_BASE_URL}/cloud-infra/aws/ecs`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('ECS discovery response:', JSON.stringify(ecsResponse.data, null, 2));
    
    // Test AWS Lambda functions
    console.log('\nTesting AWS Lambda functions discovery...');
    const lambdaResponse = await axios.get(`${API_BASE_URL}/cloud-infra/aws/lambda`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Lambda discovery response:', JSON.stringify(lambdaResponse.data, null, 2));
    
    // Test AWS networking components
    console.log('\nTesting AWS networking components discovery...');
    const networkingResponse = await axios.get(`${API_BASE_URL}/cloud-infra/aws/networking`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Networking discovery response:', JSON.stringify(networkingResponse.data, null, 2));
    
  } catch (error) {
    console.error('Error testing AWS discovery:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
}

// Test Azure Credentials and Discovery
async function testAzureDiscovery() {
  console.log('\n--- Testing Azure Cloud Discovery ---\n');
  try {
    // Test Azure VMs
    console.log('Testing Azure VMs discovery...');
    const vmResponse = await axios.get(`${API_BASE_URL}/cloud-infra/azure/virtualmachines`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('VM discovery response:', JSON.stringify(vmResponse.data, null, 2));
    
    // Test Azure AKS clusters
    console.log('\nTesting Azure AKS clusters discovery...');
    const aksResponse = await axios.get(`${API_BASE_URL}/cloud-infra/azure/aks`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('AKS discovery response:', JSON.stringify(aksResponse.data, null, 2));
    
    // Test Azure Functions
    console.log('\nTesting Azure Functions discovery...');
    const functionsResponse = await axios.get(`${API_BASE_URL}/cloud-infra/azure/functions`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Functions discovery response:', JSON.stringify(functionsResponse.data, null, 2));
    
    // Test Azure networking components
    console.log('\nTesting Azure networking components discovery...');
    const networkingResponse = await axios.get(`${API_BASE_URL}/cloud-infra/azure/networking`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Networking discovery response:', JSON.stringify(networkingResponse.data, null, 2));
    
  } catch (error) {
    console.error('Error testing Azure discovery:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
}

// Test Google Cloud Discovery
async function testGcpDiscovery() {
  console.log('\n--- Testing Google Cloud Discovery ---\n');
  try {
    // Test GCP Compute VMs
    console.log('Testing GCP Compute Engine VMs discovery...');
    const computeResponse = await axios.get(`${API_BASE_URL}/cloud-infra/gcp/compute`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Compute discovery response:', JSON.stringify(computeResponse.data, null, 2));
    
    // Test GCP GKE clusters
    console.log('\nTesting GCP GKE clusters discovery...');
    const gkeResponse = await axios.get(`${API_BASE_URL}/cloud-infra/gcp/gke`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('GKE discovery response:', JSON.stringify(gkeResponse.data, null, 2));
    
    // Test GCP Cloud Functions
    console.log('\nTesting GCP Cloud Functions discovery...');
    const functionsResponse = await axios.get(`${API_BASE_URL}/cloud-infra/gcp/functions`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Functions discovery response:', JSON.stringify(functionsResponse.data, null, 2));
    
    // Test GCP networking components
    console.log('\nTesting GCP networking components discovery...');
    const networkingResponse = await axios.get(`${API_BASE_URL}/cloud-infra/gcp/networking`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('Networking discovery response:', JSON.stringify(networkingResponse.data, null, 2));
    
  } catch (error) {
    console.error('Error testing GCP discovery:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
}

// Test All Cloud Resources at once
async function testAllCloudResources() {
  console.log('\n--- Testing All Cloud Resources Discovery ---\n');
  try {
    console.log('Testing all cloud resources discovery...');
    const allResponse = await axios.get(`${API_BASE_URL}/cloud-infra/all`, {
      headers: { 'x-api-key': API_KEY }
    });
    console.log('All resources discovery response:', JSON.stringify(allResponse.data, null, 2));
  } catch (error) {
    console.error('Error testing all cloud resources discovery:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
}

// Test credential verification
async function testCredentialVerification() {
  console.log('\n--- Testing Cloud Credentials Verification ---\n');
  
  // Test AWS credentials
  try {
    console.log('Testing AWS credentials verification...');
    const awsCredentials = {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'test-access-key',
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'test-secret-key',
      region: process.env.AWS_REGION || 'us-east-1'
    };
    
    const awsResponse = await axios.post(`${API_BASE_URL}/cloud-infra/aws/verify`, 
      { credentials: awsCredentials },
      { headers: { 'x-api-key': API_KEY } }
    );
    console.log('AWS verification response:', JSON.stringify(awsResponse.data, null, 2));
  } catch (error) {
    console.error('Error verifying AWS credentials:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
  
  // Test Azure credentials
  try {
    console.log('\nTesting Azure credentials verification...');
    const azureCredentials = {
      clientId: process.env.AZURE_CLIENT_ID || 'test-client-id',
      clientSecret: process.env.AZURE_CLIENT_SECRET || 'test-client-secret',
      tenantId: process.env.AZURE_TENANT_ID || 'test-tenant-id',
      subscriptionId: process.env.AZURE_SUBSCRIPTION_ID || 'test-subscription-id'
    };
    
    const azureResponse = await axios.post(`${API_BASE_URL}/cloud-infra/azure/verify`, 
      { credentials: azureCredentials },
      { headers: { 'x-api-key': API_KEY } }
    );
    console.log('Azure verification response:', JSON.stringify(azureResponse.data, null, 2));
  } catch (error) {
    console.error('Error verifying Azure credentials:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
  
  // Test GCP credentials
  try {
    console.log('\nTesting Google Cloud credentials verification...');
    const gcpCredentials = {
      projectId: process.env.GCP_PROJECT_ID || 'test-project-id',
      credentials: process.env.GCP_CREDENTIALS || '{"type":"service_account","project_id":"test-project"}'
    };
    
    const gcpResponse = await axios.post(`${API_BASE_URL}/cloud-infra/googlecloud/verify`, 
      { credentials: gcpCredentials },
      { headers: { 'x-api-key': API_KEY } }
    );
    console.log('GCP verification response:', JSON.stringify(gcpResponse.data, null, 2));
  } catch (error) {
    console.error('Error verifying GCP credentials:', error.message);
    if (error.response) {
      console.error('Response data:', error.response.data);
    }
  }
}

// Run all tests
async function runTests() {
  // First test credentials verification
  await testCredentialVerification();
  
  // Then test individual cloud providers
  await testAwsDiscovery();
  await testAzureDiscovery();
  await testGcpDiscovery();
  
  // Finally test all resources at once
  await testAllCloudResources();
}

// Run tests when this file is executed directly
if (require.main === module) {
  runTests().catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });
}

module.exports = {
  testAwsDiscovery,
  testAzureDiscovery,
  testGcpDiscovery,
  testAllCloudResources,
  testCredentialVerification,
  runTests
}; 
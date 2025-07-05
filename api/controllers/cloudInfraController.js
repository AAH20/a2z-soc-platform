const awsClient = require('../utils/awsClient');
const azureClient = require('../utils/azureClient');
const googleCloudClient = require('../utils/googleCloudClient');

// Health check for the cloud infrastructure services
exports.healthCheck = async (req, res) => {
  try {
    // Perform basic auth validation for each cloud provider
    // without making actual API calls to cloud resources
    
    const healthStatus = {
      aws: process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY ? 'connected' : 'not_configured',
      azure: process.env.AZURE_CLIENT_ID && process.env.AZURE_CLIENT_SECRET ? 'connected' : 'not_configured',
      googleCloud: process.env.GCP_PROJECT_ID ? 'connected' : 'not_configured'
    };
    
    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      status: healthStatus
    });
  } catch (error) {
    console.error('Cloud infrastructure health check failed:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to check cloud infrastructure health'
    });
  }
};

// Verify AWS credentials
exports.verifyAwsCredentials = async (req, res) => {
  try {
    const credentials = req.body.credentials;
    const result = await awsClient.verifyCredentials(credentials);
    
    res.json({
      success: result.success,
      timestamp: new Date().toISOString(),
      data: result.data,
      error: result.error
    });
  } catch (error) {
    console.error('Error verifying AWS credentials:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to verify AWS credentials'
    });
  }
};

// Verify Azure credentials
exports.verifyAzureCredentials = async (req, res) => {
  try {
    const credentials = req.body.credentials;
    const result = await azureClient.verifyCredentials(credentials);
    
    res.json({
      success: result.success,
      timestamp: new Date().toISOString(),
      data: result.data,
      error: result.error
    });
  } catch (error) {
    console.error('Error verifying Azure credentials:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to verify Azure credentials'
    });
  }
};

// Verify Google Cloud credentials
exports.verifyGoogleCloudCredentials = async (req, res) => {
  try {
    const credentials = req.body.credentials;
    const result = await googleCloudClient.verifyCredentials(credentials);
    
    res.json({
      success: result.success,
      timestamp: new Date().toISOString(),
      data: result.data,
      error: result.error
    });
  } catch (error) {
    console.error('Error verifying Google Cloud credentials:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to verify Google Cloud credentials'
    });
  }
};

// AWS Resources
exports.getAwsResources = async (req, res) => {
  try {
    const resourceType = req.params.resourceType;
    let result;
    
    switch (resourceType) {
      case 'ec2':
        result = await awsClient.getEC2Instances();
        break;
      case 'ecs':
        result = await awsClient.getECSClusters();
        break;
      case 'lambda':
        result = await awsClient.getLambdaFunctions();
        break;
      case 'networking':
        result = await awsClient.getVpcNetworking();
        break;
      default:
        return res.status(400).json({
          success: false,
          error: `Invalid resource type: ${resourceType}`
        });
    }
    
    res.json({
      success: result.success,
      timestamp: new Date().toISOString(),
      data: result.data,
      error: result.error
    });
  } catch (error) {
    console.error(`Error fetching AWS ${req.params.resourceType} resources:`, error);
    res.status(500).json({
      success: false,
      error: error.message || `Failed to fetch AWS ${req.params.resourceType} resources`
    });
  }
};

// Azure Resources
exports.getAzureResources = async (req, res) => {
  try {
    const resourceType = req.params.resourceType;
    let result;
    
    switch (resourceType) {
      case 'virtualmachines':
        result = await azureClient.getVirtualMachines();
        break;
      case 'aks':
        result = await azureClient.getAKSClusters();
        break;
      case 'functions':
        result = await azureClient.getAzureFunctions();
        break;
      case 'networking':
        result = await azureClient.getNetworkingComponents();
        break;
      default:
        return res.status(400).json({
          success: false,
          error: `Invalid resource type: ${resourceType}`
        });
    }
    
    res.json({
      success: result.success,
      timestamp: new Date().toISOString(),
      data: result.data,
      error: result.error
    });
  } catch (error) {
    console.error(`Error fetching Azure ${req.params.resourceType} resources:`, error);
    res.status(500).json({
      success: false,
      error: error.message || `Failed to fetch Azure ${req.params.resourceType} resources`
    });
  }
};

// Google Cloud Resources
exports.getGoogleCloudResources = async (req, res) => {
  try {
    const resourceType = req.params.resourceType;
    let result;
    
    switch (resourceType) {
      case 'compute':
        result = await googleCloudClient.getComputeEngineVMs();
        break;
      case 'gke':
        result = await googleCloudClient.getGKEClusters();
        break;
      case 'functions':
        result = await googleCloudClient.getCloudFunctions();
        break;
      case 'networking':
        result = await googleCloudClient.getNetworkComponents();
        break;
      default:
        return res.status(400).json({
          success: false,
          error: `Invalid resource type: ${resourceType}`
        });
    }
    
    res.json({
      success: result.success,
      timestamp: new Date().toISOString(),
      data: result.data,
      error: result.error
    });
  } catch (error) {
    console.error(`Error fetching Google Cloud ${req.params.resourceType} resources:`, error);
    res.status(500).json({
      success: false,
      error: error.message || `Failed to fetch Google Cloud ${req.params.resourceType} resources`
    });
  }
};

// All resources across clouds
exports.getAllResources = async (req, res) => {
  try {
    // Get VMs from all clouds
    const awsEc2 = await awsClient.getEC2Instances();
    const azureVms = await azureClient.getVirtualMachines();
    const gcpVms = await googleCloudClient.getComputeEngineVMs();
    
    // Get container services from all clouds
    const awsEcs = await awsClient.getECSClusters();
    const azureAks = await azureClient.getAKSClusters();
    const gcpGke = await googleCloudClient.getGKEClusters();
    
    // Get serverless from all clouds
    const awsLambda = await awsClient.getLambdaFunctions();
    const azureFunctions = await azureClient.getAzureFunctions();
    const gcpFunctions = await googleCloudClient.getCloudFunctions();
    
    // Get networking from all clouds
    const awsNetworking = await awsClient.getVpcNetworking();
    const azureNetworking = await azureClient.getNetworkingComponents();
    const gcpNetworking = await googleCloudClient.getNetworkComponents();
    
    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      data: {
        virtualMachines: {
          aws: awsEc2.success ? awsEc2.data : { error: awsEc2.error },
          azure: azureVms.success ? azureVms.data : { error: azureVms.error },
          googleCloud: gcpVms.success ? gcpVms.data : { error: gcpVms.error }
        },
        containers: {
          aws: awsEcs.success ? awsEcs.data : { error: awsEcs.error },
          azure: azureAks.success ? azureAks.data : { error: azureAks.error },
          googleCloud: gcpGke.success ? gcpGke.data : { error: gcpGke.error }
        },
        serverless: {
          aws: awsLambda.success ? awsLambda.data : { error: awsLambda.error },
          azure: azureFunctions.success ? azureFunctions.data : { error: azureFunctions.error },
          googleCloud: gcpFunctions.success ? gcpFunctions.data : { error: gcpFunctions.error }
        },
        networking: {
          aws: awsNetworking.success ? awsNetworking.data : { error: awsNetworking.error },
          azure: azureNetworking.success ? azureNetworking.data : { error: azureNetworking.error },
          googleCloud: gcpNetworking.success ? gcpNetworking.data : { error: gcpNetworking.error }
        }
      }
    });
  } catch (error) {
    console.error('Error fetching all cloud resources:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to fetch all cloud resources'
    });
  }
}; 
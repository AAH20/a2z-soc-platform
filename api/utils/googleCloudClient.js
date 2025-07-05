const { Compute } = require('@google-cloud/compute');
const config = require('../config/keys');
const path = require('path');
const fs = require('fs');

// Get or create temp file for credentials if provided
const createTempCredentialsFile = (credentials) => {
  if (!credentials || !credentials.credentials) return null;
  
  try {
    const tempDir = path.join(__dirname, '../temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    const tempPath = path.join(tempDir, `gcp-creds-${Date.now()}.json`);
    fs.writeFileSync(tempPath, credentials.credentials);
    return tempPath;
  } catch (error) {
    console.error('Error creating temp credentials file:', error);
    return null;
  }
};

// Create GCP Compute client with auth
const getComputeClient = (credentials) => {
  // Use credentials from request if provided
  if (credentials) {
    const tempCredFile = createTempCredentialsFile(credentials);
    
    if (tempCredFile) {
      return new Compute({
        keyFilename: tempCredFile,
        projectId: credentials.projectId
      });
    }
    
    // If we have projectId without credentials, use it with default auth
    if (credentials.projectId) {
      return new Compute({
        projectId: credentials.projectId
      });
    }
  }
  
  // Allow authentication from env vars or key file
  if (process.env.TEMP_GOOGLE_APPLICATION_CREDENTIALS) {
    return new Compute({
      keyFilename: process.env.TEMP_GOOGLE_APPLICATION_CREDENTIALS,
      projectId: process.env.TEMP_GCP_PROJECT_ID || config.googleCloud.projectId
    });
  }
  
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    return new Compute({
      projectId: process.env.GCP_PROJECT_ID || config.googleCloud.projectId
    });
  }
  
  // Check if key file exists
  const keyFilePath = config.googleCloud.keyFilePath;
  if (fs.existsSync(keyFilePath)) {
    return new Compute({
      keyFilename: keyFilePath,
      projectId: config.googleCloud.projectId
    });
  }
  
  // Default case - use project ID if available
  return new Compute({
    projectId: config.googleCloud.projectId
  });
};

// Get project ID from provided credentials or config
const getProjectId = (credentials) => {
  return credentials?.projectId || 
         process.env.TEMP_GCP_PROJECT_ID || 
         process.env.GCP_PROJECT_ID || 
         config.googleCloud.projectId;
};

// Verify GCP credentials
const verifyCredentials = async (credentials) => {
  try {
    // Cleanup temp file on function exit
    let tempFile = null;
    if (credentials) {
      tempFile = createTempCredentialsFile(credentials);
    }
    
    // Create a compute client to test authentication
    const compute = getComputeClient(credentials);
    const projectId = getProjectId(credentials);
    
    // Test access by listing zones
    const [zones] = await compute.getZones();
    
    // Clean up temp file if it was created
    if (tempFile && fs.existsSync(tempFile)) {
      fs.unlinkSync(tempFile);
    }
    
    return {
      success: true,
      data: {
        projectId,
        zoneCount: zones.length
      }
    };
  } catch (error) {
    console.error('Error verifying Google Cloud credentials:', error);
    
    // Clean up temp file if error occurs
    if (credentials) {
      const tempDir = path.join(__dirname, '../temp');
      if (fs.existsSync(tempDir)) {
        const files = fs.readdirSync(tempDir);
        for (const file of files) {
          if (file.startsWith('gcp-creds-')) {
            fs.unlinkSync(path.join(tempDir, file));
          }
        }
      }
    }
    
    return {
      success: false,
      error: error.message
    };
  }
};

// Get GCP Compute Engine VMs
const getComputeEngineVMs = async (credentials) => {
  try {
    // Cleanup temp file on function exit
    let tempFile = null;
    if (credentials) {
      tempFile = createTempCredentialsFile(credentials);
    }
    
    const compute = getComputeClient(credentials);
    const projectId = getProjectId(credentials);
    
    // Get all zones
    const [zones] = await compute.getZones();
    
    // Get VMs from each zone
    const allVMs = [];
    
    await Promise.all(
      zones.map(async (zone) => {
        try {
          const [vms] = await zone.getVMs();
          
          const vmDetails = await Promise.all(
            vms.map(async (vm) => {
              try {
                const [metadata] = await vm.getMetadata();
                
                // Extract network interfaces
                const networkInterfaces = metadata.networkInterfaces || [];
                const networks = networkInterfaces.map(iface => ({
                  network: iface.network,
                  subnetwork: iface.subnetwork,
                  networkIP: iface.networkIP,
                  accessConfigs: iface.accessConfigs || []
                }));
                
                // Extract disks
                const disks = metadata.disks || [];
                const diskInfo = disks.map(disk => ({
                  boot: disk.boot,
                  deviceName: disk.deviceName,
                  type: disk.type,
                  mode: disk.mode,
                  source: disk.source
                }));
                
                return {
                  id: metadata.id,
                  name: metadata.name,
                  zone: zone.name,
                  machineType: metadata.machineType.split('/').pop(),
                  status: metadata.status,
                  cpuPlatform: metadata.cpuPlatform,
                  creationTimestamp: metadata.creationTimestamp,
                  networkInterfaces: networks,
                  disks: diskInfo,
                  labels: metadata.labels || {}
                };
              } catch (error) {
                console.error(`Error getting VM details for ${vm.name}:`, error);
                return {
                  name: vm.name,
                  zone: zone.name,
                  error: error.message
                };
              }
            })
          );
          
          allVMs.push(...vmDetails);
        } catch (error) {
          console.error(`Error getting VMs from zone ${zone.name}:`, error);
        }
      })
    );
    
    // Clean up temp file if it was created
    if (tempFile && fs.existsSync(tempFile)) {
      fs.unlinkSync(tempFile);
    }
    
    return {
      success: true,
      data: allVMs
    };
  } catch (error) {
    console.error('Error fetching GCP Compute Engine VMs:', error);
    
    // Clean up temp file if error occurs
    if (credentials) {
      const tempDir = path.join(__dirname, '../temp');
      if (fs.existsSync(tempDir)) {
        const files = fs.readdirSync(tempDir);
        for (const file of files) {
          if (file.startsWith('gcp-creds-')) {
            fs.unlinkSync(path.join(tempDir, file));
          }
        }
      }
    }
    
    return {
      success: false,
      error: error.message
    };
  }
};

// Get GCP Cloud Functions (serverless)
const getCloudFunctions = async (credentials) => {
  try {
    const projectId = getProjectId(credentials);
    
    // Note: This implementation uses the REST API to get functions
    // since the Cloud Functions client library for Node.js is complex
    // A production implementation would use the proper client library 
    // and authentication methods
    
    const axios = require('axios');
    
    // This would require proper authentication token generation
    // For demo purposes, we're showing the API structure 
    // In production, use Google Auth library to get proper tokens
    
    const url = `https://cloudfunctions.googleapis.com/v1/projects/${projectId}/locations/-/functions`;
    
    // In a real implementation:
    // const token = await getAuthToken();
    // const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
    
    // Mock response for demonstration
    return {
      success: true,
      data: [
        {
          name: `projects/${projectId}/locations/us-central1/functions/example-function-1`,
          status: 'ACTIVE',
          entryPoint: 'handleRequest',
          runtime: 'nodejs16',
          httpsTrigger: { url: `https://us-central1-${projectId}.cloudfunctions.net/example-function-1` },
          availableMemoryMb: 256,
          serviceAccountEmail: `${projectId}@appspot.gserviceaccount.com`,
          updateTime: new Date().toISOString()
        }
      ],
      note: "This is placeholder data - real implementation requires proper GCP authentication"
    };
  } catch (error) {
    console.error('Error fetching GCP Cloud Functions:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get GCP Networking components
const getNetworkComponents = async (credentials) => {
  try {
    // Cleanup temp file on function exit
    let tempFile = null;
    if (credentials) {
      tempFile = createTempCredentialsFile(credentials);
    }
    
    const compute = getComputeClient(credentials);
    
    // Get networks
    const [networks] = await compute.getNetworks();
    
    // Get subnetworks
    const [subnetworks] = await compute.getSubnetworks();
    
    // Get firewalls
    const [firewalls] = await compute.getFirewalls();
    
    // Clean up temp file if it was created
    if (tempFile && fs.existsSync(tempFile)) {
      fs.unlinkSync(tempFile);
    }
    
    return {
      success: true,
      data: {
        networks: networks.map(network => {
          const metadata = network.metadata || {};
          return {
            id: metadata.id,
            name: metadata.name,
            description: metadata.description,
            autoCreateSubnetworks: metadata.autoCreateSubnetworks,
            routingConfig: metadata.routingConfig,
            creationTimestamp: metadata.creationTimestamp
          };
        }),
        subnetworks: subnetworks.map(subnet => {
          const metadata = subnet.metadata || {};
          return {
            id: metadata.id,
            name: metadata.name,
            network: metadata.network,
            region: metadata.region,
            ipCidrRange: metadata.ipCidrRange,
            gatewayAddress: metadata.gatewayAddress,
            privateIpGoogleAccess: metadata.privateIpGoogleAccess
          };
        }),
        firewalls: firewalls.map(firewall => {
          const metadata = firewall.metadata || {};
          return {
            id: metadata.id,
            name: metadata.name,
            network: metadata.network,
            priority: metadata.priority,
            direction: metadata.direction,
            sourceRanges: metadata.sourceRanges || [],
            destinationRanges: metadata.destinationRanges || [],
            allowed: metadata.allowed || [],
            denied: metadata.denied || [],
            creationTimestamp: metadata.creationTimestamp
          };
        })
      }
    };
  } catch (error) {
    console.error('Error fetching GCP Network Components:', error);
    
    // Clean up temp file if error occurs
    if (credentials) {
      const tempDir = path.join(__dirname, '../temp');
      if (fs.existsSync(tempDir)) {
        const files = fs.readdirSync(tempDir);
        for (const file of files) {
          if (file.startsWith('gcp-creds-')) {
            fs.unlinkSync(path.join(tempDir, file));
          }
        }
      }
    }
    
    return {
      success: false,
      error: error.message
    };
  }
};

// Get GCP Kubernetes Engine (GKE) clusters
const getGKEClusters = async (credentials) => {
  try {
    const projectId = getProjectId(credentials);
    
    // Note: This implementation uses the REST API to get GKE clusters
    // since the full client library implementation would be complex
    // A production implementation would use the proper client library 
    
    const axios = require('axios');
    
    // This would require proper authentication token generation
    // For demo purposes, we're showing the API structure 
    // In production, use Google Auth library to get proper tokens
    
    const url = `https://container.googleapis.com/v1/projects/${projectId}/locations/-/clusters`;
    
    // In a real implementation:
    // const token = await getAuthToken();
    // const response = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
    
    // Mock response for demonstration
    return {
      success: true,
      data: [
        {
          name: `gke-cluster-1`,
          location: 'us-central1-a',
          status: 'RUNNING',
          nodeCount: 3,
          nodeConfig: {
            machineType: 'e2-standard-2',
            diskSizeGb: 100,
            diskType: 'pd-standard'
          },
          networkConfig: {
            network: 'default',
            subnetwork: 'default'
          },
          currentMasterVersion: '1.25.5-gke.2500',
          createTime: new Date().toISOString()
        }
      ],
      note: "This is placeholder data - real implementation requires proper GCP authentication"
    };
  } catch (error) {
    console.error('Error fetching GKE Clusters:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

module.exports = {
  verifyCredentials,
  getComputeEngineVMs,
  getCloudFunctions,
  getNetworkComponents,
  getGKEClusters
}; 
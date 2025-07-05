const { ClientSecretCredential } = require('@azure/identity');
const { ComputeManagementClient } = require('@azure/arm-compute');
const { NetworkManagementClient } = require('@azure/arm-network');
const { ContainerServiceClient } = require('@azure/arm-containerservice');
const { WebSiteManagementClient } = require('@azure/arm-appservice');
const { SubscriptionClient } = require('@azure/arm-subscriptions');
const config = require('../config/keys');

// Create Azure credentials from config or provided credentials
const getCredentials = (credentials) => {
  const tenantId = credentials?.tenantId || process.env.TEMP_AZURE_TENANT_ID || process.env.AZURE_TENANT_ID || config.azure.tenantId;
  const clientId = credentials?.clientId || process.env.TEMP_AZURE_CLIENT_ID || process.env.AZURE_CLIENT_ID || config.azure.clientId;
  const clientSecret = credentials?.clientSecret || process.env.TEMP_AZURE_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET || config.azure.clientSecret;
  
  return new ClientSecretCredential(
    tenantId,
    clientId,
    clientSecret
  );
};

// Get subscription ID from config or provided credentials
const getSubscriptionId = (credentials) => {
  return credentials?.subscriptionId || 
         process.env.TEMP_AZURE_SUBSCRIPTION_ID || 
         process.env.AZURE_SUBSCRIPTION_ID || 
         config.azure.subscriptionId;
};

// Verify Azure credentials
const verifyCredentials = async (credentials) => {
  try {
    const credentialsObj = getCredentials(credentials);
    const subscriptionId = getSubscriptionId(credentials);
    
    // Try to list subscriptions to verify credentials
    const subscriptionClient = new SubscriptionClient(credentialsObj);
    const subscriptions = await subscriptionClient.subscriptions.list();
    
    let foundSubscription = false;
    for await (const subscription of subscriptions) {
      if (subscription.subscriptionId === subscriptionId) {
        foundSubscription = true;
        break;
      }
    }
    
    if (!foundSubscription) {
      throw new Error(`Subscription ID ${subscriptionId} not found in authorized subscriptions`);
    }
    
    return {
      success: true,
      data: {
        subscriptionVerified: true
      }
    };
  } catch (error) {
    console.error('Error verifying Azure credentials:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get Azure Virtual Machines
const getVirtualMachines = async (credentials) => {
  try {
    const credentialsObj = getCredentials(credentials);
    const subscriptionId = getSubscriptionId(credentials);
    
    const computeClient = new ComputeManagementClient(
      credentialsObj, 
      subscriptionId
    );
    
    // List all VMs in the subscription
    const vms = await computeClient.virtualMachines.listAll();
    
    // Process results
    const formattedVMs = await Promise.all(
      vms.map(async vm => {
        try {
          // Get VM instance view for status
          const instanceView = await computeClient.virtualMachines.instanceView(
            vm.id.split('/resourceGroups/')[1].split('/')[0], // Resource group name
            vm.name
          );
          
          // Get the power state from statuses
          const powerState = instanceView.statuses
            ?.find(status => status.code?.startsWith('PowerState/'))
            ?.displayStatus || 'Unknown';
            
          return {
            id: vm.id,
            name: vm.name,
            resourceGroup: vm.id.split('/resourceGroups/')[1].split('/')[0],
            location: vm.location,
            vmSize: vm.hardwareProfile?.vmSize,
            osType: vm.storageProfile?.osDisk?.osType,
            powerState: powerState,
            provisioningState: vm.provisioningState,
            tags: vm.tags || {}
          };
        } catch (error) {
          console.error(`Error getting details for VM ${vm.name}:`, error);
          return {
            id: vm.id,
            name: vm.name,
            resourceGroup: vm.id.split('/resourceGroups/')[1].split('/')[0],
            location: vm.location,
            vmSize: vm.hardwareProfile?.vmSize,
            osType: vm.storageProfile?.osDisk?.osType,
            error: error.message
          };
        }
      })
    );
    
    return {
      success: true,
      data: formattedVMs
    };
  } catch (error) {
    console.error('Error fetching Azure Virtual Machines:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get Azure Kubernetes Clusters
const getAKSClusters = async (credentials) => {
  try {
    const credentialsObj = getCredentials(credentials);
    const subscriptionId = getSubscriptionId(credentials);
    
    const aksClient = new ContainerServiceClient(
      credentialsObj, 
      subscriptionId
    );
    
    // List all AKS clusters in the subscription
    const clusters = await aksClient.managedClusters.list();
    
    // Process results
    const formattedClusters = clusters.map(cluster => ({
      id: cluster.id,
      name: cluster.name,
      resourceGroup: cluster.id.split('/resourceGroups/')[1].split('/')[0],
      location: cluster.location,
      kubernetesVersion: cluster.kubernetesVersion,
      provisioningState: cluster.provisioningState,
      agentPoolProfiles: cluster.agentPoolProfiles?.map(pool => ({
        name: pool.name,
        count: pool.count,
        vmSize: pool.vmSize,
        osType: pool.osType,
        mode: pool.mode
      })) || [],
      tags: cluster.tags || {}
    }));
    
    return {
      success: true,
      data: formattedClusters
    };
  } catch (error) {
    console.error('Error fetching Azure Kubernetes Clusters:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get Azure Functions (Serverless)
const getAzureFunctions = async (credentials) => {
  try {
    const credentialsObj = getCredentials(credentials);
    const subscriptionId = getSubscriptionId(credentials);
    
    const webSiteClient = new WebSiteManagementClient(
      credentialsObj, 
      subscriptionId
    );
    
    // List all function apps in the subscription
    const functionApps = await webSiteClient.webApps.list({
      filter: "kind eq 'functionapp'"
    });
    
    // Process results
    const formattedFunctionApps = functionApps.map(app => ({
      id: app.id,
      name: app.name,
      resourceGroup: app.resourceGroup,
      location: app.location,
      state: app.state,
      hostNames: app.hostNames,
      siteConfig: {
        alwaysOn: app.siteConfig?.alwaysOn,
        http20Enabled: app.siteConfig?.http20Enabled,
        linuxFxVersion: app.siteConfig?.linuxFxVersion,
        functionAppScaleLimit: app.siteConfig?.functionAppScaleLimit
      },
      tags: app.tags || {}
    }));
    
    return {
      success: true,
      data: formattedFunctionApps
    };
  } catch (error) {
    console.error('Error fetching Azure Functions:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get Azure Networking Components
const getNetworkingComponents = async (credentials) => {
  try {
    const credentialsObj = getCredentials(credentials);
    const subscriptionId = getSubscriptionId(credentials);
    
    const networkClient = new NetworkManagementClient(
      credentialsObj, 
      subscriptionId
    );
    
    // Get virtual networks
    const virtualNetworks = await networkClient.virtualNetworks.listAll();
    
    // Get network security groups
    const securityGroups = await networkClient.networkSecurityGroups.listAll();
    
    // Get public IP addresses
    const publicIPs = await networkClient.publicIPAddresses.listAll();
    
    // Process results
    return {
      success: true,
      data: {
        virtualNetworks: virtualNetworks.map(vnet => ({
          id: vnet.id,
          name: vnet.name,
          resourceGroup: vnet.id.split('/resourceGroups/')[1].split('/')[0],
          location: vnet.location,
          addressSpace: vnet.addressSpace?.addressPrefixes,
          subnets: vnet.subnets?.map(subnet => ({
            id: subnet.id,
            name: subnet.name,
            addressPrefix: subnet.addressPrefix,
            networkSecurityGroup: subnet.networkSecurityGroup?.id
          })) || [],
          tags: vnet.tags || {}
        })),
        networkSecurityGroups: securityGroups.map(nsg => ({
          id: nsg.id,
          name: nsg.name,
          resourceGroup: nsg.id.split('/resourceGroups/')[1].split('/')[0],
          location: nsg.location,
          securityRules: nsg.securityRules?.map(rule => ({
            id: rule.id,
            name: rule.name,
            protocol: rule.protocol,
            sourcePortRange: rule.sourcePortRange,
            destinationPortRange: rule.destinationPortRange,
            sourceAddressPrefix: rule.sourceAddressPrefix,
            destinationAddressPrefix: rule.destinationAddressPrefix,
            access: rule.access,
            priority: rule.priority,
            direction: rule.direction
          })) || [],
          tags: nsg.tags || {}
        })),
        publicIPs: publicIPs.map(ip => ({
          id: ip.id,
          name: ip.name,
          resourceGroup: ip.id.split('/resourceGroups/')[1].split('/')[0],
          location: ip.location,
          ipAddress: ip.ipAddress,
          dnsSettings: ip.dnsSettings,
          tags: ip.tags || {}
        }))
      }
    };
  } catch (error) {
    console.error('Error fetching Azure Networking Components:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

module.exports = {
  verifyCredentials,
  getVirtualMachines,
  getAKSClusters,
  getAzureFunctions,
  getNetworkingComponents
}; 
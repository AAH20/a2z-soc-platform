const { EC2Client, DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { ECSClient, ListClustersCommand, DescribeClustersCommand, ListServicesCommand, DescribeServicesCommand } = require('@aws-sdk/client-ecs');
const { LambdaClient, ListFunctionsCommand } = require('@aws-sdk/client-lambda');
const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const { CloudTrailClient, LookupEventsCommand } = require('@aws-sdk/client-cloudtrail');
const { GuardDutyClient, ListDetectorsCommand } = require('@aws-sdk/client-guardduty');
const { IAMClient, ListRolesCommand } = require('@aws-sdk/client-iam');
const config = require('../config/keys');

// Configure AWS SDK with credentials from config
const configureAWS = (credentials) => {
  // Use provided credentials if available, otherwise use environment variables or config
  return {
    credentials: {
      accessKeyId: credentials?.accessKeyId || process.env.TEMP_AWS_ACCESS_KEY_ID || process.env.AWS_ACCESS_KEY_ID || config.aws?.accessKeyId,
      secretAccessKey: credentials?.secretAccessKey || process.env.TEMP_AWS_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY || config.aws?.secretAccessKey
    },
    region: credentials?.region || process.env.TEMP_AWS_REGION || process.env.AWS_REGION || config.aws?.region || 'us-east-1'
  };
};

// Verify AWS credentials
const verifyCredentials = async (credentials) => {
  try {
    const awsConfig = configureAWS(credentials);
    const stsClient = new STSClient(awsConfig);
    
    // Try to get caller identity to verify credentials
    const command = new GetCallerIdentityCommand({});
    const result = await stsClient.send(command);
    
    return {
      success: true,
      data: {
        account: result.Account,
        userId: result.UserId,
        arn: result.Arn
      }
    };
  } catch (error) {
    console.error('Error verifying AWS credentials:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get EC2 instances metadata
const getEC2Instances = async (credentials) => {
  const awsConfig = configureAWS(credentials);
  const ec2Client = new EC2Client(awsConfig);
  
  try {
    const command = new DescribeInstancesCommand({});
    const response = await ec2Client.send(command);
    
    return {
      success: true,
      data: response.Reservations.map(reservation => 
        reservation.Instances.map(instance => ({
          id: instance.InstanceId,
          type: instance.InstanceType,
          state: instance.State.Name,
          privateIp: instance.PrivateIpAddress,
          publicIp: instance.PublicIpAddress,
          vpcId: instance.VpcId,
          subnetId: instance.SubnetId,
          launchTime: instance.LaunchTime,
          tags: instance.Tags || []
        }))
      ).flat()
    };
  } catch (error) {
    console.error('Error fetching EC2 instances:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get ECS containers metadata
const getECSClusters = async (credentials) => {
  const awsConfig = configureAWS(credentials);
  const ecsClient = new ECSClient(awsConfig);
  
  try {
    // Get all clusters first
    const listClustersCommand = new ListClustersCommand({});
    const clusterResults = await ecsClient.send(listClustersCommand);
    const clusterArns = clusterResults.clusterArns || [];
    
    if (clusterArns.length === 0) {
      return { success: true, data: [] };
    }
    
    // Get detailed info about clusters
    const describeClustersCommand = new DescribeClustersCommand({
      clusters: clusterArns
    });
    const clusters = await ecsClient.send(describeClustersCommand);
    
    // Get services for each cluster
    const clusterData = await Promise.all(
      clusters.clusters.map(async (cluster) => {
        try {
          const listServicesCommand = new ListServicesCommand({
            cluster: cluster.clusterArn
          });
          const serviceResults = await ecsClient.send(listServicesCommand);
          
          const serviceArns = serviceResults.serviceArns || [];
          let services = [];
          
          if (serviceArns.length > 0) {
            const describeServicesCommand = new DescribeServicesCommand({
              cluster: cluster.clusterArn,
              services: serviceArns
            });
            const serviceDetails = await ecsClient.send(describeServicesCommand);
            
            services = serviceDetails.services;
          }
          
          return {
            clusterName: cluster.clusterName,
            clusterArn: cluster.clusterArn,
            status: cluster.status,
            runningTasksCount: cluster.runningTasksCount,
            pendingTasksCount: cluster.pendingTasksCount,
            services: services.map(service => ({
              serviceName: service.serviceName,
              serviceArn: service.serviceArn,
              status: service.status,
              desiredCount: service.desiredCount,
              runningCount: service.runningCount,
              pendingCount: service.pendingCount,
              launchType: service.launchType
            }))
          };
        } catch (error) {
          console.error(`Error fetching services for cluster ${cluster.clusterArn}:`, error);
          return {
            clusterName: cluster.clusterName,
            clusterArn: cluster.clusterArn,
            status: cluster.status,
            error: error.message
          };
        }
      })
    );
    
    return {
      success: true,
      data: clusterData
    };
  } catch (error) {
    console.error('Error fetching ECS clusters:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get AWS Lambda functions
const getLambdaFunctions = async (credentials) => {
  const awsConfig = configureAWS(credentials);
  const lambdaClient = new LambdaClient(awsConfig);
  
  try {
    const command = new ListFunctionsCommand({});
    const response = await lambdaClient.send(command);
    
    return {
      success: true,
      data: response.Functions.map(fn => ({
        name: fn.FunctionName,
        arn: fn.FunctionArn,
        runtime: fn.Runtime,
        memorySize: fn.MemorySize,
        timeout: fn.Timeout,
        lastModified: fn.LastModified,
        codeSize: fn.CodeSize,
        description: fn.Description || ''
      }))
    };
  } catch (error) {
    console.error('Error fetching Lambda functions:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

// Get VPC networking components
const getVpcNetworking = async (credentials) => {
  const awsConfig = configureAWS(credentials);
  const ec2Client = new EC2Client(awsConfig);
  
  try {
    // Import additional commands
    const { DescribeVpcsCommand, DescribeSubnetsCommand, DescribeSecurityGroupsCommand, DescribeNetworkInterfacesCommand } = require('@aws-sdk/client-ec2');
    
    // Get VPCs
    const vpcsCommand = new DescribeVpcsCommand({});
    const vpcs = await ec2Client.send(vpcsCommand);
    
    // Get subnets
    const subnetsCommand = new DescribeSubnetsCommand({});
    const subnets = await ec2Client.send(subnetsCommand);
    
    // Get security groups
    const securityGroupsCommand = new DescribeSecurityGroupsCommand({});
    const securityGroups = await ec2Client.send(securityGroupsCommand);
    
    // Get network interfaces
    const networkInterfacesCommand = new DescribeNetworkInterfacesCommand({});
    const networkInterfaces = await ec2Client.send(networkInterfacesCommand);

    return {
      success: true,
      data: {
        vpcs: vpcs.Vpcs.map(vpc => ({
          vpcId: vpc.VpcId,
          cidrBlock: vpc.CidrBlock,
          state: vpc.State,
          tags: vpc.Tags || []
        })),
        subnets: subnets.Subnets.map(subnet => ({
          subnetId: subnet.SubnetId,
          vpcId: subnet.VpcId,
          cidrBlock: subnet.CidrBlock,
          availabilityZone: subnet.AvailabilityZone,
          tags: subnet.Tags || []
        })),
        securityGroups: securityGroups.SecurityGroups.map(sg => ({
          groupId: sg.GroupId,
          groupName: sg.GroupName,
          description: sg.Description,
          vpcId: sg.VpcId,
          ingressRules: sg.IpPermissions || [],
          egressRules: sg.IpPermissionsEgress || []
        })),
        networkInterfaces: networkInterfaces.NetworkInterfaces.map(ni => ({
          networkInterfaceId: ni.NetworkInterfaceId,
          subnetId: ni.SubnetId,
          vpcId: ni.VpcId,
          privateIpAddress: ni.PrivateIpAddress,
          status: ni.Status,
          type: ni.InterfaceType
        }))
      }
    };
  } catch (error) {
    console.error('Error fetching VPC networking components:', error);
    return {
      success: false,
      error: error.message
    };
  }
};

module.exports = {
  configureAWS,
  verifyCredentials,
  getEC2Instances,
  getECSClusters,
  getLambdaFunctions,
  getVpcNetworking
}; 
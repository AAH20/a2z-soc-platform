# Cloud Infrastructure API

The Cloud Infrastructure API provides a seamless way to collect metadata from AWS, Azure, and Google Cloud resources without deploying any agents. This API is designed to integrate with the A2Z SOC platform and provide comprehensive infrastructure visibility.

## Authentication

All API requests require an API key, which should be included in the `x-api-key` header.

```
x-api-key: your-api-key
```

## Base URL

```
https://api.a2z-soc.com/api/v1/cloud-infra
```

For local development:

```
http://localhost:3001/api/v1/cloud-infra
```

## Endpoints

### Health Check

Check the health and connectivity status of all configured cloud providers.

```
GET /health
```

#### Response

```json
{
  "success": true,
  "timestamp": "2025-05-02T15:56:12.345Z",
  "status": {
    "aws": "connected",
    "azure": "connected",
    "googleCloud": "not_configured"
  }
}
```

### AWS Resources

Retrieve information about different AWS resource types.

```
GET /aws/:resourceType
```

Resource types:
- `ec2`: EC2 instances
- `ecs`: ECS clusters and services
- `lambda`: Lambda functions
- `networking`: VPC, subnets, security groups, etc.

#### Example: Get EC2 Instances

```
GET /aws/ec2
```

#### Response

```json
{
  "success": true,
  "timestamp": "2025-05-02T15:56:12.345Z",
  "data": [
    {
      "id": "i-0123456789abcdef0",
      "type": "t3.medium",
      "state": "running",
      "privateIp": "172.31.16.25",
      "publicIp": "54.23.212.45",
      "vpcId": "vpc-0123456789abcdef0",
      "subnetId": "subnet-0123456789abcdef0",
      "launchTime": "2025-04-01T12:00:00.000Z",
      "tags": [
        {
          "Key": "Name",
          "Value": "WebServer"
        }
      ]
    }
  ]
}
```

### Azure Resources

Retrieve information about different Azure resource types.

```
GET /azure/:resourceType
```

Resource types:
- `virtualmachines`: Azure Virtual Machines
- `aks`: Azure Kubernetes Service clusters
- `functions`: Azure Functions
- `networking`: Virtual Networks, NSGs, Public IPs, etc.

#### Example: Get Azure Virtual Machines

```
GET /azure/virtualmachines
```

#### Response

```json
{
  "success": true,
  "timestamp": "2025-05-02T15:56:12.345Z",
  "data": [
    {
      "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/vm-web-01",
      "name": "vm-web-01",
      "resourceGroup": "my-rg",
      "location": "eastus",
      "vmSize": "Standard_D2s_v3",
      "osType": "Linux",
      "powerState": "running",
      "provisioningState": "Succeeded",
      "tags": {
        "environment": "production",
        "department": "IT"
      }
    }
  ]
}
```

### Google Cloud Resources

Retrieve information about different Google Cloud resource types.

```
GET /gcp/:resourceType
```

Resource types:
- `compute`: Compute Engine VMs
- `gke`: Google Kubernetes Engine clusters
- `functions`: Cloud Functions
- `networking`: VPC networks, subnets, firewalls, etc.

#### Example: Get Compute Engine VMs

```
GET /gcp/compute
```

#### Response

```json
{
  "success": true,
  "timestamp": "2025-05-02T15:56:12.345Z",
  "data": [
    {
      "id": "1234567890123456789",
      "name": "instance-1",
      "zone": "us-central1-a",
      "machineType": "n2-standard-2",
      "status": "RUNNING",
      "cpuPlatform": "Intel Cascade Lake",
      "creationTimestamp": "2025-03-15T10:20:30.123Z",
      "networkInterfaces": [
        {
          "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/default",
          "subnetwork": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/subnetworks/default",
          "networkIP": "10.128.0.2",
          "accessConfigs": [
            {
              "natIP": "35.192.45.23",
              "type": "ONE_TO_ONE_NAT"
            }
          ]
        }
      ],
      "disks": [
        {
          "boot": true,
          "deviceName": "instance-1",
          "type": "PERSISTENT",
          "mode": "READ_WRITE",
          "source": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/instance-1"
        }
      ],
      "labels": {
        "env": "prod"
      }
    }
  ]
}
```

### All Resources

Retrieve resources from all cloud providers in a single request.

```
GET /all
```

#### Response

The response contains a comprehensive view of all resources across all configured cloud providers, organized by resource type and provider.

```json
{
  "success": true,
  "timestamp": "2025-05-02T15:56:12.345Z",
  "data": {
    "virtualMachines": {
      "aws": [...],
      "azure": [...],
      "googleCloud": [...]
    },
    "containers": {
      "aws": [...],
      "azure": [...],
      "googleCloud": [...]
    },
    "serverless": {
      "aws": [...],
      "azure": [...],
      "googleCloud": [...]
    },
    "networking": {
      "aws": {...},
      "azure": {...},
      "googleCloud": {...}
    }
  }
}
```

## Error Handling

In case of an error, the API will return a JSON response with an error message and appropriate HTTP status code.

```json
{
  "success": false,
  "error": "Failed to fetch AWS resources: The security token included in the request is invalid"
}
```

## Configuration

The API requires appropriate cloud provider credentials to be configured in environment variables or configuration files. Refer to the installation guide for details on setting up cloud provider access.

## Authentication Method

This API uses API key authentication for simplicity and security. The keys are stored securely in environment variables on the server and never exposed to clients. For enterprise deployments, OAuth2 can be implemented as an alternative authentication method. 
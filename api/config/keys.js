module.exports = {
  virustotal: {
    apiKey: process.env.VIRUSTOTAL_API_KEY || 'your-virustotal-api-key'
  },
  googleSecurityCommand: {
    apiKey: process.env.GOOGLE_SECURITY_API_KEY || 'your-google-security-api-key'
  },
  mandiant: {
    apiKey: process.env.MANDIANT_API_KEY || 'your-mandiant-api-key'
  },
  aws: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'your-aws-access-key-id',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || 'your-aws-secret-access-key',
    region: process.env.AWS_REGION || 'us-east-1'
  },
  azure: {
    clientId: process.env.AZURE_CLIENT_ID || 'your-azure-client-id',
    clientSecret: process.env.AZURE_CLIENT_SECRET || 'your-azure-client-secret',
    tenantId: process.env.AZURE_TENANT_ID || 'your-azure-tenant-id',
    subscriptionId: process.env.AZURE_SUBSCRIPTION_ID || 'your-azure-subscription-id'
  },
  googleCloud: {
    projectId: process.env.GCP_PROJECT_ID || 'your-gcp-project-id',
    keyFilePath: process.env.GCP_KEY_FILE_PATH || './config/gcp-key.json'
  }
}; 
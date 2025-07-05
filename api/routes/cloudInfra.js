const express = require('express');
const router = express.Router();
const cloudInfraController = require('../controllers/cloudInfraController');
const { validateApiKey } = require('../middleware/auth');

// Apply API key validation to all routes
router.use(validateApiKey);

// Health check
router.get('/health', cloudInfraController.healthCheck);

// Credential verification endpoints
router.post('/aws/verify', cloudInfraController.verifyAwsCredentials);
router.post('/azure/verify', cloudInfraController.verifyAzureCredentials);
router.post('/googlecloud/verify', cloudInfraController.verifyGoogleCloudCredentials);

// AWS resources
router.get('/aws/:resourceType', cloudInfraController.getAwsResources);
router.post('/aws/:resourceType', cloudInfraController.getAwsResources);

// Azure resources
router.get('/azure/:resourceType', cloudInfraController.getAzureResources);
router.post('/azure/:resourceType', cloudInfraController.getAzureResources);

// Google Cloud resources
router.get('/gcp/:resourceType', cloudInfraController.getGoogleCloudResources);
router.post('/gcp/:resourceType', cloudInfraController.getGoogleCloudResources);

// Get all resources across clouds
router.get('/all', cloudInfraController.getAllResources);
router.post('/all', cloudInfraController.getAllResources);

module.exports = router; 
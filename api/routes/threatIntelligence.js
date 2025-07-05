const express = require('express');
const multer = require('multer');
const {
  // VirusTotal endpoints
  checkVirusTotalHealth,
  searchVirusTotal,
  getFileReport,
  getUrlReport,
  getIpReport,
  getDomainReport,
  getLargeFileUploadUrl,
  uploadFile,
  
  // Google Security Command Center
  getSecurityCommandCenterAlerts,
  
  // Mandiant
  getMandiantIntelligence
} = require('../controllers/threatIntelligence');
const { authenticateToken, validateRapidApiHeaders } = require('../middleware/auth');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Apply RapidAPI validation middleware to all routes in this router
router.use(validateRapidApiHeaders);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/health
 * @desc Check VirusTotal API health
 * @access Private
 */
router.get('/virustotal/health', authenticateToken, checkVirusTotalHealth);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/search
 * @desc Search for an indicator in VirusTotal
 * @access Private
 */
router.get('/virustotal/search', authenticateToken, searchVirusTotal);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/file/:hash
 * @desc Get file report from VirusTotal
 * @access Private
 */
router.get('/virustotal/file/:hash', authenticateToken, getFileReport);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/url
 * @desc Get URL report from VirusTotal
 * @access Private
 */
router.get('/virustotal/url', authenticateToken, getUrlReport);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/ip/:ip
 * @desc Get IP report from VirusTotal
 * @access Private
 */
router.get('/virustotal/ip/:ip', authenticateToken, getIpReport);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/domain/:domain
 * @desc Get domain report from VirusTotal
 * @access Private
 */
router.get('/virustotal/domain/:domain', authenticateToken, getDomainReport);

/**
 * @route GET /api/v1/threat-intelligence/virustotal/file/upload-url
 * @desc Get a URL for uploading large files to VirusTotal (>32MB, up to 650MB)
 * @access Private
 */
router.get('/virustotal/file/upload-url', authenticateToken, getLargeFileUploadUrl);

/**
 * @route POST /api/v1/threat-intelligence/virustotal/file/upload
 * @desc Upload a file to VirusTotal (for files up to 32MB)
 * @access Private
 */
router.post('/virustotal/file/upload', 
  authenticateToken, 
  upload.single('file'), 
  uploadFile
);

/**
 * @route GET /api/v1/threat-intelligence/google-scc/alerts
 * @desc Get Google Security Command Center alerts
 * @access Private
 */
router.get('/google-scc/alerts', authenticateToken, getSecurityCommandCenterAlerts);

/**
 * @route GET /api/v1/threat-intelligence/mandiant
 * @desc Get Mandiant threat intelligence
 * @access Private
 */
router.get('/mandiant', authenticateToken, getMandiantIntelligence);

module.exports = router; 
const express = require('express');
const { 
  getAudits,
  getAuditDetails,
  updateAuditStatus,
  getAuditStats
} = require('../controllers/audits');
const { authenticateToken, validateRapidApiHeaders } = require('../middleware/auth');

const router = express.Router();

// Apply RapidAPI validation middleware to all routes in this router
router.use(validateRapidApiHeaders);

/**
 * @route GET /api/v1/audits
 * @desc Get all audit logs
 * @access Private
 */
router.get('/', authenticateToken, getAudits);

/**
 * @route GET /api/v1/audits/stats
 * @desc Get audit statistics
 * @access Private
 */
router.get('/stats', authenticateToken, getAuditStats);

/**
 * @route GET /api/v1/audits/:id
 * @desc Get specific audit details by ID
 * @access Private
 */
router.get('/:id', authenticateToken, getAuditDetails);

/**
 * @route PUT /api/v1/audits/:id/status
 * @desc Update audit status
 * @access Private
 */
router.put('/:id/status', authenticateToken, updateAuditStatus);

module.exports = router; 
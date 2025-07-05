const express = require('express');
const {
  getAiInsightsOverview,
  getAnalyticsTrend,
  getRecommendations,
  updateRecommendation,
  analyzeSecurityPosture,
  getDashboardStats
} = require('../controllers/aiInsights');
const { authenticateToken, validateRapidApiHeaders } = require('../middleware/auth');

const router = express.Router();

// Apply RapidAPI validation middleware to all routes in this router
router.use(validateRapidApiHeaders);

/**
 * @route GET /api/v1/ai-insights/overview
 * @desc Get AI insights overview dashboard data
 * @access Private
 */
router.get('/overview', authenticateToken, getAiInsightsOverview);

/**
 * @route GET /api/v1/ai-insights/dashboard-stats
 * @desc Get dashboard statistics
 * @access Private
 */
router.get('/dashboard-stats', authenticateToken, getDashboardStats);

/**
 * @route GET /api/v1/ai-insights/recommendations
 * @desc Get all AI recommendations
 * @access Private
 */
router.get('/recommendations', authenticateToken, getRecommendations);

/**
 * @route PUT /api/v1/ai-insights/recommendations/:id
 * @desc Update a recommendation status
 * @access Private
 */
router.put('/recommendations/:id', authenticateToken, updateRecommendation);

/**
 * @route GET /api/v1/ai-insights/trends
 * @desc Get analytics trend data
 * @access Private
 */
router.get('/trends', authenticateToken, getAnalyticsTrend);

/**
 * @route POST /api/v1/ai-insights/analyze-security-posture
 * @desc Analyze security posture
 * @access Private
 */
router.post('/analyze-security-posture', authenticateToken, analyzeSecurityPosture);

/**
 * @route GET /api/v1/ai-insights/deepseek/key
 * @desc Get DeepSeek API key (secured)
 * @access Private
 */
router.get('/deepseek/key', authenticateToken, (req, res) => {
  try {
    // Return the DeepSeek API key from environment variables
    const apiKey = process.env.DEEPSEEK_API_KEY || 'sk-d637686205e6432084507504935e68dc';
    
    if (!apiKey) {
      return res.status(500).json({
        success: false,
        error: 'DeepSeek API key not configured'
      });
    }
    
    res.json({
      success: true,
      key: apiKey
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route POST /api/v1/ai-insights/deepseek/analyze-code
 * @desc Analyze code for security issues using DeepSeek
 * @access Private
 */
router.post('/deepseek/analyze-code', authenticateToken, async (req, res) => {
  try {
    const { code, language } = req.body;
    
    if (!code || !language) {
      return res.status(400).json({
        success: false,
        error: 'Code and language are required'
      });
    }
    
    // Mock analysis result - in production, this would call DeepSeek API
    const analysisResult = {
      summary: "Security analysis completed successfully",
      vulnerabilities: [
        {
          severity: "high",
          description: "Potential SQL injection vulnerability detected",
          location: "Line 15, user input validation",
          recommendation: "Use parameterized queries or prepared statements"
        },
        {
          severity: "medium", 
          description: "Hardcoded credentials found",
          location: "Line 32, database connection",
          recommendation: "Move credentials to environment variables"
        }
      ],
      recommendations: [
        "Implement input validation for all user inputs",
        "Use environment variables for sensitive configuration",
        "Add proper error handling to prevent information disclosure"
      ],
      securityScore: 72
    };
    
    res.json({
      success: true,
      data: analysisResult,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route POST /api/v1/ai-insights/deepseek/generate-report
 * @desc Generate a security report using DeepSeek
 * @access Private
 */
router.post('/deepseek/generate-report', authenticateToken, async (req, res) => {
  try {
    const { reportType, data } = req.body;
    
    if (!reportType || !data) {
      return res.status(400).json({
        success: false,
        error: 'Report type and data are required'
      });
    }
    
    // Mock report generation - in production, this would call DeepSeek API
    const report = {
      id: `RPT-${Date.now()}`,
      title: `${reportType.charAt(0).toUpperCase() + reportType.slice(1)} Report`,
      generatedAt: new Date().toISOString(),
      status: 'completed',
      downloadUrl: `/api/v1/ai-insights/reports/${reportType}-${Date.now()}.pdf`
    };
    
    res.json({
      success: true,
      data: report,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route GET /api/v1/ai-insights/manus/credentials
 * @desc Get Manus AI credentials (secured)
 * @access Private
 */
router.get('/manus/credentials', authenticateToken, (req, res) => {
  try {
    // In production, these would come from secure environment variables
    const credentials = {
      apiKey: process.env.MANUS_API_KEY || 'manus-demo-key-12345',
      endpoint: process.env.MANUS_ENDPOINT || 'https://api.manus.im/v1'
    };
    
    if (!credentials.apiKey || credentials.apiKey === 'manus-demo-key-12345') {
      return res.status(503).json({
        success: false,
        error: 'Manus AI credentials not configured',
        message: 'Contact administrator to configure Manus AI integration'
      });
    }
    
    res.json({
      success: true,
      data: credentials
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * @route POST /api/v1/ai-insights/manus/analyze
 * @desc Analyze security data using Manus AI
 * @access Private
 */
router.post('/manus/analyze', authenticateToken, async (req, res) => {
  try {
    const { analysisType, data } = req.body;
    
    if (!analysisType || !data) {
      return res.status(400).json({
        success: false,
        error: 'Analysis type and data are required'
      });
    }
    
    // Mock Manus analysis - in production, this would call Manus API
    const analysis = {
      id: `MANUS-${Date.now()}`,
      type: analysisType,
      status: 'completed',
      confidence: 0.92,
      findings: [
        {
          category: 'threat_detection',
          severity: 'high',
          description: 'Advanced persistent threat indicators detected'
        }
      ],
      recommendations: [
        'Enhance monitoring for lateral movement',
        'Implement additional network segmentation'
      ],
      timestamp: new Date().toISOString()
    };
    
    res.json({
      success: true,
      data: analysis
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router; 
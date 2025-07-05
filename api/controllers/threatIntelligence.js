const virustotal = require('../utils/virusTotal');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

/**
 * Check the health status of the VirusTotal API connection
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const checkVirusTotalHealth = async (req, res) => {
  try {
    const isHealthy = await virustotal.checkApiHealth();
    
    res.json({
      success: true,
      status: isHealthy ? 'healthy' : 'unhealthy',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Search for an indicator in VirusTotal
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const searchVirusTotal = async (req, res) => {
  try {
    const { query, type } = req.query;
    
    if (!query) {
      return res.status(400).json({ 
        success: false,
        error: 'Search query is required' 
      });
    }
    
    const results = await virustotal.searchIndicator(query, type || 'general');
    
    res.json({
      success: true,
      data: results,
      query,
      type: type || 'general',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Get a file report from VirusTotal
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const getFileReport = async (req, res) => {
  try {
    const { hash } = req.params;
    
    if (!hash) {
      return res.status(400).json({ 
        success: false,
        error: 'File hash is required' 
      });
    }
    
    const report = await virustotal.getFileReport(hash);
    
    res.json({
      success: true,
      data: report,
      hash,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Get a URL report from VirusTotal
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const getUrlReport = async (req, res) => {
  try {
    const { url } = req.query;
    
    if (!url) {
      return res.status(400).json({ 
        success: false,
        error: 'URL is required' 
      });
    }
    
    const report = await virustotal.getUrlReport(url);
    
    res.json({
      success: true,
      data: report,
      url,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Get an IP address report from VirusTotal
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const getIpReport = async (req, res) => {
  try {
    const { ip } = req.params;
    
    if (!ip) {
      return res.status(400).json({ 
        success: false,
        error: 'IP address is required' 
      });
    }
    
    const report = await virustotal.getIpReport(ip);
    
    res.json({
      success: true,
      data: report,
      ip,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Get a domain report from VirusTotal
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const getDomainReport = async (req, res) => {
  try {
    const { domain } = req.params;
    
    if (!domain) {
      return res.status(400).json({ 
        success: false,
        error: 'Domain is required' 
      });
    }
    
    const report = await virustotal.getDomainReport(domain);
    
    res.json({
      success: true,
      data: report,
      domain,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Get a URL for uploading large files to VirusTotal (>32MB, up to 650MB)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const getLargeFileUploadUrl = async (req, res) => {
  try {
    const uploadUrl = await virustotal.getLargeFileUploadUrl();
    
    res.json({
      success: true,
      data: {
        url: uploadUrl
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

/**
 * Upload a file to VirusTotal (for files up to 32MB)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
const uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file provided'
      });
    }
    
    // Check file size (32MB limit for direct upload)
    const maxSize = 32 * 1024 * 1024; // 32MB in bytes
    if (req.file.size > maxSize) {
      return res.status(400).json({
        success: false,
        error: 'File is too large for direct upload. Use the /file/upload-url endpoint for files larger than 32MB'
      });
    }
    
    // Calculate file hash if available
    const crypto = require('crypto');
    const fileHash = crypto.createHash('md5').update(req.file.buffer).digest('hex');
    const sha1Hash = crypto.createHash('sha1').update(req.file.buffer).digest('hex');
    const sha256Hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
    
    // Include file metadata in the response regardless of the API response status
    const fileMetadata = {
      name: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      md5: fileHash,
      sha1: sha1Hash,
      sha256: sha256Hash,
      uploaded_at: new Date().toISOString()
    };
    
    try {
      // Try to submit to VirusTotal
      console.log(`Uploading file: ${req.file.originalname}, size: ${req.file.size} bytes, hash: ${sha256Hash}`);
      const result = await virustotal.uploadFile(req.file.buffer, req.file.originalname);
      console.log('VirusTotal API response:', JSON.stringify(result, null, 2));
      
      // Success response with both VirusTotal data and our metadata
      res.json({
        success: true,
        data: {
          ...result,
          meta: {
            file_info: fileMetadata
          }
        },
        filename: req.file.originalname,
        timestamp: new Date().toISOString()
      });
    } catch (vtError) {
      console.error('VirusTotal API error:', vtError.message);
      
      // Even if VirusTotal fails, return success with our file metadata
      // so the file can still be displayed in the UI
      res.json({
        success: true,
        data: {
          meta: {
            file_info: fileMetadata
          },
          // Include a placeholder data structure for consistency
          data: {
            type: 'file',
            id: sha256Hash
          }
        },
        error: vtError.message,
        filename: req.file.originalname,
        timestamp: new Date().toISOString()
      });
    }
  } catch (error) {
    console.error('File upload processing error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

// Database-driven Security Command Center alerts
const getSecurityCommandCenterAlerts = async (req, res) => {
  try {
    const db = new (require('../services/databaseService'))();
    const organizationId = req.headers['x-tenant-id'] || req.user?.organization_id;

    if (!organizationId) {
      return res.status(400).json({
        success: false,
        error: 'Organization ID is required'
      });
    }

    // Get real security events from database that match command center alert patterns
    const alerts = await db.getSecurityEvents(organizationId, {
      severity: ['high', 'critical'],
      limit: 20
    });

    // Transform database events into command center format
    const commandCenterAlerts = alerts.map(event => ({
      id: `sc-${event.id.replace(/-/g, '').substring(0, 10)}`,
      name: event.description || `${event.event_type} detected`,
      category: event.event_type.toUpperCase().replace(/[^A-Z_]/g, '_'),
      severity: event.severity.toUpperCase(),
      createTime: event.created_at,
      description: event.description || `Security event detected: ${event.event_type}`,
      sourceProperties: {
        sourceIp: event.source_ip,
        destinationIp: event.destination_ip,
        protocol: event.protocol,
        ruleId: event.rule_id,
        agentName: event.agent_name
      },
      state: event.status === 'resolved' ? 'INACTIVE' : 'ACTIVE'
    }));

    res.json({
      success: true,
      count: commandCenterAlerts.length,
      data: commandCenterAlerts
    });
  } catch (error) {
    console.error('Security Command Center alerts error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

// Database-driven Mandiant threat intelligence
const getMandiantIntelligence = async (req, res) => {
  try {
    const db = new (require('../services/databaseService'))();
    const organizationId = req.headers['x-tenant-id'] || req.user?.organization_id;

    if (!organizationId) {
      return res.status(400).json({
        success: false,
        error: 'Organization ID is required'
      });
    }

    // Get real threat intelligence from database
    const threatIntel = await db.query(`
      SELECT 
        ti.*,
        COUNT(se.id) as related_events
      FROM threat_intelligence ti
      LEFT JOIN security_events se ON (
        se.source_ip::text = ti.ioc_value OR 
        se.destination_ip::text = ti.ioc_value OR
        se.raw_data::text LIKE '%' || ti.ioc_value || '%'
      )
      WHERE ti.organization_id = $1 AND ti.is_active = true
      GROUP BY ti.id
      ORDER BY ti.confidence_score DESC, ti.last_seen DESC
      LIMIT 20
    `, [organizationId]);

    // Group threat intel by threat type
    const activeThreats = {};
    const indicators = [];
    
    threatIntel.rows.forEach(intel => {
      const threatType = intel.threat_type || 'Unknown';
      
      if (!activeThreats[threatType]) {
        activeThreats[threatType] = {
          id: threatType.toUpperCase().replace(/\s+/g, '_'),
          name: threatType,
          aliases: [],
          targets: [],
          country: 'Unknown',
          description: intel.description || `${threatType} threat activity detected`,
          ttps: [],
          indicators: []
        };
      }
      
      activeThreats[threatType].indicators.push({
        type: intel.ioc_type,
        value: intel.ioc_value,
        confidence: intel.confidence_score >= 0.8 ? 'high' : 
                   intel.confidence_score >= 0.5 ? 'medium' : 'low',
        source: intel.source,
        relatedEvents: intel.related_events
      });
    });

    // Get recent security campaigns from security events
    const recentCampaigns = await db.query(`
      SELECT 
        event_type,
        COUNT(*) as event_count,
        MIN(created_at) as first_seen,
        MAX(created_at) as last_seen,
        array_agg(DISTINCT source_ip::text) as source_ips,
        array_agg(DISTINCT mitre_technique) FILTER (WHERE mitre_technique IS NOT NULL) as techniques
      FROM security_events
      WHERE organization_id = $1 
        AND created_at >= NOW() - INTERVAL '30 days'
        AND severity IN ('high', 'critical')
      GROUP BY event_type
      HAVING COUNT(*) >= 5
      ORDER BY event_count DESC
      LIMIT 5
    `, [organizationId]);

    const campaigns = recentCampaigns.rows.map((campaign, index) => ({
      id: `CAMPAIGN-${new Date().getFullYear()}-${String(index + 1).padStart(2, '0')}`,
      name: `${campaign.event_type.replace(/_/g, ' ')} Campaign`,
      actors: [`Unknown Actor ${index + 1}`],
      targetSectors: ['Your Organization'],
      timeframe: `${new Date(campaign.first_seen).toLocaleDateString()} - ${new Date(campaign.last_seen).toLocaleDateString()}`,
      description: `Campaign involving ${campaign.event_count} ${campaign.event_type} events detected`,
      affectedCountries: ['Unknown'],
      eventCount: parseInt(campaign.event_count),
      techniques: campaign.techniques || []
    }));

    const threatIntelResponse = {
      activeThreats: Object.values(activeThreats),
      recentCampaigns: campaigns,
      summary: {
        totalIndicators: threatIntel.rows.length,
        highConfidenceIndicators: threatIntel.rows.filter(i => i.confidence_score >= 0.8).length,
        activeCampaigns: campaigns.length,
        lastUpdated: new Date().toISOString()
      }
    };
    
    res.json({
      success: true,
      data: threatIntelResponse
    });
  } catch (error) {
    console.error('Mandiant intelligence error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
};

module.exports = {
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
}; 
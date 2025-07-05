const db = require('../services/databaseService');

// Helper function to get organization ID from request
const getOrganizationId = (req) => {
  // For demo purposes, use the default organization
  // In production, this would come from the authenticated user's context
  return '00000000-0000-0000-0000-000000000001';
};

const getAnalyticsTrend = async (req, res) => {
  try {
    const organizationId = getOrganizationId(req);
    const { timeframe = '7d' } = req.query;

    // Calculate date range
    let startDate = new Date();
    switch (timeframe) {
      case '1d':
        startDate.setDate(startDate.getDate() - 1);
        break;
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      default:
        startDate.setDate(startDate.getDate() - 7);
    }

    // Get security events grouped by day
    const eventsQuery = `
      SELECT 
        DATE(created_at) as date,
        severity,
        COUNT(*) as count
      FROM security_events 
      WHERE organization_id = $1 AND created_at >= $2
      GROUP BY DATE(created_at), severity
      ORDER BY date ASC
    `;

    const events = await db.query(eventsQuery, [organizationId, startDate]);
    
    // Get AI analysis results
    const aiAnalysisQuery = `
      SELECT 
        DATE(created_at) as date,
        analysis_type,
        AVG(confidence_score) as avg_confidence,
        COUNT(*) as analysis_count
      FROM ai_analysis_results 
      WHERE organization_id = $1 AND created_at >= $2
      GROUP BY DATE(created_at), analysis_type
      ORDER BY date ASC
    `;

    const aiAnalysis = await db.query(aiAnalysisQuery, [organizationId, startDate]);

    // Process the data into the expected format
    const trendData = processAnalyticsTrendData(events.rows, aiAnalysis.rows, timeframe);

    res.json({
      success: true,
      timeframe,
      data: trendData,
      summary: {
        totalEvents: events.rows.reduce((sum, row) => sum + parseInt(row.count), 0),
        avgConfidence: aiAnalysis.rows.length > 0 
          ? (aiAnalysis.rows.reduce((sum, row) => sum + parseFloat(row.avg_confidence || 0), 0) / aiAnalysis.rows.length).toFixed(2)
          : 0.85,
        aiAnalysisCount: aiAnalysis.rows.reduce((sum, row) => sum + parseInt(row.analysis_count), 0)
      }
    });

  } catch (error) {
    console.error('Error fetching analytics trend:', error);
    res.status(500).json({ error: 'Failed to fetch analytics trend data' });
  }
};

const getRecommendations = async (req, res) => {
  try {
    const organizationId = getOrganizationId(req);
    const { status, severity, limit = 50 } = req.query;

    const filters = { limit: parseInt(limit) };
    if (status) filters.status = status;
    if (severity) filters.severity = severity;

    // Get security recommendations from database
    let recommendations = await db.getSecurityRecommendations(organizationId, filters);

    // If no recommendations exist, generate some initial ones
    if (recommendations.length === 0) {
      await generateInitialRecommendations(organizationId);
      recommendations = await db.getSecurityRecommendations(organizationId, filters);
    }

    // Calculate statistics
    const stats = {
      total: recommendations.length,
      implemented: recommendations.filter(r => r.status === 'implemented').length,
      pending: recommendations.filter(r => r.status === 'new').length,
      inProgress: recommendations.filter(r => r.status === 'in_progress').length
    };
    
    res.json({
      success: true,
      data: recommendations.map(formatRecommendation),
      statistics: {
        total: stats.total,
        implemented: stats.implemented,
        pending: stats.pending,
        inProgress: stats.inProgress,
        implementationRate: stats.total > 0 ? ((stats.implemented / stats.total) * 100).toFixed(1) : 0
      }
    });

  } catch (error) {
    console.error('Error fetching recommendations:', error);
    res.status(500).json({ error: 'Failed to fetch recommendations' });
  }
};

const updateRecommendation = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;
    const organizationId = getOrganizationId(req);

    // Update recommendation status
    const updateQuery = `
      UPDATE security_recommendations 
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND organization_id = $3
      RETURNING *
    `;

    const result = await db.query(updateQuery, [status, id, organizationId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Recommendation not found' });
    }

    // Log the update action
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user?.id || null,
      action: 'update_recommendation',
      resource_type: 'security_recommendation',
      resource_id: id,
      details: { status, notes },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    res.json({
      success: true,
      recommendation: formatRecommendation(result.rows[0])
    });

  } catch (error) {
    console.error('Error updating recommendation:', error);
    res.status(500).json({ error: 'Failed to update recommendation' });
  }
};

const analyzeSecurityPosture = async (req, res) => {
  try {
    const organizationId = getOrganizationId(req);
    const { timeRange = '30d' } = req.query;

    // Calculate date range
    let startDate = new Date();
    switch (timeRange) {
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      default:
        startDate.setDate(startDate.getDate() - 30);
    }

    // Get comprehensive security data
    const [securityEvents, agents, recommendations] = await Promise.all([
      db.getSecurityEvents(organizationId, { start_date: startDate }),
      db.getNetworkAgents(organizationId),
      db.getSecurityRecommendations(organizationId)
    ]);

    // Analyze the data
    const analysis = {
      overallScore: calculateSecurityScore(securityEvents, agents, recommendations),
      riskFactors: identifyRiskFactors(securityEvents, agents),
      improvements: generateImprovementSuggestions(securityEvents, recommendations),
      trends: analyzeTrends(securityEvents),
      agentHealth: analyzeAgentHealth(agents),
      threatLandscape: analyzeThreatLandscape(securityEvents)
    };

    // Store the analysis result
    await db.createAiAnalysisResult({
      organization_id: organizationId,
      analysis_type: 'security_posture',
      input_data: {
        timeRange,
        eventsCount: securityEvents.length,
        agentsCount: agents.length,
        recommendationsCount: recommendations.length
      },
      results: analysis,
      confidence_score: 0.85,
      model_version: 'v1.0',
      processing_time_ms: 150
    });
    
    res.json({
      success: true,
      timeRange,
      analysis,
      lastUpdated: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error analyzing security posture:', error);
    res.status(500).json({ error: 'Failed to analyze security posture' });
  }
};

const getDashboardStats = async (req, res) => {
  try {
    const organizationId = getOrganizationId(req);
    const stats = await db.getDashboardStats(organizationId);

    res.json({
      success: true,
      data: {
        totalAgents: stats.totalAgents,
        activeAgents: stats.activeAgents,
        eventsToday: stats.eventsToday,
        criticalEvents: stats.criticalEvents,
        eventsBySeverity: stats.eventsBySeverity,
        recentAlerts: stats.recentAlerts.slice(0, 5) // Limit to 5 most recent
      }
    });

  } catch (error) {
    console.error('Error fetching dashboard stats:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
  }
};

const getAiInsightsOverview = async (req, res) => {
  try {
    const organizationId = getOrganizationId(req);

    // Get recent AI analysis results
    const aiAnalysisQuery = `
      SELECT analysis_type, results, confidence_score, created_at
      FROM ai_analysis_results 
      WHERE organization_id = $1 
      ORDER BY created_at DESC 
      LIMIT 10
    `;

    const aiAnalysis = await db.query(aiAnalysisQuery, [organizationId]);

    // Get recent security events for insights
    const recentEvents = await db.getSecurityEvents(organizationId, { 
      limit: 20,
      start_date: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
    });

    const insights = aiAnalysis.rows.map(analysis => ({
      id: `ai-${Date.now()}-${Math.random()}`,
      type: analysis.analysis_type,
      title: generateInsightTitle(analysis.analysis_type, analysis.results),
      description: generateInsightDescription(analysis.analysis_type, analysis.results),
      severity: determineSeverity(analysis.results),
      confidence: analysis.confidence_score,
      timestamp: analysis.created_at,
      source: 'ai_analysis'
    }));
    
    res.json({
      success: true,
      data: {
        insights,
        recentEvents: recentEvents.slice(0, 10),
        summary: {
          totalInsights: insights.length,
          highSeverityInsights: insights.filter(i => i.severity === 'high' || i.severity === 'critical').length,
          avgConfidence: insights.length > 0 
            ? (insights.reduce((sum, i) => sum + i.confidence, 0) / insights.length).toFixed(2)
            : 0
        }
      }
    });

  } catch (error) {
    console.error('Error fetching AI insights overview:', error);
    res.status(500).json({ error: 'Failed to fetch AI insights overview' });
  }
};

// Helper functions

function processAnalyticsTrendData(events, aiAnalysis, timeframe) {
  const trendData = [];
  const daysBack = timeframe === '1d' ? 1 : timeframe === '7d' ? 7 : timeframe === '30d' ? 30 : 90;
  
  for (let i = daysBack - 1; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dateStr = date.toISOString().split('T')[0];
    
    const dayEvents = events.filter(e => e.date === dateStr);
    const dayAnalysis = aiAnalysis.filter(a => a.date === dateStr);
    
    trendData.push({
      date: dateStr,
      total: dayEvents.reduce((sum, e) => sum + parseInt(e.count), 0),
      critical: dayEvents.filter(e => e.severity === 'critical').reduce((sum, e) => sum + parseInt(e.count), 0),
      high: dayEvents.filter(e => e.severity === 'high').reduce((sum, e) => sum + parseInt(e.count), 0),
      medium: dayEvents.filter(e => e.severity === 'medium').reduce((sum, e) => sum + parseInt(e.count), 0),
      low: dayEvents.filter(e => e.severity === 'low').reduce((sum, e) => sum + parseInt(e.count), 0),
      aiAnalysisCount: dayAnalysis.reduce((sum, a) => sum + parseInt(a.analysis_count), 0),
      avgConfidence: dayAnalysis.length > 0 
        ? (dayAnalysis.reduce((sum, a) => sum + parseFloat(a.avg_confidence || 0), 0) / dayAnalysis.length).toFixed(2)
        : 0
    });
  }
  
  return trendData;
}

function formatRecommendation(rec) {
  return {
    id: rec.id,
    type: rec.recommendation_type,
    title: rec.title,
    description: rec.description,
    severity: rec.severity,
    status: rec.status,
    implementationEffort: rec.implementation_effort,
    riskReduction: rec.risk_reduction_score,
    createdAt: rec.created_at,
    implementedAt: rec.implemented_at
  };
}

async function generateInitialRecommendations(organizationId) {
  const recommendations = [
    {
      organization_id: organizationId,
      recommendation_type: 'network_security',
      title: 'Enable Network Segmentation',
      description: 'Implement network segmentation to isolate critical systems and reduce the attack surface.',
      severity: 'high',
      implementation_effort: 'medium',
      risk_reduction_score: 85
    },
    {
      organization_id: organizationId,
      recommendation_type: 'access_control',
      title: 'Implement Multi-Factor Authentication',
      description: 'Deploy MFA for all administrative accounts to prevent unauthorized access.',
      severity: 'critical',
      implementation_effort: 'low',
      risk_reduction_score: 90
    },
    {
      organization_id: organizationId,
      recommendation_type: 'monitoring',
      title: 'Enhance Logging Coverage',
      description: 'Increase logging coverage for critical systems and implement log analysis automation.',
      severity: 'medium',
      implementation_effort: 'medium',
      risk_reduction_score: 70
    },
    {
      organization_id: organizationId,
      recommendation_type: 'vulnerability_management',
      title: 'Regular Security Assessments',
      description: 'Conduct quarterly penetration testing and vulnerability assessments.',
      severity: 'high',
      implementation_effort: 'high',
      risk_reduction_score: 80
    },
    {
      organization_id: organizationId,
      recommendation_type: 'incident_response',
      title: 'Update Incident Response Plan',
      description: 'Review and update incident response procedures to include modern threat scenarios.',
      severity: 'medium',
      implementation_effort: 'low',
      risk_reduction_score: 65
    }
  ];

  for (const rec of recommendations) {
    await db.createSecurityRecommendation(rec);
  }
}

function calculateSecurityScore(events, agents, recommendations) {
  let score = 100;
  
  // Deduct points for critical events
  const criticalEvents = events.filter(e => e.severity === 'critical').length;
  score -= Math.min(criticalEvents * 5, 30);
  
  // Deduct points for offline agents
  const offlineAgents = agents.filter(a => a.status === 'offline').length;
  score -= Math.min(offlineAgents * 10, 25);
  
  // Add points for implemented recommendations
  const implementedRecs = recommendations.filter(r => r.status === 'implemented').length;
  const totalRecs = recommendations.length;
  if (totalRecs > 0) {
    score += (implementedRecs / totalRecs) * 15;
  }
  
  return Math.max(Math.min(Math.round(score), 100), 0);
}

function identifyRiskFactors(events, agents) {
  const risks = [];
  
  const criticalEvents = events.filter(e => e.severity === 'critical');
  if (criticalEvents.length > 5) {
    risks.push({
      type: 'high_critical_events',
      severity: 'high',
      description: `${criticalEvents.length} critical security events detected`,
      recommendation: 'Review and address critical security events immediately'
    });
  }
  
  const offlineAgents = agents.filter(a => a.status === 'offline');
  if (offlineAgents.length > 0) {
    risks.push({
      type: 'offline_agents',
      severity: 'medium',
      description: `${offlineAgents.length} security agents offline`,
      recommendation: 'Restore connectivity to offline security agents'
    });
  }
  
  return risks;
}

function generateImprovementSuggestions(events, recommendations) {
  const suggestions = [];
  
  // Analyze event patterns
  const eventTypes = {};
  events.forEach(e => {
    eventTypes[e.event_type] = (eventTypes[e.event_type] || 0) + 1;
  });
  
  const topEventType = Object.keys(eventTypes).reduce((a, b) => 
    eventTypes[a] > eventTypes[b] ? a : b, Object.keys(eventTypes)[0]
  );
  
  if (topEventType && eventTypes[topEventType] > 3) {
    suggestions.push({
      category: 'threat_prevention',
      title: `Address ${topEventType} threats`,
      description: `Focus on preventing ${topEventType} events which represent ${eventTypes[topEventType]} incidents`,
      priority: 'high'
    });
  }
  
  // Check recommendation implementation rate
  const implementedCount = recommendations.filter(r => r.status === 'implemented').length;
  const totalCount = recommendations.length;
  
  if (totalCount > 0 && (implementedCount / totalCount) < 0.5) {
    suggestions.push({
      category: 'compliance',
      title: 'Increase recommendation implementation rate',
      description: `Only ${Math.round((implementedCount / totalCount) * 100)}% of security recommendations have been implemented`,
      priority: 'medium'
    });
  }
  
  return suggestions;
}

function analyzeTrends(events) {
  const last7Days = events.filter(e => {
    const eventDate = new Date(e.created_at);
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    return eventDate >= weekAgo;
  });
  
  const last14Days = events.filter(e => {
    const eventDate = new Date(e.created_at);
    const twoWeeksAgo = new Date();
    twoWeeksAgo.setDate(twoWeeksAgo.getDate() - 14);
    return eventDate >= twoWeeksAgo && eventDate < new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  });
  
  const currentWeekEvents = last7Days.length;
  const previousWeekEvents = last14Days.length;
  
  const trend = currentWeekEvents > previousWeekEvents ? 'increasing' : 
                currentWeekEvents < previousWeekEvents ? 'decreasing' : 'stable';
  
  const changePercent = previousWeekEvents > 0 
    ? ((currentWeekEvents - previousWeekEvents) / previousWeekEvents * 100).toFixed(1)
    : 0;
  
  return {
    direction: trend,
    changePercent: parseFloat(changePercent),
    currentWeekEvents,
    previousWeekEvents
  };
}

function analyzeAgentHealth(agents) {
  const online = agents.filter(a => a.status === 'online').length;
  const total = agents.length;
  
  return {
    totalAgents: total,
    onlineAgents: online,
    offlineAgents: total - online,
    healthPercentage: total > 0 ? Math.round((online / total) * 100) : 0,
    status: online === total ? 'healthy' : online > total * 0.8 ? 'warning' : 'critical'
  };
}

function analyzeThreatLandscape(events) {
  const threatTypes = {};
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  
  events.forEach(event => {
    if (event.event_type) {
      threatTypes[event.event_type] = (threatTypes[event.event_type] || 0) + 1;
    }
    if (event.severity) {
      severityCounts[event.severity] = (severityCounts[event.severity] || 0) + 1;
    }
  });
  
  const topThreats = Object.entries(threatTypes)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5)
    .map(([type, count]) => ({ type, count }));
  
  return {
    topThreats,
    severityDistribution: severityCounts,
    totalThreats: events.length,
    riskLevel: severityCounts.critical > 5 ? 'high' : 
               severityCounts.critical > 0 || severityCounts.high > 10 ? 'medium' : 'low'
  };
}

function generateInsightTitle(analysisType, results) {
  switch (analysisType) {
    case 'security_posture':
      return `Security Posture Score: ${results.overallScore}/100`;
    case 'threat_analysis':
      return 'Threat Landscape Analysis';
    case 'vulnerability_assessment':
      return 'Vulnerability Assessment Results';
    default:
      return 'AI Security Analysis';
  }
}

function generateInsightDescription(analysisType, results) {
  switch (analysisType) {
    case 'security_posture':
      return `Overall security score is ${results.overallScore}/100. ${results.riskFactors?.length || 0} risk factors identified.`;
    case 'threat_analysis':
      return `Analysis of threat landscape shows ${results.threatLandscape?.riskLevel || 'medium'} risk level.`;
    default:
      return 'AI-powered security analysis completed.';
  }
}

function determineSeverity(results) {
  if (results.overallScore && results.overallScore < 60) return 'critical';
  if (results.riskFactors && results.riskFactors.length > 3) return 'high';
  if (results.overallScore && results.overallScore < 80) return 'medium';
  return 'low';
}

module.exports = {
  getAnalyticsTrend,
  getRecommendations,
  updateRecommendation,
  analyzeSecurityPosture,
  getDashboardStats,
  getAiInsightsOverview
}; 
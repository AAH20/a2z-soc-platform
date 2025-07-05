const DatabaseService = require('./databaseService');

class AgentService {
  constructor() {
    // Removed database instantiation from constructor
  }

  async getAllAgents(organizationId) {
    try {
      // Using singleton db instance
      const agents = await db.getNetworkAgents(organizationId);
      
      return {
        success: true,
        data: agents.map(agent => ({
          id: agent.id,
          name: agent.name,
          status: agent.status,
          type: agent.agent_type,
          ip_address: agent.ip_address,
          hostname: agent.hostname,
          operating_system: agent.operating_system,
          version: agent.version,
          lastSeen: agent.last_heartbeat,
          created_at: agent.created_at,
          configuration: agent.configuration
        }))
      };
    } catch (error) {
      console.error('Error getting all agents:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async getAgent(id, organizationId) {
    try {
      // Using singleton db instance
      const agents = await db.getNetworkAgents(organizationId, { agent_id: id });
      const agent = agents[0];
      
      if (!agent) {
        return {
          success: false,
          data: null
        };
      }

      return {
        success: true,
        data: {
          id: agent.id,
          name: agent.name,
          status: agent.status,
          type: agent.agent_type,
          ip_address: agent.ip_address,
          hostname: agent.hostname,
          operating_system: agent.operating_system,
          version: agent.version,
          lastSeen: agent.last_heartbeat,
          created_at: agent.created_at,
          configuration: agent.configuration
        }
      };
    } catch (error) {
      console.error('Error getting agent:', error);
      return {
        success: false,
        data: null
      };
    }
  }

  async getAgentMetrics(id, organizationId) {
    try {
      // Get agent first to verify it exists
      const agent = await this.getAgent(id, organizationId);
      if (!agent.success) {
        return agent;
      }

      // For now, return simulated metrics - this would be extended with real metrics collection
      return {
        success: true,
        data: {
          cpu: Math.floor(Math.random() * 100),
          memory: Math.floor(Math.random() * 100),
          network: Math.floor(Math.random() * 1000),
          uptime: Math.floor(Math.random() * 86400),
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      console.error('Error getting agent metrics:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async registerAgent(agentData, organizationId) {
    try {
      // Using singleton db instance
      const agent = await db.createNetworkAgent({
        organization_id: organizationId,
        name: agentData.name,
        agent_type: agentData.type || 'network',
        ip_address: agentData.ip_address,
        hostname: agentData.hostname,
        operating_system: agentData.operating_system,
        version: agentData.version || '1.0.0',
        configuration: agentData.configuration || {}
      });

      return {
        success: true,
        data: {
          id: agent.id,
          name: agent.name,
          type: agent.agent_type,
          registeredAt: agent.created_at
        }
      };
    } catch (error) {
      console.error('Error registering agent:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async listAgents(organizationId, options = {}) {
    try {
      // Using singleton db instance
      const filters = {};
      if (options.status) filters.status = options.status;
      if (options.type) filters.agent_type = options.type;
      
      const agents = await db.getNetworkAgents(organizationId, filters);
      
      // Apply pagination
      const offset = options.offset || 0;
      const limit = options.limit || 50;
      const paginatedAgents = agents.slice(offset, offset + limit);
      
      return paginatedAgents.map(agent => ({
        id: agent.id,
        name: agent.name,
        status: agent.status,
        type: agent.agent_type,
        ip_address: agent.ip_address,
        hostname: agent.hostname,
        operating_system: agent.operating_system,
        version: agent.version,
        lastSeen: agent.last_heartbeat,
        created_at: agent.created_at
      }));
    } catch (error) {
      console.error('Error listing agents:', error);
      return [];
    }
  }

  async countAgents(organizationId, filters = {}) {
    try {
      // Using singleton db instance
      const agents = await db.getNetworkAgents(organizationId, filters);
      return agents.length;
    } catch (error) {
      console.error('Error counting agents:', error);
      return 0;
    }
  }

  async updateAgentStatus(agentId, status) {
    try {
      // Using singleton db instance
      await db.updateAgentHeartbeat(agentId, status);
      return {
        success: true
      };
    } catch (error) {
      console.error('Error updating agent status:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  async validateAgentAuth(authHeader) {
    try {
      // Extract agent key from auth header
      const agentKey = authHeader.replace('Bearer ', '');
      
      // Find agent by API key - this would need to be implemented in database
      // For now, return a basic validation
      if (agentKey && agentKey.length > 10) {
        return {
          id: 'agent-' + agentKey.slice(-6),
          tenantId: '00000000-0000-0000-0000-000000000001', // Default org
          key: agentKey
        };
      }
      
      return null;
    } catch (error) {
      console.error('Error validating agent auth:', error);
      return null;
    }
  }

  async close() {
    // No persistent connection to close
  }
}

module.exports = AgentService; 
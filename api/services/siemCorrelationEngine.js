const EventEmitter = require('events');

class SIEMCorrelationEngine extends EventEmitter {
  constructor() {
    super();
    this.rules = new Map();
    this.eventBuffer = [];
    this.correlationWindows = new Map();
  }

  async initialize() {
    console.log('SIEM Correlation Engine initialized');
    return true;
  }

  addRule(rule) {
    this.rules.set(rule.id, rule);
    console.log(`Added correlation rule: ${rule.name}`);
  }

  async processEvent(event) {
    const correlationResult = {
      correlation_id: null,
      alert: null
    };

    // Simple correlation logic
    for (const [ruleId, rule] of this.rules) {
      if (this.matchesRule(event, rule)) {
        const correlationId = `corr_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        correlationResult.correlation_id = correlationId;
        correlationResult.alert = {
          title: `${rule.name} Triggered`,
          description: `Event matched correlation rule: ${rule.name}`,
          severity: rule.severity,
          source_ip: event.source_ip,
          destination_ip: event.destination_ip,
          affected_assets: [event.source_ip].filter(Boolean),
          indicators: { rule_id: ruleId, event_id: event.event_id },
          rule_id: ruleId,
          event_count: 1
        };

        break;
      }
    }

    return correlationResult;
  }

  matchesRule(event, rule) {
    // Simple string matching for now
    if (rule.query && event.message) {
      const queryTerms = rule.query.toLowerCase().split(' ');
      const message = event.message.toLowerCase();
      
      return queryTerms.some(term => {
        if (term.includes('*')) {
          const cleanTerm = term.replace(/\*/g, '');
          return message.includes(cleanTerm);
        }
        return message.includes(term);
      });
    }
    
    return false;
  }
}

module.exports = SIEMCorrelationEngine; 
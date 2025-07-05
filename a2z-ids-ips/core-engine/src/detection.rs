use std::collections::HashMap;
use tracing::{info, warn};
use crate::network::PacketInfo;

pub struct ThreatDetector {
    rules: HashMap<String, ThreatRule>,
    statistics: ThreatStats,
}

#[derive(Debug, Clone)]
pub struct ThreatRule {
    pub id: String,
    pub name: String,
    pub severity: ThreatSeverity,
    pub conditions: Vec<ThreatCondition>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum ThreatCondition {
    PortRange { start: u16, end: u16 },
    SuspiciousPort(u16),
    IpPattern(String),
    ProtocolMatch(String),
    PayloadPattern(String),
}

#[derive(Debug, Clone)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Default)]
pub struct ThreatStats {
    pub rules_loaded: usize,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub last_update: Option<chrono::DateTime<chrono::Utc>>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            rules: HashMap::new(),
            statistics: ThreatStats::default(),
        };
        
        // Load default rules
        detector.load_default_rules();
        
        info!("🛡️  Threat detector initialized with {} rules", 
              detector.statistics.rules_loaded);
        
        detector
    }

    fn load_default_rules(&mut self) {
        // Port scan detection rule
        self.add_rule(ThreatRule {
            id: "port_scan_001".to_string(),
            name: "Port Scan Detection".to_string(),
            severity: ThreatSeverity::Medium,
            conditions: vec![
                ThreatCondition::PortRange { start: 1, end: 1024 },
            ],
            description: "Detects potential port scanning activity".to_string(),
        });

        // Suspicious port access
        self.add_rule(ThreatRule {
            id: "suspicious_port_001".to_string(),
            name: "Suspicious Port Access".to_string(),
            severity: ThreatSeverity::High,
            conditions: vec![
                ThreatCondition::SuspiciousPort(23),   // Telnet
                ThreatCondition::SuspiciousPort(135),  // MS RPC
                ThreatCondition::SuspiciousPort(139),  // NetBIOS
                ThreatCondition::SuspiciousPort(445),  // SMB
                ThreatCondition::SuspiciousPort(1433), // MS SQL
                ThreatCondition::SuspiciousPort(3389), // RDP
            ],
            description: "Detects access to commonly exploited ports".to_string(),
        });

        // DDoS pattern detection
        self.add_rule(ThreatRule {
            id: "ddos_001".to_string(),
            name: "DDoS Pattern Detection".to_string(),
            severity: ThreatSeverity::Critical,
            conditions: vec![
                ThreatCondition::ProtocolMatch("TCP".to_string()),
                ThreatCondition::ProtocolMatch("UDP".to_string()),
            ],
            description: "Detects potential DDoS attack patterns".to_string(),
        });

        // Malware communication pattern
        self.add_rule(ThreatRule {
            id: "malware_comm_001".to_string(),
            name: "Malware Communication".to_string(),
            severity: ThreatSeverity::High,
            conditions: vec![
                ThreatCondition::PortRange { start: 6660, end: 6669 }, // IRC
                ThreatCondition::SuspiciousPort(4444), // Common backdoor
                ThreatCondition::SuspiciousPort(31337), // Elite backdoor
            ],
            description: "Detects potential malware command and control traffic".to_string(),
        });

        info!("✅ Loaded {} default threat detection rules", self.rules.len());
        self.statistics.rules_loaded = self.rules.len();
        self.statistics.last_update = Some(chrono::Utc::now());
    }

    fn add_rule(&mut self, rule: ThreatRule) {
        self.rules.insert(rule.id.clone(), rule);
    }

    pub async fn analyze_packet(&self, packet_info: &PacketInfo) -> bool {
        // Check each rule against the packet
        for (rule_id, rule) in &self.rules {
            if self.check_rule_conditions(rule, packet_info) {
                warn!("🚨 Threat detected: {} (Rule: {})", rule.name, rule_id);
                return true;
            }
        }

        false
    }

    fn check_rule_conditions(&self, rule: &ThreatRule, packet_info: &PacketInfo) -> bool {
        for condition in &rule.conditions {
            match condition {
                ThreatCondition::PortRange { start, end } => {
                    if packet_info.dst_port >= *start && packet_info.dst_port <= *end {
                        // Only trigger for certain protocols to reduce false positives
                        if packet_info.protocol == "TCP" && 
                           packet_info.flags.contains(&"SYN".to_string()) {
                            return true;
                        }
                    }
                }
                ThreatCondition::SuspiciousPort(port) => {
                    if packet_info.dst_port == *port || packet_info.src_port == *port {
                        return true;
                    }
                }
                ThreatCondition::IpPattern(pattern) => {
                    if packet_info.src_ip.contains(pattern) || 
                       packet_info.dst_ip.contains(pattern) {
                        return true;
                    }
                }
                ThreatCondition::ProtocolMatch(protocol) => {
                    if packet_info.protocol == *protocol {
                        // Additional logic for protocol-specific threats
                        if protocol == "TCP" && packet_info.flags.is_empty() {
                            return true; // Suspicious TCP packet with no flags
                        }
                    }
                }
                ThreatCondition::PayloadPattern(_pattern) => {
                    // Payload analysis would require packet payload data
                    // This is a placeholder for future implementation
                    // Skip this condition for now
                    continue;
                }
            }
        }

        false
    }

    pub async fn analyze_log_entry(&self, log_entry: &str) -> Vec<String> {
        let mut threats = Vec::new();
        let log_lower = log_entry.to_lowercase();

        // Security-related log analysis
        if log_lower.contains("failed login") || 
           log_lower.contains("authentication failed") ||
           log_lower.contains("access denied") {
            threats.push("Authentication Failure".to_string());
        }

        if log_lower.contains("privilege escalation") || 
           log_lower.contains("sudo") && log_lower.contains("failed") {
            threats.push("Privilege Escalation Attempt".to_string());
        }

        if log_lower.contains("network error") || 
           log_lower.contains("connection timeout") ||
           log_lower.contains("host unreachable") {
            threats.push("Network Anomaly".to_string());
        }

        if log_lower.contains("malware") || 
           log_lower.contains("virus") ||
           log_lower.contains("trojan") {
            threats.push("Malware Detection".to_string());
        }

        if log_lower.contains("kernel panic") || 
           log_lower.contains("system crash") ||
           log_lower.contains("segmentation fault") {
            threats.push("System Stability Issue".to_string());
        }

        if !threats.is_empty() {
            warn!("🚨 Log-based threats detected: {:?}", threats);
        }

        threats
    }

    pub fn get_statistics(&self) -> &ThreatStats {
        &self.statistics
    }

    pub fn get_rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn get_rules(&self) -> Vec<&ThreatRule> {
        self.rules.values().collect()
    }
} 
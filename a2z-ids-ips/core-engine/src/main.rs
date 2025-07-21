use anyhow::Result;
use clap::{Arg, Command, ArgMatches};
use std::time::Duration;
use tracing::{info, warn, error};
use tracing_subscriber;
use pnet_datalink::{self, NetworkInterface};
use std::sync::Arc;
use tokio::sync::Mutex;
use signal_hook::{consts::SIGTERM};
use signal_hook_tokio::Signals as AsyncSignals;
use futures_util::StreamExt;
use uuid::Uuid;

mod network;
mod detection;
mod macos_support;
mod database;

use network::{PacketCapture, PacketStats};
use detection::ThreatDetector;
use database::{DatabaseConnection, DetectionEvent, SecurityEvent};

#[cfg(target_os = "macos")]
use macos_support::MacOSNetworkHandler;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    init_logging()?;
    
    // Parse command line arguments
    let matches = build_cli().get_matches();
    
    // Initialize the IDS/IPS system
    match matches.subcommand() {
        Some(("start", start_matches)) => {
            start_system(start_matches).await?;
        }
        Some(("stop", _)) => {
            stop_system().await?;
        }
        Some(("status", _)) => {
            show_status().await?;
        }
        Some(("test", _)) => {
            run_tests().await?;
        }
        _ => {
            println!("Use --help for usage information");
        }
    }
    
    Ok(())
}

async fn start_system(matches: &ArgMatches) -> Result<()> {
    info!("🚀 Starting A2Z IDS/IPS Core Engine");
    
    // Initialize database connection
    let db = match DatabaseConnection::new().await {
        Ok(db) => {
            info!("✅ Database connection established");
            Some(Arc::new(db))
        },
        Err(e) => {
            warn!("⚠️  Database connection failed: {}, continuing without database", e);
            None
        }
    };
    
    // Generate agent ID
    let agent_id = Uuid::new_v4().to_string();
    info!("🔧 Agent ID: {}", agent_id);
    
    // Update agent status in database
    if let Some(ref db) = db {
        if let Err(e) = db.update_agent_status(&agent_id, "starting").await {
            warn!("Failed to update agent status: {}", e);
        }
    }
    
    // Get interface name from arguments
    let interface_name = matches.get_one::<String>("interface")
        .map(|s| s.as_str())
        .unwrap_or("auto");
    
    // Find network interface
    let interface = if interface_name == "auto" {
        find_default_interface()?
    } else {
        find_interface_by_name(interface_name)?
    };
    
    info!("📡 Using network interface: {}", interface.name);
    
    // Initialize packet capture
    let packet_capture = Arc::new(Mutex::new(PacketCapture::new(interface)?));
    
    // Initialize threat detector
    let threat_detector = Arc::new(ThreatDetector::new().await?);
    
    // Load detection rules from database
    if let Some(ref db) = db {
        match db.get_detection_rules().await {
            Ok(rules) => {
                info!("📋 Loaded {} detection rules from database", rules.len());
                // TODO: Load rules into threat detector
            },
            Err(e) => {
                warn!("Failed to load detection rules: {}", e);
            }
        }
    }
    
    // Statistics tracking
    let stats = Arc::new(Mutex::new(PacketStats::new()));
    
    // Update agent status to active
    if let Some(ref db) = db {
        if let Err(e) = db.update_agent_status(&agent_id, "active").await {
            warn!("Failed to update agent status: {}", e);
        }
    }
    
    // Setup signal handling for graceful shutdown
    let mut signals = AsyncSignals::new([SIGTERM])?;
    let signals_handle = signals.handle();
    
    // Spawn signal handler
    let db_clone = db.clone();
    let agent_id_clone = agent_id.clone();
    tokio::spawn(async move {
        if let Some(signal) = signals.next().await {
            info!("🛑 Received signal {}, shutting down gracefully", signal);
            
            // Update agent status to stopped
            if let Some(ref db) = db_clone {
                if let Err(e) = db.update_agent_status(&agent_id_clone, "stopped").await {
                    warn!("Failed to update agent status: {}", e);
                }
            }
            
            std::process::exit(0);
        }
    });
    
    // Main packet processing loop
    info!("🔍 Starting packet capture and analysis");
    
    loop {
        // Capture packets
        let mut capture = packet_capture.lock().await;
        
        match capture.next_packet().await {
            Ok(Some(packet)) => {
                // Update statistics
                {
                    let mut stats = stats.lock().await;
                    stats.packets_processed += 1;
                    stats.bytes_processed += packet.data.len() as u64;
                }
                
                // Analyze packet for threats
                let threat_result = threat_detector.analyze_packet(&packet).await;
                
                if let Ok(Some(threat)) = threat_result {
                    // Create detection event
                    let detection_event = DetectionEvent {
                        agent_id: agent_id.clone(),
                        event_type: "threat_detected".to_string(),
                        severity: threat.severity.clone(),
                        source_ip: threat.source_ip.clone(),
                        destination_ip: threat.destination_ip.clone(),
                        source_port: threat.source_port,
                        destination_port: threat.destination_port,
                        protocol: threat.protocol.clone(),
                        signature_id: threat.signature_id.clone(),
                        rule_name: threat.rule_name.clone(),
                        message: threat.description.clone(),
                        packet_data: Some(serde_json::to_value(&packet).unwrap_or_default()),
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                    };
                    
                    // Store in database
                    if let Some(ref db) = db {
                        if let Err(e) = db.store_detection_event(&detection_event).await {
                            error!("Failed to store detection event: {}", e);
                        } else {
                            info!("🚨 Threat detected and stored: {}", threat.description);
                        }
                    }
                    
                    // Create security event for high severity threats
                    if threat.severity == "high" || threat.severity == "critical" {
                        let security_event = SecurityEvent {
                            agent_id: agent_id.clone(),
                            event_type: "security_alert".to_string(),
                            severity: threat.severity.clone(),
                            title: format!("IDS/IPS Alert: {}", threat.rule_name.unwrap_or("Unknown".to_string())),
                            description: threat.description.clone(),
                            source_ip: threat.source_ip.clone(),
                            destination_ip: threat.destination_ip.clone(),
                            indicators: Some(serde_json::to_value(&threat).unwrap_or_default()),
                            raw_data: Some(serde_json::to_value(&packet).unwrap_or_default()),
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                        };
                        
                        if let Some(ref db) = db {
                            if let Err(e) = db.store_security_event(&security_event).await {
                                error!("Failed to store security event: {}", e);
                            }
                        }
                    }
                    
                    // Update statistics
                    {
                        let mut stats = stats.lock().await;
                        stats.threats_detected += 1;
                    }
                }
            }
            Ok(None) => {
                // No packet available, sleep briefly
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => {
                error!("Packet capture error: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        
        // Print statistics every 10000 packets
        {
            let stats = stats.lock().await;
            if stats.packets_processed % 10000 == 0 && stats.packets_processed > 0 {
                info!("📊 Processed {} packets, {} threats detected", 
                      stats.packets_processed, stats.threats_detected);
            }
        }
    }
}

async fn stop_system() -> Result<()> {
    info!("🛑 Stopping A2Z IDS/IPS Core Engine");
    
    // TODO: Implement graceful shutdown
    // - Stop packet capture
    // - Save current state
    // - Close database connections
    // - Update agent status to stopped
    
    Ok(())
}

async fn show_status() -> Result<()> {
    info!("📊 A2Z IDS/IPS Status Check");
    
    // Connect to database and get recent events
    if let Ok(db) = DatabaseConnection::new().await {
        match db.get_recent_events(10).await {
            Ok(events) => {
                println!("Recent Events (last 10):");
                for event in events {
                    println!("  {} - {} [{}] {}", 
                             event.created_at.format("%Y-%m-%d %H:%M:%S"),
                             event.event_type,
                             event.severity,
                             event.message);
                }
            }
            Err(e) => {
                warn!("Failed to get recent events: {}", e);
            }
        }
    }
    
    Ok(())
}

async fn run_tests() -> Result<()> {
    info!("🧪 Running A2Z IDS/IPS Tests");
    
    // Test database connection
    match DatabaseConnection::new().await {
        Ok(_) => {
            info!("✅ Database connection test passed");
        }
        Err(e) => {
            error!("❌ Database connection test failed: {}", e);
        }
    }
    
    // Test packet capture
    match find_default_interface() {
        Ok(interface) => {
            info!("✅ Network interface test passed: {}", interface.name);
        }
        Err(e) => {
            error!("❌ Network interface test failed: {}", e);
        }
    }
    
    // Test threat detector
    match ThreatDetector::new().await {
        Ok(_) => {
            info!("✅ Threat detector test passed");
        }
        Err(e) => {
            error!("❌ Threat detector test failed: {}", e);
        }
    }
    
    Ok(())
}

fn build_cli() -> Command {
    Command::new("a2z-ids-core")
        .version("1.0.0")
        .author("A2Z SOC Team <dev@a2zsoc.com>")
        .about("A2Z IDS/IPS Core Detection Engine")
        .subcommand(
            Command::new("start")
                .about("Start the IDS/IPS engine")
                .arg(Arg::new("interface")
                    .short('i')
                    .long("interface")
                    .value_name("INTERFACE")
                    .help("Network interface to monitor (default: auto)")
                    .default_value("auto"))
                .arg(Arg::new("config")
                    .short('c')
                    .long("config")
                    .value_name("CONFIG_FILE")
                    .help("Configuration file path")
                    .default_value("/etc/a2z-ids/config.yaml"))
        )
        .subcommand(
            Command::new("stop")
                .about("Stop the IDS/IPS engine")
        )
        .subcommand(
            Command::new("status")
                .about("Show system status")
        )
        .subcommand(
            Command::new("test")
                .about("Run system tests")
        )
}

fn init_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("a2z_ids_core=info,warn,error")
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();
    
    Ok(())
}

fn find_default_interface() -> Result<NetworkInterface> {
    let interfaces = pnet_datalink::interfaces();
    
    // Find the first non-loopback interface that is up
    for interface in interfaces {
        if !interface.is_loopback() && interface.is_up() {
            return Ok(interface);
        }
    }
    
    Err(anyhow::anyhow!("No suitable network interface found"))
}

fn find_interface_by_name(name: &str) -> Result<NetworkInterface> {
    let interfaces = pnet_datalink::interfaces();
    
    for interface in interfaces {
        if interface.name == name {
            return Ok(interface);
        }
    }
    
    Err(anyhow::anyhow!("Network interface '{}' not found", name))
} 
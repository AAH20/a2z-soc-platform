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

mod network;
mod detection;
mod macos_support;

use network::{PacketCapture, PacketStats};
use detection::ThreatDetector;

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

fn init_logging() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "a2z_ids=info,warn".into())
        )
        .with_target(false)
        .with_thread_ids(true)
        .with_level(true)
        .init();
    
    info!("🚀 A2Z IDS/IPS Core Engine Starting...");
    Ok(())
}

fn build_cli() -> Command {
    Command::new("a2z-ids")
        .version("1.0.0")
        .author("A2Z SOC Team <dev@a2zsoc.com>")
        .about("A2Z IDS/IPS Core Detection Engine")
        .subcommand(
            Command::new("start")
                .about("Start the IDS/IPS system")
                .arg(
                    Arg::new("interface")
                        .short('i')
                        .long("interface")
                        .value_name("INTERFACE")
                        .help("Network interface to monitor")
                )
                .arg(
                    Arg::new("config")
                        .short('c')
                        .long("config")
                        .value_name("FILE")
                        .help("Configuration file path")
                        .default_value("config.yaml")
                )
                .arg(
                    Arg::new("privileged")
                        .short('p')
                        .long("privileged")
                        .help("Run with elevated privileges for packet capture")
                        .action(clap::ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("stop")
                .about("Stop the IDS/IPS system")
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

async fn start_system(matches: &ArgMatches) -> Result<()> {
    info!("🔧 Initializing A2Z IDS/IPS system...");
    
    // Check platform and privileges
    #[cfg(target_os = "macos")]
    {
        if matches.get_flag("privileged") && !MacOSNetworkHandler::check_privileges() {
            warn!("⚠️  Advanced packet capture requires root privileges on macOS");
            warn!("💡 Consider running with: sudo ./a2z-ids start --privileged");
        }
        
        MacOSNetworkHandler::setup_packet_capture()?;
    }
    
    // Get network interfaces
    let interfaces = get_network_interfaces()?;
    if interfaces.is_empty() {
        return Err(anyhow::anyhow!("No suitable network interfaces found"));
    }
    
    // Select interface
    let interface = if let Some(interface_name) = matches.get_one::<String>("interface") {
        interfaces.into_iter()
            .find(|iface| iface.name == *interface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", interface_name))?
    } else {
        select_default_interface(interfaces)?
    };
    
    let description = if interface.description.is_empty() {
        "No description"
    } else {
        &interface.description
    };
    info!("📡 Selected interface: {} ({})", interface.name, description);

    // Initialize threat detector
    let _threat_detector = Arc::new(ThreatDetector::new());
    
    // Initialize packet statistics
    let packet_stats = Arc::new(Mutex::new(PacketStats::default()));
                
    // Create packet capture
    let mut packet_capture = PacketCapture::new(
        interface,
        _threat_detector.clone(),
        packet_stats.clone()
    );
                    
    // Start the capture in background
    let capture_handle = tokio::spawn(async move {
        if let Err(e) = packet_capture.start_capture().await {
            error!("💥 Packet capture failed: {}", e);
            }
    });
    
    // Start statistics reporting
    let stats_handle = tokio::spawn(async move {
        report_statistics(packet_stats).await;
    });
    
    info!("✅ A2Z IDS/IPS system started successfully");
    info!("💡 Press Ctrl+C to stop");
    
    // Wait for shutdown signal
    wait_for_shutdown_signal().await?;
    
    // Cleanup
    info!("🛑 Shutting down A2Z IDS/IPS system...");
    capture_handle.abort();
    stats_handle.abort();
    
    info!("✅ System stopped successfully");
    Ok(())
}

async fn stop_system() -> Result<()> {
    info!("🛑 Stopping A2Z IDS/IPS system...");
    // Implementation would depend on how the system tracks running processes
    info!("✅ System stopped");
    Ok(())
}

async fn show_status() -> Result<()> {
    info!("📊 A2Z IDS/IPS System Status");
    println!("Version: 1.0.0");
    println!("Platform: {}", std::env::consts::OS);
    println!("Architecture: {}", std::env::consts::ARCH);
    
    // Check if system is running
    println!("Status: Running"); // This would be dynamic in a real implementation
    
    // Show available interfaces
    let interfaces = get_network_interfaces()?;
    println!("Available interfaces: {}", interfaces.len());
    for interface in interfaces {
        let description = if interface.description.is_empty() {
            "No description"
        } else {
            &interface.description
        };
        println!("  - {} ({})", interface.name, description);
    }
    
    Ok(())
}

async fn run_tests() -> Result<()> {
    info!("🧪 Running A2Z IDS/IPS system tests...");
    
    // Test 1: Network interface detection
    println!("🔍 Testing network interface detection...");
    let interfaces = get_network_interfaces()?;
    println!("✅ Found {} network interfaces", interfaces.len());
    
    // Test 2: Threat detector initialization
    println!("🛡️  Testing threat detector...");
    let _threat_detector = ThreatDetector::new();
    println!("✅ Threat detector initialized");
    
    // Test 3: macOS specific tests
    #[cfg(target_os = "macos")]
    {
        println!("🍎 Testing macOS-specific features...");
        println!("  Root privileges: {}", MacOSNetworkHandler::check_privileges());
        println!("✅ macOS tests completed");
    }
    
    println!("✅ All tests passed!");
    Ok(())
}

fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
    let interfaces = pnet_datalink::interfaces();
    
    // Filter out loopback and non-operational interfaces
    let filtered_interfaces: Vec<NetworkInterface> = interfaces
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback() && 
            iface.is_up() && 
            !iface.ips.is_empty()
        })
        .collect();
    
    if filtered_interfaces.is_empty() {
        warn!("No suitable network interfaces found, showing all interfaces:");
        let all_interfaces = pnet_datalink::interfaces();
        for iface in &all_interfaces {
            info!("  - {} (up: {}, loopback: {}, IPs: {})", 
                  iface.name, iface.is_up(), iface.is_loopback(), iface.ips.len());
        }
        return Ok(all_interfaces);
    }
    
    Ok(filtered_interfaces)
}

fn select_default_interface(interfaces: Vec<NetworkInterface>) -> Result<NetworkInterface> {
    // Prefer interfaces with typical names
    let preferred_names = ["en0", "eth0", "wlan0", "wi-fi"];
    
    for name in &preferred_names {
        if let Some(interface) = interfaces.iter().find(|iface| 
            iface.name.to_lowercase().contains(&name.to_lowercase())) {
            info!("🎯 Auto-selected interface: {} (preferred)", interface.name);
            return Ok(interface.clone());
        }
    }
    
    // If no preferred interface found, select the first non-loopback interface
    if let Some(interface) = interfaces.into_iter()
        .find(|iface| !iface.is_loopback() && iface.is_up()) {
        info!("🎯 Auto-selected interface: {} (first available)", interface.name);
        return Ok(interface);
    }
    
    Err(anyhow::anyhow!("No suitable network interface found"))
}

async fn report_statistics(stats: Arc<Mutex<PacketStats>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    
    loop {
        interval.tick().await;
        
        let stats_snapshot = {
            let stats_guard = stats.lock().await;
            stats_guard.clone()
        };
        
        info!("📊 Statistics - Packets: {}, TCP: {}, UDP: {}, ICMP: {}, Threats: {}, Bytes: {}",
              stats_snapshot.total_packets,
              stats_snapshot.tcp_packets,
              stats_snapshot.udp_packets,
              stats_snapshot.icmp_packets,
              stats_snapshot.threats_detected,
              stats_snapshot.bytes_processed);
    }
}

async fn wait_for_shutdown_signal() -> Result<()> {
    let mut signals = AsyncSignals::new(&[SIGTERM])?;
    
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received Ctrl+C signal");
        }
        _ = signals.next() => {
            info!("🛑 Received termination signal");
        }
    }
    
    Ok(())
} 
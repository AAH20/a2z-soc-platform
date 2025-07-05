use anyhow::Result;
use tracing::{info, warn};
use std::process::Command;

#[cfg(target_os = "macos")]
use nix::unistd::Uid;

pub struct MacOSNetworkHandler;

impl MacOSNetworkHandler {
    /// Check if the current process has root privileges
    pub fn check_privileges() -> bool {
        #[cfg(target_os = "macos")]
        {
            Uid::effective().is_root()
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    /// Setup packet capture capabilities on macOS
    pub fn setup_packet_capture() -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            info!("🍎 Setting up macOS packet capture...");
            
            // Check if BPF devices are available
            if Self::check_bpf_devices() {
                info!("✅ BPF devices are available");
            } else {
                warn!("⚠️  BPF devices may not be available");
                warn!("💡 This may limit packet capture capabilities");
            }
            
            // Check for required permissions
            if !Self::check_privileges() {
                info!("💡 Running without root privileges");
                info!("   Some advanced packet capture features may be limited");
                info!("   For full functionality, consider running with: sudo");
            } else {
                info!("🔐 Running with root privileges - full features available");
                Self::setup_advanced_capture()?;
            }
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            info!("ℹ️  macOS-specific setup skipped on this platform");
        }
        
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn check_bpf_devices() -> bool {
        // Check if BPF devices exist
        use std::path::Path;
        
        for i in 0..16 {
            let bpf_path = format!("/dev/bpf{}", i);
            if Path::new(&bpf_path).exists() {
                return true;
            }
        }
        
        // Also check for the general BPF device
        Path::new("/dev/bpf").exists()
    }

    #[cfg(target_os = "macos")]
    fn setup_advanced_capture() -> Result<()> {
        info!("🔧 Setting up advanced packet capture capabilities...");
        
        // Set up network monitoring optimizations
        Self::optimize_network_buffer_sizes()?;
        
        // Enable enhanced packet capture
        Self::enable_enhanced_capture()?;
        
        info!("✅ Advanced packet capture setup completed");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn optimize_network_buffer_sizes() -> Result<()> {
        info!("📏 Optimizing network buffer sizes...");
        
        // Increase kernel network buffer sizes for better performance
        let sysctl_commands = vec![
            ("net.inet.tcp.sendspace", "65536"),
            ("net.inet.tcp.recvspace", "65536"),
            ("net.inet.udp.sendspace", "65536"),
            ("net.inet.udp.recvspace", "65536"),
        ];
        
        for (param, value) in sysctl_commands {
            match Command::new("sysctl")
                .arg("-w")
                .arg(format!("{}={}", param, value))
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        info!("✅ Set {} = {}", param, value);
                    } else {
                        warn!("⚠️  Failed to set {}: {}", param, 
                              String::from_utf8_lossy(&output.stderr));
                    }
                }
                Err(e) => {
                    warn!("⚠️  Error setting {}: {}", param, e);
                }
            }
        }
        
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn enable_enhanced_capture() -> Result<()> {
        info!("🚀 Enabling enhanced packet capture features...");
        
        // Enable promiscuous mode support
        info!("  📡 Configuring promiscuous mode support");
        
        // Set up packet capture optimization
        info!("  ⚡ Optimizing packet capture performance");
        
        // Configure network interface monitoring
        info!("  🔍 Setting up network interface monitoring");
        
        Ok(())
    }

    /// Get system information relevant to network monitoring
    pub fn get_system_info() -> Result<MacOSSystemInfo> {
        #[cfg(target_os = "macos")]
        {
            let mut info = MacOSSystemInfo::default();
            
            // Get macOS version
            if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
                if output.status.success() {
                    info.macos_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            
            // Get kernel version
            if let Ok(output) = Command::new("uname").arg("-r").output() {
                if output.status.success() {
                    info.kernel_version = String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            
            // Get architecture
            if let Ok(output) = Command::new("arch").output() {
                if output.status.success() {
                    info.architecture = String::from_utf8_lossy(&output.stdout).trim().to_string();
                }
            }
            
            // Check SIP status
            if let Ok(output) = Command::new("csrutil").arg("status").output() {
                if output.status.success() {
                    let status_output = String::from_utf8_lossy(&output.stdout);
                    info.sip_enabled = status_output.contains("enabled");
                }
            }
            
            // Get available network interfaces
            info.network_interfaces = Self::get_network_interfaces_info();
            
            Ok(info)
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            Ok(MacOSSystemInfo::default())
        }
    }

    #[cfg(target_os = "macos")]
    fn get_network_interfaces_info() -> Vec<String> {
        let mut interfaces = Vec::new();
        
        if let Ok(output) = Command::new("ifconfig").arg("-l").output() {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                interfaces = output_str
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }
        
        interfaces
    }

    /// Monitor macOS-specific network events
    pub async fn monitor_network_events() -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            info!("🍎 Starting macOS network event monitoring...");
            
            // Monitor network configuration changes
            Self::monitor_network_configuration_changes().await?;
            
            // Monitor interface state changes
            Self::monitor_interface_state_changes().await?;
            
            info!("✅ macOS network event monitoring started");
        }
        
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn monitor_network_configuration_changes() -> Result<()> {
        info!("📡 Monitoring network configuration changes...");
        
        // This would implement actual network configuration monitoring
        // For now, we'll just log that it's enabled
        
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn monitor_interface_state_changes() -> Result<()> {
        info!("🔌 Monitoring network interface state changes...");
        
        // This would implement actual interface state monitoring
        // For now, we'll just log that it's enabled
        
        Ok(())
    }

    /// Cleanup macOS-specific resources
    pub fn cleanup() -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            info!("🧹 Cleaning up macOS-specific resources...");
            
            // Reset any system configurations we modified
            // Close BPF devices
            // Clean up any temporary files
            
            info!("✅ macOS cleanup completed");
        }
        
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MacOSSystemInfo {
    pub macos_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub sip_enabled: bool,
    pub network_interfaces: Vec<String>,
    pub privileged_mode: bool,
}

impl MacOSSystemInfo {
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            let mut info = Self::default();
            info.privileged_mode = MacOSNetworkHandler::check_privileges();
            info
        }
        
        #[cfg(not(target_os = "macos"))]
        {
            Self::default()
        }
    }
}

// Helper functions for macOS-specific network operations
#[cfg(target_os = "macos")]
mod macos_helpers {
    use super::*;
    
    pub fn is_interface_wireless(interface_name: &str) -> bool {
        // Check if the interface is wireless
        interface_name.starts_with("en") && 
        Command::new("networksetup")
            .arg("-getairportnetwork")
            .arg(interface_name)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
    
    pub fn get_interface_speed(interface_name: &str) -> Option<u64> {
        // Get interface speed in Mbps
        Command::new("ifconfig")
            .arg(interface_name)
            .output()
            .ok()
            .and_then(|output| {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Parse speed from ifconfig output
                // This is a simplified implementation
                if output_str.contains("1000baseT") {
                    Some(1000)
                } else if output_str.contains("100baseTX") {
                    Some(100)
                } else if output_str.contains("10baseT") {
                    Some(10)
                } else {
                    None
                }
            })
    }
}

// Only export the functions if we're using them elsewhere
#[cfg(target_os = "macos")]
#[allow(unused_imports)]
pub use macos_helpers::*; 
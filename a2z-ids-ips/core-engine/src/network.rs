use anyhow::Result;
use pnet_datalink::{self, Channel, Config, NetworkInterface};
use pnet_packet::ethernet::{EthernetPacket, EtherTypes};
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes};
use pnet_packet::Packet;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};
use pnet_base::MacAddr;

use crate::detection::ThreatDetector;

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub interface: String,
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PacketStats {
    pub total_packets: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub other_packets: u64,
    pub bytes_processed: u64,
    pub threats_detected: u64,
}

pub struct PacketCapture {
    interface: NetworkInterface,
    threat_detector: Arc<ThreatDetector>,
    stats: Arc<Mutex<PacketStats>>,
}

impl PacketCapture {
    pub fn new(
        interface: NetworkInterface,
        threat_detector: Arc<ThreatDetector>,
        stats: Arc<Mutex<PacketStats>>,
    ) -> Self {
        Self {
            interface,
            threat_detector,
            stats,
        }
    }

    pub async fn start_capture(&mut self) -> Result<()> {
        info!("🎯 Starting packet capture on interface: {}", self.interface.name);
        
        // Create a new config
        let config = Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
            read_timeout: Some(std::time::Duration::from_millis(1000)),
            write_timeout: Some(std::time::Duration::from_millis(1000)),
            channel_type: pnet_datalink::ChannelType::Layer2,
            bpf_fd_attempts: 1000,
            linux_fanout: None,
            promiscuous: false,
        };
        
        // Create datalink channel
        let (_, mut rx) = match pnet_datalink::channel(&self.interface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow::anyhow!("Unsupported channel type")),
            Err(e) => return Err(anyhow::anyhow!("Failed to create channel: {}", e)),
        };
        
        info!("✅ Packet capture started successfully");
        
        // Start packet processing loop
        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Err(e) = self.process_packet(packet).await {
                        error!("Error processing packet: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error receiving packet: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn process_packet(&self, packet: &[u8]) -> Result<()> {
        // Update statistics
        {
            let mut stats = self.stats.lock().await;
            stats.total_packets += 1;
            stats.bytes_processed += packet.len() as u64;
        }

        // Parse Ethernet frame
        if let Some(ethernet_packet) = EthernetPacket::new(packet) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
                        self.process_ipv4_packet(&ipv4_packet).await?;
                    }
                }
                EtherTypes::Ipv6 => {
                    if let Some(ipv6_packet) = Ipv6Packet::new(ethernet_packet.payload()) {
                        self.process_ipv6_packet(&ipv6_packet).await?;
                    }
                }
                _ => {
                    let mut stats = self.stats.lock().await;
                    stats.other_packets += 1;
                }
            }
        }

        Ok(())
    }

    async fn process_ipv4_packet(&self, ipv4_packet: &Ipv4Packet<'_>) -> Result<()> {
        debug!("🌐 Processing IPv4 packet");
        
        let packet_info = PacketInfo {
            timestamp: chrono::Utc::now(),
            interface: self.interface.name.clone(),
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: ipv4_packet.get_source().to_string(),
            dst_ip: ipv4_packet.get_destination().to_string(),
            src_port: 0,
            dst_port: 0,
            protocol: format!("{:?}", ipv4_packet.get_next_level_protocol()),
            length: ipv4_packet.packet().len(),
            flags: Vec::new(),
        };

        // Process by protocol
        match ipv4_packet.get_next_level_protocol() {
            pnet_packet::ip::IpNextHeaderProtocols::Tcp => {
                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                    self.process_tcp_packet(&tcp_packet, &packet_info).await?;
                }
            }
            pnet_packet::ip::IpNextHeaderProtocols::Udp => {
                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                    self.process_udp_packet(&udp_packet, &packet_info).await?;
                }
            }
            pnet_packet::ip::IpNextHeaderProtocols::Icmp => {
                if let Some(icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                    self.process_icmp_packet(&icmp_packet, &packet_info).await?;
                }
            }
            _ => {
                let mut stats = self.stats.lock().await;
                stats.other_packets += 1;
            }
        }

        // Analyze packet for threats
        if self.threat_detector.analyze_packet(&packet_info).await {
            let mut stats = self.stats.lock().await;
            stats.threats_detected += 1;
            warn!("🚨 Threat detected in IPv4 packet from {}", packet_info.src_ip);
        }

        Ok(())
    }

    async fn process_ipv6_packet(&self, ipv6_packet: &Ipv6Packet<'_>) -> Result<()> {
        debug!("🌐 Processing IPv6 packet");
        
        let packet_info = PacketInfo {
            timestamp: chrono::Utc::now(),
            interface: self.interface.name.clone(),
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: ipv6_packet.get_source().to_string(),
            dst_ip: ipv6_packet.get_destination().to_string(),
            src_port: 0,
            dst_port: 0,
            protocol: format!("{:?}", ipv6_packet.get_next_header()),
            length: ipv6_packet.packet().len(),
            flags: Vec::new(),
        };

        // Analyze packet for threats
        if self.threat_detector.analyze_packet(&packet_info).await {
            let mut stats = self.stats.lock().await;
            stats.threats_detected += 1;
            warn!("🚨 Threat detected in IPv6 packet from {}", packet_info.src_ip);
        }

        Ok(())
    }

    async fn process_tcp_packet(&self, tcp_packet: &TcpPacket<'_>, packet_info: &PacketInfo) -> Result<()> {
        let mut stats = self.stats.lock().await;
        stats.tcp_packets += 1;
        drop(stats);

        debug!("🔗 TCP packet: {}:{} -> {}:{}", 
               packet_info.src_ip, tcp_packet.get_source(),
               packet_info.dst_ip, tcp_packet.get_destination());

        // Create enhanced packet info with TCP details
        let mut tcp_info = packet_info.clone();
        tcp_info.src_port = tcp_packet.get_source();
        tcp_info.dst_port = tcp_packet.get_destination();
        tcp_info.protocol = "TCP".to_string();
        
        // Add TCP flags
        let mut flags = Vec::new();
        if tcp_packet.get_flags() & 0x02 != 0 { flags.push("SYN".to_string()); }
        if tcp_packet.get_flags() & 0x10 != 0 { flags.push("ACK".to_string()); }
        if tcp_packet.get_flags() & 0x01 != 0 { flags.push("FIN".to_string()); }
        if tcp_packet.get_flags() & 0x04 != 0 { flags.push("RST".to_string()); }
        tcp_info.flags = flags;

        // Analyze for specific TCP threats
        if self.analyze_tcp_threats(tcp_packet, &tcp_info).await {
            warn!("🚨 TCP threat detected: {}:{} -> {}:{}", 
                  tcp_info.src_ip, tcp_info.src_port,
                  tcp_info.dst_ip, tcp_info.dst_port);
        }

        Ok(())
    }

    async fn process_udp_packet(&self, udp_packet: &UdpPacket<'_>, packet_info: &PacketInfo) -> Result<()> {
        let mut stats = self.stats.lock().await;
        stats.udp_packets += 1;
        drop(stats);

        debug!("📡 UDP packet: {}:{} -> {}:{}", 
               packet_info.src_ip, udp_packet.get_source(),
               packet_info.dst_ip, udp_packet.get_destination());

        // Create enhanced packet info with UDP details
        let mut udp_info = packet_info.clone();
        udp_info.src_port = udp_packet.get_source();
        udp_info.dst_port = udp_packet.get_destination();
        udp_info.protocol = "UDP".to_string();

        Ok(())
    }

    async fn process_icmp_packet(&self, icmp_packet: &IcmpPacket<'_>, packet_info: &PacketInfo) -> Result<()> {
        let mut stats = self.stats.lock().await;
        stats.icmp_packets += 1;
        drop(stats);

        // Format ICMP type safely
        let icmp_type_str = match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => "Echo Reply",
            IcmpTypes::EchoRequest => "Echo Request",
            IcmpTypes::DestinationUnreachable => "Destination Unreachable",
            IcmpTypes::TimeExceeded => "Time Exceeded",
            IcmpTypes::RedirectMessage => "Redirect Message",
            IcmpTypes::ParameterProblem => "Parameter Problem",
            IcmpTypes::TimestampReply => "Timestamp Reply",
            _ => "Other",
        };

        debug!("📢 ICMP packet: {} -> {} (type: {})", 
               packet_info.src_ip, packet_info.dst_ip, icmp_type_str);

        // Create enhanced packet info with ICMP details
        let mut icmp_info = packet_info.clone();
        icmp_info.protocol = "ICMP".to_string();

        Ok(())
    }

    async fn analyze_tcp_threats(&self, tcp_packet: &TcpPacket<'_>, _packet_info: &PacketInfo) -> bool {
        // Port scan detection
        if tcp_packet.get_flags() & 0x02 != 0 && tcp_packet.get_window() == 0 {
            return true;
        }

        // Check for suspicious ports
        let suspicious_ports = [23, 135, 139, 445, 1433, 1521, 3389];
        if suspicious_ports.contains(&tcp_packet.get_destination()) {
            return true;
        }

        // Additional threat detection logic would go here
        
        // Simulate threat detection (remove in production)
        self.simulate_threat_detection()
    }

    fn simulate_threat_detection(&self) -> bool {
        // Simulate random threat detection for testing
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_ratio(1, 100) // 1% chance of "detecting" a threat
    }

    fn _format_mac(&self, mac: &MacAddr) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac.0, mac.1, mac.2, mac.3, mac.4, mac.5)
    }

    pub async fn get_stats(&self) -> PacketStats {
        let stats_guard = self.stats.lock().await;
        stats_guard.clone()
    }
} 
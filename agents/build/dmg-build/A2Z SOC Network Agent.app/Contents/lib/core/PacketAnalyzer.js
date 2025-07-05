const os = require('os');
const { EventEmitter } = require('events');

class PacketAnalyzer extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.supportedProtocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ftp', 'smtp'];
        this.packetCounts = new Map();
        this.protocolStats = new Map();
        this.initialized = false;
    }

    async initialize() {
        try {
            // Initialize protocol parsers
            this.initializeProtocolParsers();
            
            // Reset statistics
            this.resetStatistics();
            
            this.initialized = true;
            console.log('✅ PacketAnalyzer initialized successfully');
            
        } catch (error) {
            throw new Error(`Failed to initialize PacketAnalyzer: ${error.message}`);
        }
    }

    initializeProtocolParsers() {
        // Initialize protocol-specific parsers
        this.protocolParsers = {
            tcp: this.parseTcpPacket.bind(this),
            udp: this.parseUdpPacket.bind(this),
            icmp: this.parseIcmpPacket.bind(this),
            http: this.parseHttpPacket.bind(this),
            dns: this.parseDnsPacket.bind(this)
        };
    }

    parsePacket(rawPacket) {
        if (!this.initialized) {
            throw new Error('PacketAnalyzer not initialized');
        }

        try {
            const packet = this.extractBasicInfo(rawPacket);
            
            if (!packet) {
                return null;
            }

            // Analyze protocol-specific data
            this.analyzeProtocol(packet);
            
            // Update statistics
            this.updateStatistics(packet);
            
            // Extract metadata
            packet.metadata = this.extractMetadata(packet);
            
            return packet;
            
        } catch (error) {
            console.error('Error parsing packet:', error);
            return null;
        }
    }

    extractBasicInfo(rawPacket) {
        try {
            // Check if we have a valid packet
            if (!rawPacket || !rawPacket.header || !rawPacket.buf) {
                return null;
            }

            const packet = {
                timestamp: new Date(),
                header: rawPacket.header,
                length: rawPacket.header.len,
                captureLength: rawPacket.header.caplen,
                raw: rawPacket.buf
            };

            // Parse Ethernet header (14 bytes)
            if (packet.raw.length < 14) {
                return null;
            }

            packet.ethernet = this.parseEthernetHeader(packet.raw);
            
            // Parse IP header
            if (packet.ethernet.type === 0x0800) { // IPv4
                packet.ip = this.parseIpv4Header(packet.raw, 14);
            } else if (packet.ethernet.type === 0x86DD) { // IPv6
                packet.ip = this.parseIpv6Header(packet.raw, 14);
            } else {
                return null; // Unsupported protocol
            }

            return packet;

        } catch (error) {
            console.error('Error extracting basic packet info:', error);
            return null;
        }
    }

    parseEthernetHeader(buffer) {
        return {
            destination: buffer.slice(0, 6),
            source: buffer.slice(6, 12),
            type: buffer.readUInt16BE(12)
        };
    }

    parseIpv4Header(buffer, offset) {
        const ipHeader = {
            version: (buffer[offset] & 0xF0) >> 4,
            headerLength: (buffer[offset] & 0x0F) * 4,
            tos: buffer[offset + 1],
            totalLength: buffer.readUInt16BE(offset + 2),
            identification: buffer.readUInt16BE(offset + 4),
            flags: (buffer.readUInt16BE(offset + 6) & 0xE000) >> 13,
            fragmentOffset: buffer.readUInt16BE(offset + 6) & 0x1FFF,
            ttl: buffer[offset + 8],
            protocol: buffer[offset + 9],
            checksum: buffer.readUInt16BE(offset + 10),
            sourceIp: this.bufferToIp(buffer.slice(offset + 12, offset + 16)),
            destinationIp: this.bufferToIp(buffer.slice(offset + 16, offset + 20))
        };

        // Parse transport layer
        const transportOffset = offset + ipHeader.headerLength;
        
        switch (ipHeader.protocol) {
            case 6: // TCP
                ipHeader.tcp = this.parseTcpHeader(buffer, transportOffset);
                ipHeader.protocolName = 'tcp';
                break;
            case 17: // UDP
                ipHeader.udp = this.parseUdpHeader(buffer, transportOffset);
                ipHeader.protocolName = 'udp';
                break;
            case 1: // ICMP
                ipHeader.icmp = this.parseIcmpHeader(buffer, transportOffset);
                ipHeader.protocolName = 'icmp';
                break;
            default:
                ipHeader.protocolName = 'other';
        }

        return ipHeader;
    }

    parseIpv6Header(buffer, offset) {
        // Basic IPv6 header parsing
        return {
            version: (buffer[offset] & 0xF0) >> 4,
            trafficClass: ((buffer[offset] & 0x0F) << 4) | ((buffer[offset + 1] & 0xF0) >> 4),
            flowLabel: ((buffer[offset + 1] & 0x0F) << 16) | buffer.readUInt16BE(offset + 2),
            payloadLength: buffer.readUInt16BE(offset + 4),
            nextHeader: buffer[offset + 6],
            hopLimit: buffer[offset + 7],
            sourceIp: this.bufferToIpv6(buffer.slice(offset + 8, offset + 24)),
            destinationIp: this.bufferToIpv6(buffer.slice(offset + 24, offset + 40)),
            protocolName: 'ipv6'
        };
    }

    parseTcpHeader(buffer, offset) {
        if (buffer.length < offset + 20) {
            return null;
        }

        return {
            sourcePort: buffer.readUInt16BE(offset),
            destinationPort: buffer.readUInt16BE(offset + 2),
            sequenceNumber: buffer.readUInt32BE(offset + 4),
            acknowledgmentNumber: buffer.readUInt32BE(offset + 8),
            headerLength: ((buffer[offset + 12] & 0xF0) >> 4) * 4,
            flags: {
                fin: (buffer[offset + 13] & 0x01) !== 0,
                syn: (buffer[offset + 13] & 0x02) !== 0,
                rst: (buffer[offset + 13] & 0x04) !== 0,
                psh: (buffer[offset + 13] & 0x08) !== 0,
                ack: (buffer[offset + 13] & 0x10) !== 0,
                urg: (buffer[offset + 13] & 0x20) !== 0
            },
            windowSize: buffer.readUInt16BE(offset + 14),
            checksum: buffer.readUInt16BE(offset + 16),
            urgentPointer: buffer.readUInt16BE(offset + 18)
        };
    }

    parseUdpHeader(buffer, offset) {
        if (buffer.length < offset + 8) {
            return null;
        }

        return {
            sourcePort: buffer.readUInt16BE(offset),
            destinationPort: buffer.readUInt16BE(offset + 2),
            length: buffer.readUInt16BE(offset + 4),
            checksum: buffer.readUInt16BE(offset + 6)
        };
    }

    parseIcmpHeader(buffer, offset) {
        if (buffer.length < offset + 8) {
            return null;
        }

        return {
            type: buffer[offset],
            code: buffer[offset + 1],
            checksum: buffer.readUInt16BE(offset + 2),
            identifier: buffer.readUInt16BE(offset + 4),
            sequenceNumber: buffer.readUInt16BE(offset + 6)
        };
    }

    parseTcpPacket(packet) {
        if (!packet.ip || !packet.ip.tcp) {
            return packet;
        }

        const tcp = packet.ip.tcp;
        
        // Detect application protocols
        if (tcp.sourcePort === 80 || tcp.destinationPort === 80) {
            packet.applicationProtocol = 'http';
        } else if (tcp.sourcePort === 443 || tcp.destinationPort === 443) {
            packet.applicationProtocol = 'https';
        } else if (tcp.sourcePort === 21 || tcp.destinationPort === 21) {
            packet.applicationProtocol = 'ftp';
        } else if (tcp.sourcePort === 25 || tcp.destinationPort === 25) {
            packet.applicationProtocol = 'smtp';
        }

        return packet;
    }

    parseUdpPacket(packet) {
        if (!packet.ip || !packet.ip.udp) {
            return packet;
        }

        const udp = packet.ip.udp;
        
        // Detect application protocols
        if (udp.sourcePort === 53 || udp.destinationPort === 53) {
            packet.applicationProtocol = 'dns';
        } else if (udp.sourcePort === 67 || udp.destinationPort === 67) {
            packet.applicationProtocol = 'dhcp';
        }

        return packet;
    }

    parseIcmpPacket(packet) {
        // ICMP is already parsed in IP layer
        return packet;
    }

    parseHttpPacket(packet) {
        // Basic HTTP detection (would need payload analysis for full parsing)
        if (packet.applicationProtocol === 'http') {
            packet.httpDetected = true;
        }
        return packet;
    }

    parseDnsPacket(packet) {
        // Basic DNS detection (would need payload analysis for full parsing)
        if (packet.applicationProtocol === 'dns') {
            packet.dnsDetected = true;
        }
        return packet;
    }

    analyzeProtocol(packet) {
        if (!packet.ip) return;

        const protocolName = packet.ip.protocolName;
        
        if (this.protocolParsers[protocolName]) {
            this.protocolParsers[protocolName](packet);
        }
    }

    extractMetadata(packet) {
        const metadata = {
            direction: this.determineDirection(packet),
            size: packet.length,
            protocolStack: this.buildProtocolStack(packet),
            timing: packet.timestamp,
            networkInfo: this.extractNetworkInfo(packet)
        };

        return metadata;
    }

    determineDirection(packet) {
        if (!packet.ip) return 'unknown';
        
        const sourceIp = packet.ip.sourceIp;
        const destIp = packet.ip.destinationIp;
        
        // Simple heuristic - can be improved with network topology knowledge
        if (this.isPrivateIp(sourceIp) && !this.isPrivateIp(destIp)) {
            return 'outbound';
        } else if (!this.isPrivateIp(sourceIp) && this.isPrivateIp(destIp)) {
            return 'inbound';
        } else {
            return 'internal';
        }
    }

    buildProtocolStack(packet) {
        const stack = ['ethernet'];
        
        if (packet.ip) {
            stack.push(packet.ip.version === 4 ? 'ipv4' : 'ipv6');
            stack.push(packet.ip.protocolName);
            
            if (packet.applicationProtocol) {
                stack.push(packet.applicationProtocol);
            }
        }
        
        return stack;
    }

    extractNetworkInfo(packet) {
        if (!packet.ip) return {};
        
        return {
            sourceIp: packet.ip.sourceIp,
            destinationIp: packet.ip.destinationIp,
            sourcePort: packet.ip.tcp?.sourcePort || packet.ip.udp?.sourcePort,
            destinationPort: packet.ip.tcp?.destinationPort || packet.ip.udp?.destinationPort,
            ttl: packet.ip.ttl,
            length: packet.length
        };
    }

    updateStatistics(packet) {
        // Update packet counts
        const totalKey = 'total';
        this.packetCounts.set(totalKey, (this.packetCounts.get(totalKey) || 0) + 1);
        
        // Update protocol statistics
        if (packet.ip) {
            const protocol = packet.ip.protocolName;
            this.protocolStats.set(protocol, (this.protocolStats.get(protocol) || 0) + 1);
            
            if (packet.applicationProtocol) {
                this.protocolStats.set(
                    packet.applicationProtocol, 
                    (this.protocolStats.get(packet.applicationProtocol) || 0) + 1
                );
            }
        }
    }

    resetStatistics() {
        this.packetCounts.clear();
        this.protocolStats.clear();
    }

    getStatistics() {
        return {
            packetCounts: Object.fromEntries(this.packetCounts),
            protocolStats: Object.fromEntries(this.protocolStats),
            timestamp: new Date().toISOString()
        };
    }

    bufferToIp(buffer) {
        return `${buffer[0]}.${buffer[1]}.${buffer[2]}.${buffer[3]}`;
    }

    bufferToIpv6(buffer) {
        const groups = [];
        for (let i = 0; i < 16; i += 2) {
            groups.push(buffer.readUInt16BE(i).toString(16));
        }
        return groups.join(':');
    }

    isPrivateIp(ip) {
        if (!ip) return false;
        
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return false;
        
        // RFC 1918 private ranges
        return (
            (parts[0] === 10) ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168)
        );
    }
}

module.exports = PacketAnalyzer; 
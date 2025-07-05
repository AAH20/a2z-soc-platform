import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { 
  Network, Packet, Router, Shield, AlertTriangle, 
  Activity, Clock, Database, Filter, Search 
} from 'lucide-react';

interface PacketFlow {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  packet_size: number;
  flags: string[];
  payload_size: number;
  ttl: number;
  status: 'allowed' | 'blocked' | 'inspected' | 'flagged';
  rule_triggered?: string;
  threat_score: number;
  processing_time: number;
  geolocation?: {
    country: string;
    city: string;
  };
}

interface ProcessingStage {
  name: string;
  status: 'completed' | 'processing' | 'pending' | 'failed';
  duration: number;
  throughput: number;
}

interface PacketFlowVisualizationProps {
  isMonitoring: boolean;
}

const PacketFlowVisualization: React.FC<PacketFlowVisualizationProps> = ({ isMonitoring }) => {
  const [packets, setPackets] = useState<PacketFlow[]>([]);
  const [processingStages] = useState<ProcessingStage[]>([
    { name: 'Capture', status: 'completed', duration: 0.1, throughput: 15000 },
    { name: 'Parse', status: 'completed', duration: 0.2, throughput: 14800 },
    { name: 'Rule Engine', status: 'processing', duration: 1.2, throughput: 14500 },
    { name: 'ML Analysis', status: 'processing', duration: 2.1, throughput: 14200 },
    { name: 'Action', status: 'completed', duration: 0.3, throughput: 14000 }
  ]);

  // Simulate real-time packet generation
  useEffect(() => {
    if (!isMonitoring) return;

    const interval = setInterval(() => {
      const newPackets = Array.from({ length: Math.floor(Math.random() * 3) + 1 }, (_, i) => ({
        id: `packet-${Date.now()}-${i}`,
        timestamp: new Date().toISOString(),
        source_ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        destination_ip: `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        source_port: Math.floor(Math.random() * 65535),
        destination_port: [80, 443, 22, 21, 25, 53, 3389, 8080, 8443][Math.floor(Math.random() * 9)],
        protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
        packet_size: Math.floor(Math.random() * 1500) + 64,
        flags: ['SYN', 'ACK', 'FIN', 'PSH', 'RST', 'URG'].filter(() => Math.random() > 0.7),
        payload_size: Math.floor(Math.random() * 1000),
        ttl: Math.floor(Math.random() * 64) + 64,
        status: (() => {
          const rand = Math.random();
          if (rand < 0.7) return 'allowed';
          if (rand < 0.85) return 'inspected';
          if (rand < 0.95) return 'flagged';
          return 'blocked';
        })() as any,
        threat_score: Math.floor(Math.random() * 10),
        processing_time: Math.random() * 5 + 0.5,
        geolocation: {
          country: ['US', 'CN', 'RU', 'DE', 'UK', 'FR', 'JP', 'KR'][Math.floor(Math.random() * 8)],
          city: ['New York', 'Beijing', 'Moscow', 'Berlin', 'London', 'Paris', 'Tokyo', 'Seoul'][Math.floor(Math.random() * 8)]
        }
      }));

      setPackets(prev => [...newPackets, ...prev.slice(0, 49)]);
    }, 800);

    return () => clearInterval(interval);
  }, [isMonitoring]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'allowed': return 'text-green-400 bg-green-400/20';
      case 'blocked': return 'text-red-400 bg-red-400/20';
      case 'flagged': return 'text-yellow-400 bg-yellow-400/20';
      case 'inspected': return 'text-blue-400 bg-blue-400/20';
      default: return 'text-gray-400 bg-gray-400/20';
    }
  };

  const getStageColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-400';
      case 'processing': return 'text-blue-400';
      case 'pending': return 'text-gray-400';
      case 'failed': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getThreatColor = (score: number) => {
    if (score >= 8) return 'text-red-400';
    if (score >= 6) return 'text-yellow-400';
    if (score >= 4) return 'text-orange-400';
    return 'text-green-400';
  };

  return (
    <div className="space-y-6">
      {/* Processing Pipeline */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <CardTitle className="text-white flex items-center gap-2">
            <Router className="h-5 w-5 text-blue-400" />
            Packet Processing Pipeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-4">
            {processingStages.map((stage, index) => (
              <div key={stage.name} className="relative">
                <div className={`bg-slate-700 rounded-lg p-4 border-2 ${
                  stage.status === 'processing' ? 'border-blue-400 animate-pulse' : 
                  stage.status === 'completed' ? 'border-green-400' :
                  stage.status === 'failed' ? 'border-red-400' : 'border-slate-600'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-sm font-medium ${getStageColor(stage.status)}`}>
                      {stage.name}
                    </span>
                    <Activity className={`h-4 w-4 ${getStageColor(stage.status)} ${
                      stage.status === 'processing' ? 'animate-spin' : ''
                    }`} />
                  </div>
                  <div className="space-y-1">
                    <div className="text-xs text-gray-400">
                      {stage.duration.toFixed(1)}ms avg
                    </div>
                    <div className="text-xs text-gray-400">
                      {stage.throughput.toLocaleString()} pps
                    </div>
                  </div>
                </div>
                {index < processingStages.length - 1 && (
                  <div className="absolute top-1/2 -right-2 w-4 h-0.5 bg-slate-600 transform -translate-y-1/2"></div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Live Packet Stream */}
      <Card className="bg-slate-800 border-slate-700">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-white flex items-center gap-2">
              <Network className="h-5 w-5 text-green-400" />
              Live Packet Stream
              {isMonitoring && (
                <Badge variant="outline" className="text-green-400 border-green-400 animate-pulse">
                  LIVE
                </Badge>
              )}
            </CardTitle>
            <div className="flex items-center gap-2 text-sm text-gray-400">
              <Clock className="h-4 w-4" />
              Showing last 50 packets
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {packets.map((packet) => (
              <div 
                key={packet.id}
                className="bg-slate-700 rounded-lg p-3 border border-slate-600 hover:border-slate-500 transition-all duration-200 animate-in slide-in-from-top-2"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <Badge className={`${getStatusColor(packet.status)} border-0`}>
                      {packet.status.toUpperCase()}
                    </Badge>
                    <span className="text-sm font-mono text-blue-400">{packet.protocol}</span>
                    <span className="text-xs text-gray-400">{packet.packet_size}B</span>
                    {packet.rule_triggered && (
                      <Badge variant="outline" className="text-yellow-400 border-yellow-400 text-xs">
                        Rule: {packet.rule_triggered}
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-semibold ${getThreatColor(packet.threat_score)}`}>
                      Risk: {packet.threat_score}/10
                    </span>
                    <span className="text-xs text-gray-500">
                      {new Date(packet.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-gray-400">Source:</span>
                    <div className="text-white font-mono">
                      {packet.source_ip}:{packet.source_port}
                    </div>
                    {packet.geolocation && (
                      <div className="text-xs text-gray-500">
                        {packet.geolocation.city}, {packet.geolocation.country}
                      </div>
                    )}
                  </div>
                  <div>
                    <span className="text-gray-400">Destination:</span>
                    <div className="text-white font-mono">
                      {packet.destination_ip}:{packet.destination_port}
                    </div>
                  </div>
                  <div>
                    <span className="text-gray-400">Processing:</span>
                    <div className="text-white">
                      {packet.processing_time.toFixed(2)}ms
                    </div>
                  </div>
                  <div>
                    <span className="text-gray-400">TTL:</span>
                    <div className="text-white">
                      {packet.ttl}
                    </div>
                  </div>
                </div>

                {packet.flags.length > 0 && (
                  <div className="mt-2 flex gap-1">
                    <span className="text-xs text-gray-400">Flags:</span>
                    {packet.flags.map((flag) => (
                      <Badge key={flag} variant="secondary" className="text-xs px-1 py-0">
                        {flag}
                      </Badge>
                    ))}
                  </div>
                )}

                {/* Processing time indicator */}
                <div className="mt-2">
                  <div className="flex justify-between text-xs text-gray-400 mb-1">
                    <span>Processing Time</span>
                    <span>{packet.processing_time.toFixed(2)}ms</span>
                  </div>
                  <Progress 
                    value={Math.min((packet.processing_time / 5) * 100, 100)} 
                    className="h-1"
                  />
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default PacketFlowVisualization; 
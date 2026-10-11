import React, { useEffect, useState, useRef } from 'react';
import { Play, Square, ExternalLink, Filter, Download, Activity, Cpu } from 'lucide-react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { api } from '../services/api';
import { getAccessToken } from '../services/apiClient';
import { NetworkInterface, CaptureStatus, PacketEvent } from '../types';

const PROTO_COLORS: Record<string, string> = {
  TCP: '#38bdf8',
  UDP: '#818cf8',
  DNS: '#34d399',
  HTTP: '#fbbf24',
  TLS: '#c084fc',
  ICMP: '#f472b6',
  ARP: '#f87171',
  IP: '#94a3b8'
};

export const MonitorPage: React.FC = () => {
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('Ethernet 7');
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [packets, setPackets] = useState<PacketEvent[]>([]);
  const [selectedPacket, setSelectedPacket] = useState<PacketEvent | null>(null);
  const [filterProto, setFilterProto] = useState<string>('ALL');
  const [filterSearch, setFilterSearch] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  // Fetch Interfaces & Status
  useEffect(() => {
    api.getNetworkInterfaces()
      .then(res => {
        setInterfaces(res.interfaces);
        if (res.current_interface) setSelectedInterface(res.current_interface);
      })
      .catch(err => setErrorMsg(err.message));

    api.getCaptureStatus().then(setCaptureStatus).catch(() => {});
    api.getRecentPackets(100).then(res => setPackets(res.data)).catch(() => {});

    const statusInterval = setInterval(() => {
      api.getCaptureStatus().then(setCaptureStatus).catch(() => {});
    }, 2000);

    return () => clearInterval(statusInterval);
  }, []);

  // WebSocket Live Packet Feed
  useEffect(() => {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = getAccessToken();
    const wsUrl = `${wsProtocol}//${window.location.host}/api/network/ws?token=${encodeURIComponent(token)}`;
    
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'new_packet' && payload.data) {
          setPackets(prev => [payload.data, ...prev.slice(0, 499)]);
        }
      } catch (e) {}
    };

    return () => {
      ws.close();
    };
  }, []);

  const handleStartCapture = async () => {
    try {
      setErrorMsg(null);
      await api.startCapture(selectedInterface);
      const s = await api.getCaptureStatus();
      setCaptureStatus(s);
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to start capture');
    }
  };

  const handleStopCapture = async () => {
    try {
      await api.stopCapture();
      const s = await api.getCaptureStatus();
      setCaptureStatus(s);
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to stop capture');
    }
  };

  const handleOpenWireshark = async () => {
    try {
      // Trigger protocol URL and backend launcher fallback
      window.location.href = 'socchess://wireshark';
      await api.openWireshark();
    } catch (e: any) {
      setErrorMsg(e.message || 'Failed to open Wireshark');
    }
  };

  // Filter Logic
  const filteredPackets = packets.filter(p => {
    const matchesProto = filterProto === 'ALL' || p.protocol.toUpperCase() === filterProto;
    const matchesText = !filterSearch || (
      p.source_ip.includes(filterSearch) ||
      p.destination_ip.includes(filterSearch) ||
      p.protocol.toLowerCase().includes(filterSearch.toLowerCase())
    );
    return matchesProto && matchesText;
  });

  // Calculate Protocol Distribution
  const protoCounts: Record<string, number> = {};
  packets.forEach(p => {
    const pr = (p.protocol || 'TCP').toUpperCase();
    protoCounts[pr] = (protoCounts[pr] || 0) + 1;
  });
  const chartData = Object.keys(protoCounts).map(k => ({ name: k, value: protoCounts[k] }));

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      
      {/* Top Toolbar */}
      <div className="glass-panel p-5 flex flex-wrap items-center justify-between gap-4">
        
        {/* Left: Interface & Controls */}
        <div className="flex items-center gap-4 flex-wrap">
          <div>
            <label className="block text-xs font-heading text-slate-400 mb-1">REAL HOST INTERFACE</label>
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={captureStatus?.is_capturing}
              className="bg-slate-900 border border-white/10 rounded-lg px-3 py-1.5 text-sm font-mono text-cyan-400 focus:border-cyan-500 outline-none"
            >
              {interfaces.map(i => (
                <option key={i.id} value={i.name}>
                  #{i.id} {i.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2 pt-5">
            {captureStatus?.is_capturing ? (
              <button
                onClick={handleStopCapture}
                className="btn-cyber-danger text-xs py-2 px-4 shadow-[0_0_20px_rgba(239,68,68,0.4)]"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>STOP CAPTURE</span>
              </button>
            ) : (
              <button
                onClick={handleStartCapture}
                className="btn-cyber-emerald text-xs py-2 px-4 shadow-[0_0_20px_rgba(16,185,129,0.4)]"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>START CAPTURE</span>
              </button>
            )}

            <button
              onClick={handleOpenWireshark}
              className="btn-cyber-cyan text-xs py-2 px-4"
              title="Launch host Wireshark GUI independently"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>OPEN WIRESHARK</span>
            </button>
          </div>
        </div>

        {/* Right: Capture Metrics */}
        <div className="flex items-center gap-6 font-mono text-sm">
          <div>
            <span className="text-slate-400 text-xs block font-heading">STATUS</span>
            <div className="flex items-center gap-2">
              <span className={`w-2.5 h-2.5 rounded-full ${captureStatus?.is_capturing ? 'bg-emerald-400 animate-pulse shadow-[0_0_8px_#10b981]' : 'bg-slate-500'}`}></span>
              <strong className={captureStatus?.is_capturing ? 'text-emerald-400' : 'text-slate-400'}>
                {captureStatus?.is_capturing ? 'LIVE CAPTURING' : 'STOPPED'}
              </strong>
            </div>
          </div>

          <div>
            <span className="text-slate-400 text-xs block font-heading">PACKETS</span>
            <strong className="text-cyan-400 text-lg">{captureStatus?.packet_count ?? packets.length}</strong>
          </div>

          <div>
            <span className="text-slate-400 text-xs block font-heading">THROUGHPUT</span>
            <strong className="text-purple-400 text-lg">{captureStatus?.packets_per_second ?? 0} pkt/s</strong>
          </div>
        </div>

      </div>

      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-2.5 rounded-lg font-mono text-sm">
          ⚠️ {errorMsg}
        </div>
      )}

      {/* Grid: Charts & Live Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Protocol Breakdown Card */}
        <div className="glass-panel p-5 flex flex-col justify-between">
          <div>
            <h3 className="font-heading font-bold text-sm text-cyan-400 tracking-wider mb-2">
              PROTOCOL DISTRIBUTION
            </h3>
            <p className="text-xs text-slate-400 mb-4">Real traffic distribution on {selectedInterface}</p>
          </div>

          <div className="h-48 w-full">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={4}
                  >
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={PROTO_COLORS[entry.name] || '#06b6d4'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-slate-500 text-xs font-mono">
                No packet data available.
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 mt-4 pt-4 border-t border-white/5 text-xs font-mono">
            {chartData.map(d => (
              <div key={d.name} className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: PROTO_COLORS[d.name] || '#06b6d4' }}></span>
                  {d.name}
                </span>
                <span className="font-bold text-white">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Live Packet Table (3 Columns Span) */}
        <div className="lg:col-span-3 glass-panel p-5 flex flex-col">
          
          {/* Table Filters */}
          <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
            <div className="flex items-center gap-2 flex-1 max-w-md">
              <input
                type="text"
                placeholder="Filter by IP, Port, Protocol..."
                value={filterSearch}
                onChange={(e) => setFilterSearch(e.target.value)}
                className="w-full bg-slate-900 border border-white/10 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-1.5">
              {['ALL', 'TCP', 'UDP', 'DNS', 'HTTP', 'TLS'].map(proto => (
                <button
                  key={proto}
                  onClick={() => setFilterProto(proto)}
                  className={`px-2.5 py-1 rounded text-xs font-heading font-semibold transition-all ${
                    filterProto === proto
                      ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                      : 'bg-slate-900 text-slate-400 hover:text-white border border-white/5'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto rounded-lg border border-white/5 max-h-[500px]">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead className="bg-slate-900/90 text-cyan-400 font-heading text-[11px] sticky top-0 border-b border-white/10">
                <tr>
                  <th className="p-2.5">NO</th>
                  <th className="p-2.5">TIME</th>
                  <th className="p-2.5">SOURCE</th>
                  <th className="p-2.5">DESTINATION</th>
                  <th className="p-2.5">PROTO</th>
                  <th className="p-2.5">LEN</th>
                  <th className="p-2.5">VERDICT</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredPackets.length > 0 ? (
                  filteredPackets.map((pkt, idx) => (
                    <tr
                      key={idx}
                      onClick={() => setSelectedPacket(pkt)}
                      className="hover:bg-cyan-500/10 cursor-pointer transition-colors"
                    >
                      <td className="p-2.5 text-slate-400">#{pkt.packet_no || idx + 1}</td>
                      <td className="p-2.5 text-slate-400">{pkt.timestamp.substring(11, 19)}</td>
                      <td className="p-2.5 font-bold text-slate-200">
                        {pkt.source_ip}:{pkt.source_port || ''}
                      </td>
                      <td className="p-2.5 font-bold text-slate-200">
                        {pkt.destination_ip}:{pkt.destination_port || ''}
                      </td>
                      <td className="p-2.5 font-bold" style={{ color: PROTO_COLORS[pkt.protocol] || '#38bdf8' }}>
                        {pkt.protocol}
                      </td>
                      <td className="p-2.5 text-slate-400">{pkt.packet_length}B</td>
                      <td className="p-2.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            pkt.classification === 'CRITICAL'
                              ? 'bg-red-950 text-red-400 border border-red-500 animate-pulse'
                              : pkt.classification === 'ATTACK'
                              ? 'bg-red-500/20 text-red-400 border border-red-500/40'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                          }`}
                        >
                          {pkt.classification || 'NORMAL'}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-500 font-mono">
                      No live packet traffic recorded. Start capture to stream packets.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

        </div>

      </div>

      {/* Packet Inspection Modal */}
      {selectedPacket && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="glass-panel w-full max-w-2xl p-6 border-cyan-500/50 shadow-[0_0_40px_rgba(6,182,212,0.2)]">
            <div className="flex items-center justify-between pb-4 border-b border-white/10 mb-4">
              <h3 className="font-heading font-bold text-cyan-400">
                PACKET #{selectedPacket.packet_no} DISSECTION
              </h3>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-slate-400 hover:text-red-400 font-bold text-lg"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 font-mono text-xs mb-4">
              <div className="bg-slate-900 p-3 rounded-lg border border-white/5 space-y-1.5">
                <div className="text-slate-400 font-heading text-[10px]">NETWORK LAYER</div>
                <div><strong>Source IP:</strong> {selectedPacket.source_ip}</div>
                <div><strong>Destination IP:</strong> {selectedPacket.destination_ip}</div>
                <div><strong>Protocol:</strong> {selectedPacket.protocol}</div>
                <div><strong>Frame Length:</strong> {selectedPacket.packet_length} Bytes</div>
              </div>

              <div className="bg-slate-900 p-3 rounded-lg border border-white/5 space-y-1.5">
                <div className="text-slate-400 font-heading text-[10px]">TRANSPORT & SECURITY</div>
                <div><strong>Source Port:</strong> {selectedPacket.source_port || 'N/A'}</div>
                <div><strong>Destination Port:</strong> {selectedPacket.destination_port || 'N/A'}</div>
                <div><strong>TCP Flags:</strong> {selectedPacket.tcp_flags || 'None'}</div>
                <div><strong>ML Verdict:</strong> <span className="text-emerald-400 font-bold">{selectedPacket.classification || 'NORMAL'}</span></div>
              </div>
            </div>

            <div className="bg-slate-950 p-3 rounded-lg border border-white/5 font-mono text-[11px] text-cyan-300">
              <pre className="overflow-x-auto whitespace-pre-wrap">
                {JSON.stringify(selectedPacket, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

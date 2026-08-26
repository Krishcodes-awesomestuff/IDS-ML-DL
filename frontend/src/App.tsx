import { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, LogOut, Lock, Server, Network, Sliders, Activity, LayoutDashboard, Terminal, FileText } from 'lucide-react';
import { Auth } from './components/Auth';
import { PacketTerminal } from './components/PacketTerminal';
import type { Packet } from './components/PacketTerminal';
import { SimulatorControls } from './components/SimulatorControls';
import { AnalyticsCharts } from './components/AnalyticsCharts';
import { IpsQuarantineModal } from './components/IpsQuarantineModal';
import type { BlockedIpRule } from './components/IpsQuarantineModal';
import { ReportExportModal } from './components/ReportExportModal';

interface Stats {
  total_inspected: number;
  attacks_detected: number;
  accuracy: number;
  avg_latency: number;
  avg_data_rate: number;
  active_connections: number;
  blocked_ips_count?: number;
  auto_block_enabled?: boolean;
  threat_distribution: {
    normal: number;
    dos: number;
    probe: number;
    r2l: number;
    u2r: number;
  };
}

type TabType = 'overview' | 'logs' | 'firewall' | 'reports';

function App() {
  const [user, setUser] = useState<string | null>(() => {
    return localStorage.getItem('ids_username');
  });

  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [packets, setPackets] = useState<Packet[]>([]);
  const [streamActive, setStreamActive] = useState(false);
  const [blockedIps, setBlockedIps] = useState<BlockedIpRule[]>([]);
  const [autoBlockEnabled, setAutoBlockEnabled] = useState(true);
  const [isIpsModalOpen, setIsIpsModalOpen] = useState(false);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  const [stats, setStats] = useState<Stats>({
    total_inspected: 0,
    attacks_detected: 0,
    accuracy: 100.0,
    avg_latency: 0,
    avg_data_rate: 0.0,
    active_connections: 0,
    blocked_ips_count: 0,
    auto_block_enabled: true,
    threat_distribution: { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 },
  });

  const streamIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load initial statistics and IPS rules on mount and poll in background
  useEffect(() => {
    if (user) {
      fetchStats();
      fetchIpsRules();
      const pollInterval = setInterval(() => {
        fetchStats();
        fetchIpsRules();
      }, 2000);
      return () => clearInterval(pollInterval);
    }
  }, [user]);

  // Handle continuous stream simulation
  useEffect(() => {
    if (streamActive) {
      simulatePacket('random');
      streamIntervalRef.current = setInterval(() => {
        simulatePacket('random');
      }, 1500);
    } else {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current);
      }
    }

    return () => {
      if (streamIntervalRef.current) {
        clearInterval(streamIntervalRef.current);
      }
    };
  }, [streamActive]);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/analytics/stats');
      if (!res.ok) throw new Error('Failed to load stats');
      const data = await res.json();
      setStats(data);
      setPackets(data.recent_packets || []);
      if (data.auto_block_enabled !== undefined) {
        setAutoBlockEnabled(data.auto_block_enabled);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const fetchIpsRules = async () => {
    try {
      const res = await fetch('/api/ips/rules');
      if (!res.ok) throw new Error('Failed to load IPS rules');
      const data = await res.json();
      setBlockedIps(data.blocked_ips || []);
      setAutoBlockEnabled(data.auto_block_enabled ?? true);
    } catch (err) {
      console.error(err);
    }
  };

  const simulatePacket = async (profile: string) => {
    try {
      const res = await fetch(`/api/simulation/generate?profile=${profile}`);
      if (!res.ok) throw new Error('Simulation failed');
      fetchStats();
      fetchIpsRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleManualBlockIp = async (ip: string, reason: string) => {
    try {
      const res = await fetch('/api/ips/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, profile: 'manual' }),
      });
      if (!res.ok) throw new Error('Manual block failed');
      fetchStats();
      fetchIpsRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      const res = await fetch('/api/ips/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      if (!res.ok) throw new Error('Unblock failed');
      fetchStats();
      fetchIpsRules();
    } catch (err) {
      console.error(err);
    }
  };

  const handleToggleAutoBlock = async () => {
    try {
      const res = await fetch('/api/ips/toggle-autoblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !autoBlockEnabled }),
      });
      if (!res.ok) throw new Error('Toggle auto-block failed');
      const data = await res.json();
      setAutoBlockEnabled(data.auto_block_enabled);
    } catch (err) {
      console.error(err);
    }
  };

  const handleReset = async () => {
    try {
      const res = await fetch('/api/analytics/reset', { method: 'POST' });
      if (!res.ok) throw new Error('Reset failed');
      
      setPackets([]);
      setBlockedIps([]);
      setStats({
        total_inspected: 0,
        attacks_detected: 0,
        accuracy: 100.0,
        avg_latency: 0,
        avg_data_rate: 0.0,
        active_connections: 0,
        blocked_ips_count: 0,
        auto_block_enabled: true,
        threat_distribution: { normal: 0, dos: 0, probe: 0, r2l: 0, u2r: 0 },
      });
      setStreamActive(false);
    } catch (err) {
      console.error(err);
    }
  };

  const handleLoginSuccess = (username: string) => {
    localStorage.setItem('ids_username', username);
    setUser(username);
  };

  const handleLogout = () => {
    localStorage.removeItem('ids_username');
    setUser(null);
    setStreamActive(false);
  };

  // If user is not logged in, render Auth gateway
  if (!user) {
    return <Auth onSuccess={handleLoginSuccess} />;
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-main)' }}>
      
      {/* Top Header Bar */}
      <header className="no-print" style={{ borderBottom: '1px solid var(--border)', background: '#0a0a0a', padding: '0.75rem 0' }}>
        <div className="container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 1.5rem' }}>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              background: '#161616',
              border: '1px solid #222222',
              padding: '0.4rem',
              borderRadius: '6px',
              display: 'flex',
              alignItems: 'center'
            }}>
              <Shield size={18} style={{ color: '#ffffff' }} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <h1 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                  Network Intrusion Detection System
                </h1>
                <span className="badge badge-neutral">v2.4</span>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                Real-Time Behavioral Analysis & Automatic Firewall IPS
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <button
              onClick={handleToggleAutoBlock}
              className={`btn ${autoBlockEnabled ? 'btn-danger' : 'btn-muted'}`}
              style={{ fontSize: '0.775rem' }}
            >
              Auto IPS: {autoBlockEnabled ? 'Enabled' : 'Disabled'}
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: '#111111', padding: '0.35rem 0.65rem', borderRadius: '6px', fontSize: '0.8rem', border: '1px solid #222222' }}>
              <Lock size={12} style={{ color: 'var(--text-muted)' }} />
              <span style={{ color: 'var(--text-secondary)' }}>{user}</span>
            </div>
            
            <button
              onClick={handleLogout}
              className="btn btn-muted"
              style={{ padding: '0.35rem 0.65rem', fontSize: '0.8rem' }}
            >
              <LogOut size={13} />
              Logout
            </button>
          </div>

        </div>
      </header>

      {/* Main Content Area */}
      <main className="container" style={{ marginTop: '0.5rem' }}>
        
        {/* Navigation Tabs */}
        <div className="tab-bar no-print">
          <button
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <LayoutDashboard size={15} />
            Overview
          </button>

          <button
            className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => setActiveTab('logs')}
          >
            <Terminal size={15} />
            Live Packet Logs ({packets.length})
          </button>

          <button
            className={`tab-btn ${activeTab === 'firewall' ? 'active' : ''}`}
            onClick={() => setActiveTab('firewall')}
          >
            <ShieldAlert size={15} />
            Firewall Rules ({blockedIps.length})
          </button>

          <button
            className={`tab-btn ${activeTab === 'reports' ? 'active' : ''}`}
            onClick={() => setIsReportModalOpen(true)}
          >
            <FileText size={15} />
            Export Audit Report
          </button>
        </div>

        {/* Tab 1: Overview Dashboard */}
        {activeTab === 'overview' && (
          <div>
            {/* KPI Stat Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
              
              <div className="card">
                <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.35rem' }}>
                  Inspected Packets
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: '1.5rem', fontWeight: 600 }}>
                    {stats.total_inspected.toLocaleString()}
                  </span>
                  <Server size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
              </div>

              <div className="card">
                <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.35rem' }}>
                  Threats Detected
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: '1.5rem', fontWeight: 600, color: stats.attacks_detected > 0 ? 'var(--status-danger)' : 'var(--text-primary)' }}>
                    {stats.attacks_detected.toLocaleString()}
                  </span>
                  <ShieldAlert size={16} style={{ color: stats.attacks_detected > 0 ? 'var(--status-danger)' : 'var(--text-muted)' }} />
                </div>
              </div>

              <div className="card">
                <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.35rem' }}>
                  Active Firewall Blocks
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: '1.5rem', fontWeight: 600, color: blockedIps.length > 0 ? 'var(--status-danger)' : 'var(--text-primary)' }}>
                    {blockedIps.length}
                  </span>
                  <Sliders size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
              </div>

              <div className="card">
                <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.35rem' }}>
                  Active Connections
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--status-warning)' }}>
                    {stats.active_connections}
                  </span>
                  <Network size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
              </div>

              <div className="card">
                <span style={{ fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '0.35rem' }}>
                  Model Accuracy Score
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: '1.5rem', fontWeight: 600, color: 'var(--status-normal)' }}>
                    {stats.accuracy}%
                  </span>
                  <Activity size={16} style={{ color: 'var(--text-muted)' }} />
                </div>
              </div>

            </div>

            {/* Layout Split: Left Controls/Charts, Right Recent Activity */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem', alignItems: 'start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <SimulatorControls
                  onSimulate={simulatePacket}
                  onReset={handleReset}
                  onToggleStream={setStreamActive}
                  streamActive={streamActive}
                />
                <AnalyticsCharts
                  packets={packets}
                  threatDistribution={stats.threat_distribution}
                />
              </div>

              <div style={{ height: '100%' }}>
                <PacketTerminal
                  packets={packets}
                  onBlockIp={handleManualBlockIp}
                />
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Full Packet Logs */}
        {activeTab === 'logs' && (
          <div>
            <PacketTerminal
              packets={packets}
              onBlockIp={handleManualBlockIp}
            />
          </div>
        )}

        {/* Tab 3: Firewall Rules Quarantine Manager */}
        {activeTab === 'firewall' && (
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Active Firewall Quarantine Rules</h3>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                  Manage OS firewall rule blocks (`netsh` / `iptables`) and quarantined hosts
                </p>
              </div>

              <button
                onClick={handleToggleAutoBlock}
                className={`btn ${autoBlockEnabled ? 'btn-danger' : 'btn-muted'}`}
              >
                Auto IPS Mitigation: {autoBlockEnabled ? 'Enabled' : 'Disabled'}
              </button>
            </div>

            {/* Rules Table */}
            <div style={{ border: '1px solid var(--border)', borderRadius: '6px', overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.825rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: '#0a0a0a', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                    <th style={{ padding: '0.65rem 0.85rem' }}>TARGET IP</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>PROFILE</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>REASON</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>TRIGGER</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>TIMESTAMP</th>
                    <th style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {blockedIps.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No active IP quarantine rules in effect.
                      </td>
                    </tr>
                  ) : (
                    blockedIps.map((rule) => (
                      <tr key={rule.ip} className="table-hover-row" style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td className="mono" style={{ padding: '0.65rem 0.85rem', fontWeight: 600, color: 'var(--status-danger)' }}>{rule.ip}</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>
                          <span className="badge badge-danger">{rule.profile}</span>
                        </td>
                        <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-secondary)' }}>{rule.reason}</td>
                        <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-muted)' }}>
                          {rule.auto_blocked ? 'Auto IPS' : 'Manual'}
                        </td>
                        <td className="mono" style={{ padding: '0.65rem 0.85rem', color: 'var(--text-muted)' }}>{rule.timestamp}</td>
                        <td style={{ padding: '0.65rem 0.85rem', textAlign: 'right' }}>
                          <button
                            onClick={() => handleUnblockIp(rule.ip)}
                            className="btn btn-muted"
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                          >
                            Unblock
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </main>

      {/* IPS Firewall Quarantine Modal */}
      <IpsQuarantineModal
        isOpen={isIpsModalOpen}
        onClose={() => setIsIpsModalOpen(false)}
        blockedIps={blockedIps}
        onUnblock={handleUnblockIp}
        onManualBlock={handleManualBlockIp}
        autoBlockEnabled={autoBlockEnabled}
        onToggleAutoBlock={handleToggleAutoBlock}
        onRefresh={fetchIpsRules}
      />

      {/* Executive Security Audit Report Modal */}
      <ReportExportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        stats={stats}
        blockedIps={blockedIps}
        operatorName={user}
      />

    </div>
  );
}

export default App;

import React, { useState } from 'react';
import { Terminal as TerminalIcon, Search, Filter } from 'lucide-react';

export interface Packet {
  id: number;
  timestamp: string;
  profile: string;
  protocol: string;
  service: string;
  flag: string;
  src_ip?: string;
  src_bytes: number;
  dst_bytes: number;
  count: number;
  latency: number;
  active_connections: number;
  data_rate: number;
  is_blocked?: boolean;
  action_taken?: string;
  predictions: {
    random_forest: string;
    decision_tree: string;
  };
  threat_score: number;
}

interface PacketTerminalProps {
  packets: Packet[];
  onBlockIp?: (ip: string, reason: string) => void;
}

export const PacketTerminal: React.FC<PacketTerminalProps> = ({ packets, onBlockIp }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [profileFilter, setProfileFilter] = useState('all');

  const filteredPackets = packets.filter((p) => {
    const matchesSearch =
      (p.src_ip && p.src_ip.includes(searchQuery)) ||
      p.protocol.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.service.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.profile.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesFilter =
      profileFilter === 'all' ||
      (profileFilter === 'attack' && (p.predictions.random_forest === 'Attack' || p.predictions.decision_tree === 'Attack')) ||
      (profileFilter === 'blocked' && p.is_blocked) ||
      p.profile.toLowerCase() === profileFilter.toLowerCase();

    return matchesSearch && matchesFilter;
  });

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', minHeight: '440px' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <TerminalIcon size={16} style={{ color: 'var(--text-secondary)' }} />
          <h3 style={{ fontSize: '0.925rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Live Packet Logs
          </h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            ({filteredPackets.length} events)
          </span>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.85rem' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <Search size={13} style={{ position: 'absolute', left: '0.6rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search IP, protocol, service..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="form-input"
            style={{ paddingLeft: '1.9rem', fontSize: '0.8rem' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
          <Filter size={13} style={{ color: 'var(--text-muted)' }} />
          <select
            value={profileFilter}
            onChange={(e) => setProfileFilter(e.target.value)}
            className="form-input"
            style={{ padding: '0.4rem 0.5rem', fontSize: '0.8rem', cursor: 'pointer' }}
          >
            <option value="all">All Events</option>
            <option value="attack">Threats Only</option>
            <option value="blocked">Quarantined Only</option>
            <option value="normal">Normal</option>
            <option value="dos">DoS</option>
            <option value="probe">Probe</option>
            <option value="r2l">R2L</option>
            <option value="u2r">U2R</option>
          </select>
        </div>
      </div>

      {/* Table Stream */}
      <div style={{ flexGrow: 1, overflowY: 'auto', maxHeight: '420px', border: '1px solid var(--border)', borderRadius: '6px', background: '#080808' }}>
        {filteredPackets.length === 0 ? (
          <div style={{ height: '100%', minHeight: '260px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', gap: '0.4rem' }}>
            <p style={{ fontSize: '0.85rem' }}>No matching telemetry events found.</p>
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: '#0e0e0e', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600 }}>TIME</th>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600 }}>SOURCE IP</th>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600 }}>PROFILE</th>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600 }}>PROTO</th>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600 }}>RF MODEL</th>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600 }}>DT MODEL</th>
                <th style={{ padding: '0.55rem 0.75rem', fontWeight: 600, textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {filteredPackets.map((packet) => {
                const isAttack = packet.predictions.random_forest === 'Attack' || packet.predictions.decision_tree === 'Attack';
                const srcIp = packet.src_ip || '192.168.1.100';
                const isBlocked = packet.is_blocked || packet.action_taken === 'BLOCKED_BY_IPS';

                return (
                  <tr 
                    key={packet.id} 
                    className="table-hover-row"
                    style={{ 
                      borderBottom: '1px solid var(--border-subtle)', 
                      background: isBlocked ? 'rgba(239, 68, 68, 0.05)' : (isAttack ? 'rgba(245, 158, 11, 0.03)' : 'transparent'),
                      transition: 'background 0.15s ease'
                    }}
                  >
                    <td className="mono" style={{ padding: '0.5rem 0.75rem', color: 'var(--text-muted)' }}>
                      {packet.timestamp}
                    </td>

                    <td className="mono" style={{ padding: '0.5rem 0.75rem', fontWeight: 500, color: isBlocked ? 'var(--status-danger)' : 'var(--text-primary)' }}>
                      {srcIp}
                    </td>

                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span className={`badge ${
                        packet.profile === 'normal' ? 'badge-normal' :
                        packet.profile === 'dos' ? 'badge-danger' : 'badge-warning'
                      }`}>
                        {packet.profile}
                      </span>
                    </td>

                    <td style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)' }}>
                      <span className="mono">{packet.protocol.toUpperCase()}</span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginLeft: '0.25rem' }}>({packet.service})</span>
                    </td>

                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span style={{ color: packet.predictions.random_forest === 'Attack' ? 'var(--status-danger)' : 'var(--status-normal)', fontWeight: 500 }}>
                        {packet.predictions.random_forest}
                      </span>
                    </td>

                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span style={{ color: packet.predictions.decision_tree === 'Attack' ? 'var(--status-danger)' : 'var(--status-normal)', fontWeight: 500 }}>
                        {packet.predictions.decision_tree}
                      </span>
                    </td>

                    <td style={{ padding: '0.5rem 0.75rem', textAlign: 'right' }}>
                      {isBlocked ? (
                        <span className="badge badge-danger">
                          BLOCKED
                        </span>
                      ) : isAttack && onBlockIp ? (
                        <button
                          onClick={() => onBlockIp(srcIp, `Block ${packet.profile.toUpperCase()}`)}
                          className="btn btn-danger"
                          style={{ padding: '0.15rem 0.45rem', fontSize: '0.725rem' }}
                        >
                          Block IP
                        </button>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                          Cleared
                        </span>
                      )}
                    </td>

                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

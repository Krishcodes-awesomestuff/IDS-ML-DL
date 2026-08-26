import React from 'react';
import { X, FileText, Download, Printer, Shield } from 'lucide-react';
import type { BlockedIpRule } from './IpsQuarantineModal';

interface ReportExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  stats: {
    total_inspected: number;
    attacks_detected: number;
    accuracy: number;
    avg_latency: number;
    avg_data_rate: number;
    active_connections: number;
    blocked_ips_count?: number;
    threat_distribution: {
      normal: number;
      dos: number;
      probe: number;
      r2l: number;
      u2r: number;
    };
  };
  blockedIps: BlockedIpRule[];
  operatorName: string;
}

export const ReportExportModal: React.FC<ReportExportModalProps> = ({
  isOpen,
  onClose,
  stats,
  blockedIps,
  operatorName,
}) => {
  if (!isOpen) return null;

  const reportId = `NEXUS-AUDIT-${Math.floor(100000 + Math.random() * 900000)}`;
  const timestamp = new Date().toLocaleString();

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadCsv = () => {
    window.open('/api/analytics/export/csv', '_blank');
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(5, 8, 15, 0.85)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '1.5rem'
    }}>
      <div className="card print-area" style={{
        width: '100%',
        maxWidth: '860px',
        maxHeight: '90vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: '8px',
        overflow: 'hidden',
        padding: 0
      }}>
        
        {/* Modal Header */}
        <div className="no-print" style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid #1e293b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: '#0b0f19'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FileText size={18} style={{ color: '#3b82f6' }} />
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                EXECUTIVE SECURITY AUDIT REPORT GENERATOR
              </h3>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Generate Compliance Audits, CSV Data Exports & PDF Reports
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button
              onClick={handleDownloadCsv}
              className="btn btn-primary"
              style={{ fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
            >
              <Download size={14} />
              DOWNLOAD CSV
            </button>

            <button
              onClick={handlePrint}
              className="btn btn-success"
              style={{ fontSize: '0.8rem', padding: '0.35rem 0.75rem' }}
            >
              <Printer size={14} />
              PRINT / SAVE PDF
            </button>

            <button
              onClick={onClose}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                padding: '0.3rem',
                display: 'flex',
                alignItems: 'center',
                borderRadius: '4px'
              }}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Printable Report Document Body */}
        <div id="printable-report" style={{ padding: '1.75rem', overflowY: 'auto', flexGrow: 1, color: 'var(--text-primary)', background: '#090d16' }}>
          
          {/* Document Header */}
          <div style={{ borderBottom: '2px solid #1e293b', paddingBottom: '1rem', marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                <Shield size={22} style={{ color: '#3b82f6' }} />
                <h1 style={{ fontSize: '1.35rem', fontWeight: 700, margin: 0, letterSpacing: '-0.01em' }}>
                  NEXUS SECURITY OPERATIONS CENTER
                </h1>
              </div>
              <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                Executive Threat Intelligence & Active IPS Compliance Assessment
              </p>
            </div>

            <div style={{ textAlign: 'right', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <div>REPORT ID: <span className="mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{reportId}</span></div>
              <div>DATE: <span className="mono" style={{ color: 'var(--text-primary)' }}>{timestamp}</span></div>
              <div>OPERATOR: <span className="mono" style={{ color: 'var(--text-primary)' }}>{operatorName}</span></div>
            </div>
          </div>

          {/* Executive Summary Cards */}
          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#3b82f6', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            1. Executive Telemetry Summary
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.85rem', marginBottom: '1.5rem' }}>
            
            <div style={{ padding: '0.85rem', background: '#111726', border: '1px solid #1e293b', borderRadius: '6px' }}>
              <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>TOTAL VOLUME</span>
              <div className="mono" style={{ fontSize: '1.35rem', fontWeight: 700 }}>{stats.total_inspected.toLocaleString()}</div>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Inspected packets</span>
            </div>

            <div style={{ padding: '0.85rem', background: '#111726', border: '1px solid #1e293b', borderRadius: '6px' }}>
              <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>THREAT DETECTED</span>
              <div className="mono" style={{ fontSize: '1.35rem', fontWeight: 700, color: stats.attacks_detected > 0 ? 'var(--status-danger)' : 'var(--text-primary)' }}>
                {stats.attacks_detected.toLocaleString()}
              </div>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Malicious signatures</span>
            </div>

            <div style={{ padding: '0.85rem', background: '#111726', border: '1px solid #1e293b', borderRadius: '6px' }}>
              <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>FIREWALL BLOCKS</span>
              <div className="mono" style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--status-danger)' }}>
                {blockedIps.length}
              </div>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Quarantined hosts</span>
            </div>

            <div style={{ padding: '0.85rem', background: '#111726', border: '1px solid #1e293b', borderRadius: '6px' }}>
              <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.25rem' }}>ACCURACY SCORE</span>
              <div className="mono" style={{ fontSize: '1.35rem', fontWeight: 700, color: 'var(--status-normal)' }}>
                {stats.accuracy}%
              </div>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Random Forest & DT</span>
            </div>

          </div>

          {/* Threat Distribution Table */}
          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#3b82f6', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            2. Attack Profile Distribution Breakdown
          </h4>
          <div style={{ border: '1px solid #1e293b', borderRadius: '6px', overflow: 'hidden', marginBottom: '1.5rem' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: '#0b0f19', borderBottom: '1px solid #1e293b', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '0.6rem 0.85rem' }}>ATTACK FAMILY</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>THREAT CATEGORY</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>COUNT</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>PERCENTAGE</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>SEVERITY RATING</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { name: 'Normal', desc: 'Benign standard web/network traffic', count: stats.threat_distribution.normal, color: 'var(--status-normal)', rating: 'LOW' },
                  { name: 'DoS', desc: 'Denial of Service flood (SYN, Smurf, Neptune)', count: stats.threat_distribution.dos, color: 'var(--status-danger)', rating: 'CRITICAL' },
                  { name: 'Probe', desc: 'Reconnaissance & Port Scanning (Nmap, Satan)', count: stats.threat_distribution.probe, color: 'var(--status-warning)', rating: 'MEDIUM' },
                  { name: 'R2L', desc: 'Remote to Local unauthorized access attempt', count: stats.threat_distribution.r2l, color: 'var(--status-warning)', rating: 'HIGH' },
                  { name: 'U2R', desc: 'User to Root privilege escalation attempt', count: stats.threat_distribution.u2r, color: '#06b6d4', rating: 'CRITICAL' },
                ].map((row) => {
                  const pct = stats.total_inspected > 0 ? ((row.count / stats.total_inspected) * 100).toFixed(1) : '0.0';
                  return (
                    <tr key={row.name} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                      <td style={{ padding: '0.6rem 0.85rem', fontWeight: 600, color: row.color }}>{row.name.toUpperCase()}</td>
                      <td style={{ padding: '0.6rem 0.85rem', color: 'var(--text-secondary)' }}>{row.desc}</td>
                      <td className="mono" style={{ padding: '0.6rem 0.85rem', fontWeight: 600 }}>{row.count}</td>
                      <td className="mono" style={{ padding: '0.6rem 0.85rem' }}>{pct}%</td>
                      <td style={{ padding: '0.6rem 0.85rem' }}>
                        <span style={{ fontSize: '0.7rem', fontWeight: 700, color: row.rating === 'CRITICAL' ? 'var(--status-danger)' : (row.rating === 'HIGH' ? 'var(--status-warning)' : 'var(--status-normal)') }}>
                          {row.rating}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Active Firewall Quarantine Rules Inventory */}
          <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#3b82f6', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            3. Active Active Firewall IPS Isolation Inventory
          </h4>
          <div style={{ border: '1px solid #1e293b', borderRadius: '6px', overflow: 'hidden', marginBottom: '1.5rem' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: '#0b0f19', borderBottom: '1px solid #1e293b', color: 'var(--text-secondary)' }}>
                  <th style={{ padding: '0.6rem 0.85rem' }}>ISOLATED IP</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>ATTACK PROFILE</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>REASON</th>
                  <th style={{ padding: '0.6rem 0.85rem' }}>TIMESTAMP</th>
                </tr>
              </thead>
              <tbody>
                {blockedIps.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No active IP quarantine records.
                    </td>
                  </tr>
                ) : (
                  blockedIps.slice(0, 10).map((rule) => (
                    <tr key={rule.ip} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                      <td className="mono" style={{ padding: '0.55rem 0.85rem', color: 'var(--status-danger)', fontWeight: 600 }}>{rule.ip}</td>
                      <td style={{ padding: '0.55rem 0.85rem', textTransform: 'uppercase', fontWeight: 600 }}>{rule.profile}</td>
                      <td style={{ padding: '0.55rem 0.85rem', color: 'var(--text-secondary)' }}>{rule.reason}</td>
                      <td className="mono" style={{ padding: '0.55rem 0.85rem', color: 'var(--text-muted)' }}>{rule.timestamp}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Compliance & Attestation Sign-off */}
          <div style={{ borderTop: '1px solid #1e293b', paddingTop: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            <div>
              ✔ Verified by Machine Learning Inference Engine (Scikit-Learn Random Forest & Decision Tree)
            </div>
            <div>
              Page 1 of 1 • Nexus Automated Security Reporting
            </div>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="no-print" style={{
          padding: '0.75rem 1.25rem',
          borderTop: '1px solid #1e293b',
          background: '#0b0f19',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Report Status: <strong style={{ color: 'var(--status-normal)' }}>GENERATED READY</strong>
          </span>
          <button onClick={onClose} className="btn btn-muted" style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }}>
            CLOSE REPORT
          </button>
        </div>

      </div>
    </div>
  );
};

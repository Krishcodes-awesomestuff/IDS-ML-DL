import React, { useState } from 'react';
import { ShieldAlert, X, Unlock, Plus, RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react';

export interface BlockedIpRule {
  ip: string;
  profile: string;
  reason: string;
  timestamp: string;
  auto_blocked: boolean;
}

interface IpsQuarantineModalProps {
  isOpen: boolean;
  onClose: () => void;
  blockedIps: BlockedIpRule[];
  onUnblock: (ip: string) => void;
  onManualBlock: (ip: string, reason: string) => void;
  autoBlockEnabled: boolean;
  onToggleAutoBlock: () => void;
  onRefresh: () => void;
}

export const IpsQuarantineModal: React.FC<IpsQuarantineModalProps> = ({
  isOpen,
  onClose,
  blockedIps,
  onUnblock,
  onManualBlock,
  autoBlockEnabled,
  onToggleAutoBlock,
  onRefresh,
}) => {
  const [manualIpInput, setManualIpInput] = useState('');
  const [manualReasonInput, setManualReasonInput] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!isOpen) return null;

  const handleManualSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualIpInput.trim()) return;
    setIsSubmitting(true);
    await onManualBlock(manualIpInput.trim(), manualReasonInput.trim() || 'Manual SOC operator rule');
    setManualIpInput('');
    setManualReasonInput('');
    setIsSubmitting(false);
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(5, 8, 15, 0.8)',
      backdropFilter: 'blur(4px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '1.5rem'
    }}>
      <div className="card" style={{
        width: '100%',
        maxWidth: '820px',
        maxHeight: '85vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: '#0f172a',
        border: '1px solid #1e293b',
        borderRadius: '8px',
        overflow: 'hidden',
        padding: 0
      }}>
        
        {/* Modal Header */}
        <div style={{
          padding: '1rem 1.25rem',
          borderBottom: '1px solid #1e293b',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: '#0b0f19'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldAlert size={18} style={{ color: 'var(--status-danger)' }} />
            <div>
              <h3 style={{ margin: 0, fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                FIREWALL IPS QUARANTINE MANAGER
              </h3>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Active System Isolation Rules & Threat Blocklist
              </p>
            </div>
          </div>

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

        {/* Modal Body */}
        <div style={{ padding: '1.25rem', overflowY: 'auto', flexGrow: 1, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          
          {/* IPS Controls Banner */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: '#141c2e',
            border: '1px solid #1e293b',
            padding: '0.85rem 1rem',
            borderRadius: '6px',
            flexWrap: 'wrap',
            gap: '0.75rem'
          }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>
                AUTOMATED FIREWALL IPS
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.15rem' }}>
                {autoBlockEnabled ? (
                  <>
                    <CheckCircle2 size={15} style={{ color: 'var(--status-normal)' }} />
                    <span style={{ color: 'var(--status-normal)', fontWeight: 600, fontSize: '0.85rem' }}>
                      AUTOMATED IPS ENFORCING (REAL-TIME ISOLATION)
                    </span>
                  </>
                ) : (
                  <>
                    <AlertTriangle size={15} style={{ color: 'var(--status-warning)' }} />
                    <span style={{ color: 'var(--status-warning)', fontWeight: 600, fontSize: '0.85rem' }}>
                      AUTOMATED IPS PAUSED (MONITORING ONLY)
                    </span>
                  </>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                onClick={onToggleAutoBlock}
                className={`btn ${autoBlockEnabled ? 'btn-danger' : 'btn-primary'}`}
                style={{ fontSize: '0.785rem', padding: '0.35rem 0.75rem' }}
              >
                {autoBlockEnabled ? 'PAUSE AUTO-MITIGATION' : 'ENABLE AUTO-MITIGATION'}
              </button>

              <button
                onClick={onRefresh}
                className="btn btn-muted"
                style={{ fontSize: '0.785rem', padding: '0.35rem 0.6rem' }}
                title="Refresh Firewall Rules"
              >
                <RefreshCw size={13} />
              </button>
            </div>
          </div>

          {/* Manual IP Addition Form */}
          <form onSubmit={handleManualSubmit} style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <input
              type="text"
              placeholder="e.g. 192.168.1.105"
              value={manualIpInput}
              onChange={(e) => setManualIpInput(e.target.value)}
              className="mono"
              style={{
                flex: '1 min-width 160px',
                padding: '0.45rem 0.65rem',
                borderRadius: '6px',
                background: '#090d16',
                border: '1px solid #334155',
                color: '#fff',
                fontSize: '0.8rem',
                outline: 'none'
              }}
            />
            <input
              type="text"
              placeholder="Reason for block (optional)"
              value={manualReasonInput}
              onChange={(e) => setManualReasonInput(e.target.value)}
              style={{
                flex: '2 min-width 200px',
                padding: '0.45rem 0.65rem',
                borderRadius: '6px',
                background: '#090d16',
                border: '1px solid #334155',
                color: '#fff',
                fontSize: '0.8rem',
                outline: 'none'
              }}
            />
            <button
              type="submit"
              disabled={isSubmitting || !manualIpInput.trim()}
              className="btn btn-danger"
              style={{ padding: '0.45rem 0.85rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              <Plus size={13} />
              MANUAL BLOCK
            </button>
          </form>

          {/* Blocked Rules Table */}
          <div style={{ border: '1px solid #1e293b', borderRadius: '6px', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
              <thead>
                <tr style={{ background: '#0b0f19', color: 'var(--text-secondary)', textAlign: 'left', borderBottom: '1px solid #1e293b' }}>
                  <th style={{ padding: '0.6rem 0.75rem' }}>TARGET IP</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>PROFILE</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>REASON</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>TRIGGER</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>TIME</th>
                  <th style={{ padding: '0.6rem 0.75rem', textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {blockedIps.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ padding: '1.75rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                      No IP addresses currently isolated by Firewall rules.
                    </td>
                  </tr>
                ) : (
                  blockedIps.map((rule) => {
                    return (
                      <tr key={rule.ip} className="table-hover-row" style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                        <td className="mono" style={{ padding: '0.6rem 0.75rem', fontWeight: 600, color: 'var(--status-danger)' }}>
                          {rule.ip}
                        </td>
                        <td style={{ padding: '0.6rem 0.75rem' }}>
                          <span className={`badge ${
                            rule.profile === 'dos' ? 'badge-danger' : 'badge-warning'
                          }`}>
                            {rule.profile}
                          </span>
                        </td>
                        <td style={{ padding: '0.6rem 0.75rem', color: 'var(--text-secondary)' }}>
                          {rule.reason}
                        </td>
                        <td style={{ padding: '0.6rem 0.75rem' }}>
                          <span style={{ fontSize: '0.75rem', color: rule.auto_blocked ? 'var(--status-warning)' : 'var(--text-secondary)' }}>
                            {rule.auto_blocked ? '⚡ Auto IPS' : '👤 Operator'}
                          </span>
                        </td>
                        <td className="mono" style={{ padding: '0.6rem 0.75rem', color: 'var(--text-muted)' }}>
                          {rule.timestamp}
                        </td>
                        <td style={{ padding: '0.6rem 0.75rem', textAlign: 'right' }}>
                          <button
                            onClick={() => onUnblock(rule.ip)}
                            className="btn btn-muted"
                            style={{
                              padding: '0.2rem 0.5rem',
                              fontSize: '0.725rem',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.25rem'
                            }}
                          >
                            <Unlock size={11} />
                            UNBLOCK
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

        </div>

        {/* Modal Footer */}
        <div style={{
          padding: '0.75rem 1.25rem',
          borderTop: '1px solid #1e293b',
          background: '#0b0f19',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Quarantined Host Count: <strong style={{ color: '#fff' }}>{blockedIps.length}</strong>
          </span>
          <button onClick={onClose} className="btn btn-muted" style={{ padding: '0.35rem 0.85rem', fontSize: '0.8rem' }}>
            CLOSE MANAGER
          </button>
        </div>

      </div>
    </div>
  );
};

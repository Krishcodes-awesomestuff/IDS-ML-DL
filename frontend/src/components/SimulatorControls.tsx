import React, { useState } from 'react';
import { Play, Pause, Zap, RefreshCcw, Radio } from 'lucide-react';

interface SimulatorControlsProps {
  onSimulate: (profile: string) => void;
  onReset: () => void;
  onToggleStream: (active: boolean) => void;
  streamActive: boolean;
}

export const SimulatorControls: React.FC<SimulatorControlsProps> = ({
  onSimulate,
  onReset,
  onToggleStream,
  streamActive,
}) => {
  const [selectedProfile, setSelectedProfile] = useState('random');

  const profiles = [
    { value: 'random', label: 'Random Traffic Stream' },
    { value: 'normal', label: 'Normal Traffic (Benign)' },
    { value: 'dos', label: 'Denial of Service (DoS)' },
    { value: 'probe', label: 'Port Scan / Probe' },
    { value: 'r2l', label: 'Remote to Local (R2L)' },
    { value: 'u2r', label: 'User to Root (U2R)' },
  ];

  return (
    <div className="card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Radio size={16} style={{ color: '#3b82f6' }} />
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            SIMULATION & THREAT SUITE
          </h3>
        </div>
        <span className="badge badge-info" style={{ fontSize: '0.7rem' }}>TEST ENGINE</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
        <div>
          <label className="form-label">SELECT TRAFFIC PROFILE</label>
          <select
            value={selectedProfile}
            onChange={(e) => setSelectedProfile(e.target.value)}
            className="form-input"
            style={{ cursor: 'pointer' }}
          >
            {profiles.map((p) => (
              <option key={p.value} value={p.value} style={{ background: '#0f172a' }}>
                {p.label}
              </option>
            ))}
          </select>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' }}>
          <button
            onClick={() => onSimulate(selectedProfile)}
            className="btn btn-primary"
          >
            <Zap size={14} />
            INJECT EVENT
          </button>

          <button
            onClick={() => onToggleStream(!streamActive)}
            className={streamActive ? 'btn btn-danger' : 'btn btn-success'}
          >
            {streamActive ? (
              <>
                <Pause size={14} />
                STOP AUTO FEED
              </>
            ) : (
              <>
                <Play size={14} />
                START AUTO FEED
              </>
            )}
          </button>
        </div>

        {/* Quick Trigger Buttons */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.4rem', paddingTop: '0.2rem' }}>
          <button onClick={() => onSimulate('dos')} className="btn btn-danger" style={{ padding: '0.35rem 0.2rem', fontSize: '0.7rem' }} title="Inject DoS Attack">
            DoS
          </button>
          <button onClick={() => onSimulate('probe')} className="btn btn-warning" style={{ padding: '0.35rem 0.2rem', fontSize: '0.7rem' }} title="Inject Probe Attack">
            PROBE
          </button>
          <button onClick={() => onSimulate('r2l')} className="btn btn-warning" style={{ padding: '0.35rem 0.2rem', fontSize: '0.7rem' }} title="Inject R2L Attack">
            R2L
          </button>
          <button onClick={() => onSimulate('u2r')} className="btn btn-danger" style={{ padding: '0.35rem 0.2rem', fontSize: '0.7rem' }} title="Inject U2R Attack">
            U2R
          </button>
        </div>

        <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Reset history logs & active rules
          </span>
          <button
            onClick={onReset}
            className="btn btn-muted"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.785rem' }}
          >
            <RefreshCcw size={13} />
            RESET
          </button>
        </div>
      </div>
    </div>
  );
};

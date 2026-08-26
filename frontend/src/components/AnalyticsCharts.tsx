import React, { useState } from 'react';
import { Doughnut, Line } from 'react-chartjs-2';
import { PieChart, Activity } from 'lucide-react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  Filler,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  Filler
);

interface Packet {
  id: number;
  timestamp: string;
  profile: string;
  protocol: string;
  service: string;
  flag: string;
  src_bytes: number;
  dst_bytes: number;
  count: number;
  latency: number;
  active_connections: number;
  data_rate: number;
  predictions: {
    random_forest: string;
    decision_tree: string;
  };
  threat_score: number;
}

interface AnalyticsChartsProps {
  packets: Packet[];
  threatDistribution: {
    normal: number;
    dos: number;
    probe: number;
    r2l: number;
    u2r: number;
  };
}

type TabType = 'latency' | 'connections' | 'dataRate';

export const AnalyticsCharts: React.FC<AnalyticsChartsProps> = ({ packets, threatDistribution }) => {
  const [activeTab, setActiveTab] = useState<TabType>('connections');

  const cronPackets = [...packets].reverse();
  const labels = cronPackets.map((p) => p.timestamp);

  const getLineData = () => {
    switch (activeTab) {
      case 'latency':
        return {
          labels,
          datasets: [
            {
              label: 'Latency (ms)',
              data: cronPackets.map((p) => p.latency),
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59, 130, 246, 0.08)',
              tension: 0.2,
              fill: true,
              pointBackgroundColor: '#3b82f6',
              pointRadius: 2,
            },
          ],
        };
      case 'connections':
        return {
          labels,
          datasets: [
            {
              label: 'Active Connections',
              data: cronPackets.map((p) => p.active_connections),
              borderColor: '#f59e0b',
              backgroundColor: 'rgba(245, 158, 11, 0.08)',
              tension: 0.2,
              fill: true,
              pointBackgroundColor: '#f59e0b',
              pointRadius: 2,
            },
          ],
        };
      case 'dataRate':
        return {
          labels,
          datasets: [
            {
              label: 'Throughput (MB/s)',
              data: cronPackets.map((p) => p.data_rate),
              borderColor: '#10b981',
              backgroundColor: 'rgba(16, 185, 129, 0.08)',
              tension: 0.2,
              fill: true,
              pointBackgroundColor: '#10b981',
              pointRadius: 2,
            },
          ],
        };
    }
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: '#0f172a',
        titleColor: '#94a3b8',
        bodyColor: '#f8fafc',
        borderColor: '#1e293b',
        borderWidth: 1,
        padding: 8,
      },
    },
    scales: {
      x: {
        grid: {
          color: 'rgba(255, 255, 255, 0.04)',
        },
        ticks: {
          color: '#64748b',
          font: { size: 10 },
        },
      },
      y: {
        grid: {
          color: 'rgba(255, 255, 255, 0.04)',
        },
        ticks: {
          color: '#64748b',
          font: { size: 10 },
        },
      },
    },
  };

  const doughnutData = {
    labels: ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'],
    datasets: [
      {
        data: [
          threatDistribution.normal,
          threatDistribution.dos,
          threatDistribution.probe,
          threatDistribution.r2l,
          threatDistribution.u2r,
        ],
        backgroundColor: [
          '#10b981', // Normal
          '#ef4444', // DoS
          '#f59e0b', // Probe
          '#eab308', // R2L
          '#06b6d4', // U2R
        ],
        borderWidth: 1,
        borderColor: '#111726',
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
        labels: {
          color: '#94a3b8',
          font: {
            size: 11,
            family: 'Inter',
          },
          padding: 8,
        },
      },
      tooltip: {
        backgroundColor: '#0f172a',
        borderColor: '#1e293b',
        borderWidth: 1,
        padding: 8,
      },
    },
    cutout: '65%',
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1.25rem', width: '100%' }}>
      
      {/* 1. Main Trend Monitor */}
      <div className="card" style={{ minHeight: '340px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem', marginBottom: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={16} style={{ color: '#3b82f6' }} />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              METRICS TREND MONITOR
            </h3>
          </div>
          
          <div style={{ display: 'flex', background: '#090d16', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.15rem' }}>
            <button
              onClick={() => setActiveTab('connections')}
              style={{
                background: activeTab === 'connections' ? '#1e293b' : 'none',
                color: activeTab === 'connections' ? 'var(--text-primary)' : 'var(--text-muted)',
                border: 'none',
                padding: '0.3rem 0.6rem',
                fontSize: '0.75rem',
                fontWeight: 500,
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              CONNECTIONS
            </button>
            <button
              onClick={() => setActiveTab('latency')}
              style={{
                background: activeTab === 'latency' ? '#1e293b' : 'none',
                color: activeTab === 'latency' ? 'var(--text-primary)' : 'var(--text-muted)',
                border: 'none',
                padding: '0.3rem 0.6rem',
                fontSize: '0.75rem',
                fontWeight: 500,
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              LATENCY
            </button>
            <button
              onClick={() => setActiveTab('dataRate')}
              style={{
                background: activeTab === 'dataRate' ? '#1e293b' : 'none',
                color: activeTab === 'dataRate' ? 'var(--text-primary)' : 'var(--text-muted)',
                border: 'none',
                padding: '0.3rem 0.6rem',
                fontSize: '0.75rem',
                fontWeight: 500,
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              THROUGHPUT
            </button>
          </div>
        </div>

        <div style={{ flexGrow: 1, height: '220px', position: 'relative' }}>
          {packets.length === 0 ? (
            <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              Awaiting telemetry data to generate graph...
            </div>
          ) : (
            <Line data={getLineData()} options={lineOptions} />
          )}
        </div>
      </div>

      {/* 2. Threat Classification Distribution */}
      <div className="card" style={{ minHeight: '240px', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem', marginBottom: '0.85rem' }}>
          <PieChart size={16} style={{ color: '#3b82f6' }} />
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            THREAT PROFILE BREAKDOWN
          </h3>
        </div>

        <div style={{ flexGrow: 1, height: '150px', position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          {packets.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              No classification events logged
            </div>
          ) : (
            <Doughnut data={doughnutData} options={doughnutOptions} />
          )}
        </div>
      </div>
    </div>
  );
};

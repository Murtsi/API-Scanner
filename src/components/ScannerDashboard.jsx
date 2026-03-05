import React from 'react';
import './ScannerDashboard.css';

function ScannerDashboard({ stats = {} }) {
  // stats: { endpoint, status, responseTime, vulnScore, scanCount }
  return (
    <section className="dashboard-hero">
      <div className="dashboard-hero-title">
        <h1 className="hero-title">API Scanner Pro</h1>
        <div className="scan-counter-glow">
          <span className="scan-counter-label">Live Scans</span>
          <span className="scan-counter-value">{stats?.scanCount || 0}</span>
        </div>
      </div>
      <div className="dashboard-cards">
        <div className="glass-card">
          <div className="card-label">Endpoint</div>
          <div className="card-value">{stats?.endpoint || '-'}</div>
        </div>
        <div className="glass-card">
          <div className="card-label">Status</div>
          <div className={`card-value status status-${stats?.status || 'unknown'}`}>{stats?.status || '-'}</div>
        </div>
        <div className="glass-card">
          <div className="card-label">Response</div>
          <div className="card-value">{stats?.responseTime != null ? stats.responseTime + ' ms' : '-'}</div>
        </div>
        <div className="glass-card">
          <div className="card-label">Vuln Score</div>
          <div className={`card-value vuln-score vuln-score-${stats?.vulnScore || 0}`}>{stats?.vulnScore || 0}</div>
        </div>
      </div>
    </section>
  );
}

ScannerDashboard.defaultProps = {
  stats: { scanCount: 0, endpoint: '-', status: '-', responseTime: 0, vulnScore: 0 },
};

export default ScannerDashboard;

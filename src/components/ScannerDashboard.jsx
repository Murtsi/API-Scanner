import React from 'react';
import './ScannerDashboard.css';

function ScannerDashboard({ stats = {} }) {
  // stats: { endpoint, status, responseTime, vulnScore, scanCount }
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
        <h3 className="text-lg font-semibold text-gray-300 mb-2">Total Scans</h3>
        <div className="text-3xl font-bold text-white">{stats.scanCount.toLocaleString()}</div>
      </div>
      <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
        <h3 className="text-lg font-semibold text-gray-300 mb-2">Total APIs</h3>
        <div className="text-3xl font-bold text-white">{stats.totalApis.toLocaleString()}</div>
      </div>
      <div className="bg-white/5 backdrop-blur-lg rounded-xl p-6 border border-white/10">
        <h3 className="text-lg font-semibold text-gray-300 mb-2">Vulnerabilities Found</h3>
        <div className="text-3xl font-bold text-white">{stats.vulnsFound.toLocaleString()}</div>
      </div>
    </div>
  );
}

ScannerDashboard.defaultProps = {
  stats: { scanCount: 0, totalApis: 0, vulnsFound: 0 },
};

export default ScannerDashboard;

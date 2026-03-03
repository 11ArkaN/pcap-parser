import React, { useMemo } from 'react';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts';

function Charts({ connections, ipData }) {
  const countryData = useMemo(() => {
    const counts = {};
    connections.forEach(conn => {
      const ip = isPublicIp(conn.dst) ? conn.dst : conn.src;
      const info = ipData[ip];
      if (info?.country) {
        counts[info.country] = (counts[info.country] || 0) + 1;
      }
    });
    
    return Object.entries(counts)
      .map(([country, count]) => ({ name: country, value: count }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [connections, ipData]);

  const asnData = useMemo(() => {
    const counts = {};
    connections.forEach(conn => {
      const ip = isPublicIp(conn.dst) ? conn.dst : conn.src;
      const info = ipData[ip];
      if (info?.asn) {
        counts[info.asn] = (counts[info.asn] || 0) + 1;
      }
    });
    
    return Object.entries(counts)
      .map(([asn, count]) => ({ name: asn.substring(0, 30), value: count }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [connections, ipData]);

  const portData = useMemo(() => {
    const counts = {};
    connections.forEach(conn => {
      if (conn.dstPort) {
        const service = getServiceName(conn.dstPort);
        counts[service] = (counts[service] || 0) + 1;
      }
    });
    
    return Object.entries(counts)
      .map(([service, count]) => ({ name: service, value: count }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [connections]);

  const protocolData = useMemo(() => {
    const counts = {};
    connections.forEach(conn => {
      counts[conn.protocol] = (counts[conn.protocol] || 0) + 1;
    });
    
    return Object.entries(counts)
      .map(([protocol, count]) => ({ name: protocol, value: count }));
  }, [connections]);

  const COLORS = ['#00f5ff', '#ff00ff', '#00ff9d', '#ff6b35', '#8b5cf6', '#0066ff', '#ffd700', '#ff0050'];

  const chartTooltipStyle = {
    backgroundColor: 'rgba(18, 18, 26, 0.95)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: '12px',
    color: '#fff',
    fontFamily: 'Outfit, sans-serif'
  };

  if (!connections.length) return null;

  return (
    <div className="charts-section">
      <div className="charts-grid">
        <div className="chart-card">
          <h3>Top Kraje</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={countryData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis 
                dataKey="name" 
                stroke="rgba(255,255,255,0.3)"
                tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11, fontFamily: 'Outfit' }}
                angle={-45}
                textAnchor="end"
                height={70}
              />
              <YAxis 
                stroke="rgba(255,255,255,0.3)"
                tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11, fontFamily: 'Outfit' }}
              />
              <Tooltip 
                contentStyle={chartTooltipStyle}
                cursor={{ fill: 'rgba(0, 245, 255, 0.1)' }}
              />
              <Bar 
                dataKey="value" 
                fill="url(#gradient-cyan)" 
                radius={[8, 8, 0, 0]}
              >
                <defs>
                  <linearGradient id="gradient-cyan" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00f5ff" stopOpacity={0.8} />
                    <stop offset="100%" stopColor="#0066ff" stopOpacity={0.6} />
                  </linearGradient>
                </defs>
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Top Systemy Autonomiczne (ASN)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={asnData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis 
                dataKey="name" 
                stroke="rgba(255,255,255,0.3)"
                tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 10, fontFamily: 'Outfit' }}
                angle={-45}
                textAnchor="end"
                height={80}
                interval={0}
              />
              <YAxis 
                stroke="rgba(255,255,255,0.3)"
                tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11, fontFamily: 'Outfit' }}
              />
              <Tooltip 
                contentStyle={chartTooltipStyle}
                cursor={{ fill: 'rgba(255, 0, 255, 0.1)' }}
              />
              <Bar 
                dataKey="value" 
                fill="url(#gradient-magenta)" 
                radius={[8, 8, 0, 0]}
              >
                <defs>
                  <linearGradient id="gradient-magenta" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff00ff" stopOpacity={0.8} />
                    <stop offset="100%" stopColor="#8b5cf6" stopOpacity={0.6} />
                  </linearGradient>
                </defs>
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Top Uslugi / Porty</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={portData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis 
                dataKey="name" 
                stroke="rgba(255,255,255,0.3)"
                tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11, fontFamily: 'Outfit' }}
                angle={-45}
                textAnchor="end"
                height={70}
              />
              <YAxis 
                stroke="rgba(255,255,255,0.3)"
                tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11, fontFamily: 'Outfit' }}
              />
              <Tooltip 
                contentStyle={chartTooltipStyle}
                cursor={{ fill: 'rgba(0, 255, 157, 0.1)' }}
              />
              <Bar 
                dataKey="value" 
                fill="url(#gradient-green)" 
                radius={[8, 8, 0, 0]}
              >
                <defs>
                  <linearGradient id="gradient-green" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#00ff9d" stopOpacity={0.8} />
                    <stop offset="100%" stopColor="#00cc7d" stopOpacity={0.6} />
                  </linearGradient>
                </defs>
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Dystrybucja Protokolow</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={protocolData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {protocolData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={COLORS[index % COLORS.length]}
                    stroke="rgba(18, 18, 26, 0.8)"
                    strokeWidth={2}
                  />
                ))}
              </Pie>
              <Tooltip contentStyle={chartTooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

function isPublicIp(ip) {
  if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255') return false;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 192 && parts[1] === 168) return false;
  if (parts[0] === 127) return false;
  if (parts[0] === 169 && parts[1] === 254) return false;
  if (parts[0] >= 224) return false;
  return true;
}

function getServiceName(port) {
  const services = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
  };
  return services[port] || `Port-${port}`;
}

export default Charts;

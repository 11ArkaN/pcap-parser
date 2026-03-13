import React, { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';
import type { IpLookupData, ParsedConnection } from '../types';
import { formatResolvedServiceNameWithFallback, resolveConnectionServices } from '../utils/serviceResolver';

interface ChartsProps {
  connections: ParsedConnection[];
  ipData: Record<string, IpLookupData>;
}

interface ChartDatum {
  name: string;
  value: number;
}

function Charts({ connections, ipData }: ChartsProps) {
  const countryData = useMemo<ChartDatum[]>(() => {
    const counts: Record<string, number> = {};
    connections.forEach((conn) => {
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

  const asnData = useMemo<ChartDatum[]>(() => {
    const counts: Record<string, number> = {};
    connections.forEach((conn) => {
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

  const portData = useMemo<ChartDatum[]>(() => {
    const counts: Record<string, number> = {};
    connections.forEach((conn) => {
      const resolution = resolveConnectionServices(conn);
      const service = formatResolvedServiceNameWithFallback(resolution, conn.srcPort, conn.dstPort);
      if (service === 'N/D') return;
      counts[service] = (counts[service] || 0) + 1;
    });

    return Object.entries(counts)
      .map(([service, count]) => ({ name: service, value: count }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [connections]);

  const protocolData = useMemo<ChartDatum[]>(() => {
    const counts: Record<string, number> = {};
    connections.forEach((conn) => {
      counts[conn.protocol] = (counts[conn.protocol] || 0) + 1;
    });

    return Object.entries(counts).map(([protocol, count]) => ({ name: protocol, value: count }));
  }, [connections]);

  const colors = ['#e2a039', '#60a5fa', '#34d399', '#fb923c', '#a78bfa', '#f43f5e', '#38bdf8', '#fb7185'];

  const chartTooltipStyle = {
    backgroundColor: 'rgba(12, 14, 20, 0.95)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
    borderRadius: '8px',
    color: '#f0f1f4',
    fontFamily: 'Sora, sans-serif',
    fontSize: '0.8125rem',
    padding: '8px 12px',
    boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)'
  };

  if (!connections.length) return null;

  return (
    <div className="charts-section fade-in">
      <div className="charts-grid">
        <div className="chart-card">
          <h3>Top Kraje</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={countryData} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis
                dataKey="name"
                stroke="none"
                tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 11, fontFamily: 'Sora' }}
                angle={-45}
                textAnchor="end"
                height={60}
              />
              <YAxis stroke="none" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'Fira Code' }} />
              <Tooltip contentStyle={chartTooltipStyle} cursor={{ fill: 'rgba(226, 160, 57, 0.06)' }} />
              <defs>
                <linearGradient id="grad-amber" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#e2a039" stopOpacity={0.85} />
                  <stop offset="100%" stopColor="#c98b1e" stopOpacity={0.5} />
                </linearGradient>
              </defs>
              <Bar dataKey="value" fill="url(#grad-amber)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Top Systemy Autonomiczne (ASN)</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={asnData} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis
                dataKey="name"
                stroke="none"
                tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 9, fontFamily: 'Sora' }}
                angle={-45}
                textAnchor="end"
                height={80}
                interval={0}
              />
              <YAxis stroke="none" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'Fira Code' }} />
              <Tooltip contentStyle={chartTooltipStyle} cursor={{ fill: 'rgba(167, 139, 250, 0.06)' }} />
              <defs>
                <linearGradient id="grad-violet" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#a78bfa" stopOpacity={0.85} />
                  <stop offset="100%" stopColor="#7c3aed" stopOpacity={0.5} />
                </linearGradient>
              </defs>
              <Bar dataKey="value" fill="url(#grad-violet)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Top Uslugi / Porty</h3>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={portData} margin={{ top: 4, right: 8, left: -12, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis
                dataKey="name"
                stroke="none"
                tick={{ fill: 'rgba(255,255,255,0.4)', fontSize: 11, fontFamily: 'Sora' }}
                angle={-45}
                textAnchor="end"
                height={60}
              />
              <YAxis stroke="none" tick={{ fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'Fira Code' }} />
              <Tooltip contentStyle={chartTooltipStyle} cursor={{ fill: 'rgba(52, 211, 153, 0.06)' }} />
              <defs>
                <linearGradient id="grad-emerald" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#34d399" stopOpacity={0.85} />
                  <stop offset="100%" stopColor="#10b981" stopOpacity={0.5} />
                </linearGradient>
              </defs>
              <Bar dataKey="value" fill="url(#grad-emerald)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Dystrybucja Protokolow</h3>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie
                data={protocolData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }: { name: string; percent?: number }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                outerRadius={80}
                innerRadius={40}
                fill="#8884d8"
                dataKey="value"
                strokeWidth={0}
              >
                {protocolData.map((_entry, index) => (
                  <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
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

function isPublicIp(ip: string): boolean {
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

export default Charts;

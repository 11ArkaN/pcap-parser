import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React, { useMemo } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
function Charts({ connections, ipData }) {
    const countryData = useMemo(() => {
        const counts = {};
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
    const asnData = useMemo(() => {
        const counts = {};
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
    const portData = useMemo(() => {
        const counts = {};
        connections.forEach((conn) => {
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
    if (!connections.length)
        return null;
    return (_jsx("div", { className: "charts-section fade-in", children: _jsxs("div", { className: "charts-grid", children: [_jsxs("div", { className: "chart-card", children: [_jsx("h3", { children: "Top Kraje" }), _jsx(ResponsiveContainer, { width: "100%", height: 240, children: _jsxs(BarChart, { data: countryData, margin: { top: 4, right: 8, left: -12, bottom: 0 }, children: [_jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "rgba(255,255,255,0.04)", vertical: false }), _jsx(XAxis, { dataKey: "name", stroke: "none", tick: { fill: 'rgba(255,255,255,0.4)', fontSize: 11, fontFamily: 'Sora' }, angle: -45, textAnchor: "end", height: 60 }), _jsx(YAxis, { stroke: "none", tick: { fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'Fira Code' } }), _jsx(Tooltip, { contentStyle: chartTooltipStyle, cursor: { fill: 'rgba(226, 160, 57, 0.06)' } }), _jsx("defs", { children: _jsxs("linearGradient", { id: "grad-amber", x1: "0", y1: "0", x2: "0", y2: "1", children: [_jsx("stop", { offset: "0%", stopColor: "#e2a039", stopOpacity: 0.85 }), _jsx("stop", { offset: "100%", stopColor: "#c98b1e", stopOpacity: 0.5 })] }) }), _jsx(Bar, { dataKey: "value", fill: "url(#grad-amber)", radius: [4, 4, 0, 0] })] }) })] }), _jsxs("div", { className: "chart-card", children: [_jsx("h3", { children: "Top Systemy Autonomiczne (ASN)" }), _jsx(ResponsiveContainer, { width: "100%", height: 240, children: _jsxs(BarChart, { data: asnData, margin: { top: 4, right: 8, left: -12, bottom: 0 }, children: [_jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "rgba(255,255,255,0.04)", vertical: false }), _jsx(XAxis, { dataKey: "name", stroke: "none", tick: { fill: 'rgba(255,255,255,0.4)', fontSize: 9, fontFamily: 'Sora' }, angle: -45, textAnchor: "end", height: 80, interval: 0 }), _jsx(YAxis, { stroke: "none", tick: { fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'Fira Code' } }), _jsx(Tooltip, { contentStyle: chartTooltipStyle, cursor: { fill: 'rgba(167, 139, 250, 0.06)' } }), _jsx("defs", { children: _jsxs("linearGradient", { id: "grad-violet", x1: "0", y1: "0", x2: "0", y2: "1", children: [_jsx("stop", { offset: "0%", stopColor: "#a78bfa", stopOpacity: 0.85 }), _jsx("stop", { offset: "100%", stopColor: "#7c3aed", stopOpacity: 0.5 })] }) }), _jsx(Bar, { dataKey: "value", fill: "url(#grad-violet)", radius: [4, 4, 0, 0] })] }) })] }), _jsxs("div", { className: "chart-card", children: [_jsx("h3", { children: "Top Uslugi / Porty" }), _jsx(ResponsiveContainer, { width: "100%", height: 240, children: _jsxs(BarChart, { data: portData, margin: { top: 4, right: 8, left: -12, bottom: 0 }, children: [_jsx(CartesianGrid, { strokeDasharray: "3 3", stroke: "rgba(255,255,255,0.04)", vertical: false }), _jsx(XAxis, { dataKey: "name", stroke: "none", tick: { fill: 'rgba(255,255,255,0.4)', fontSize: 11, fontFamily: 'Sora' }, angle: -45, textAnchor: "end", height: 60 }), _jsx(YAxis, { stroke: "none", tick: { fill: 'rgba(255,255,255,0.3)', fontSize: 10, fontFamily: 'Fira Code' } }), _jsx(Tooltip, { contentStyle: chartTooltipStyle, cursor: { fill: 'rgba(52, 211, 153, 0.06)' } }), _jsx("defs", { children: _jsxs("linearGradient", { id: "grad-emerald", x1: "0", y1: "0", x2: "0", y2: "1", children: [_jsx("stop", { offset: "0%", stopColor: "#34d399", stopOpacity: 0.85 }), _jsx("stop", { offset: "100%", stopColor: "#10b981", stopOpacity: 0.5 })] }) }), _jsx(Bar, { dataKey: "value", fill: "url(#grad-emerald)", radius: [4, 4, 0, 0] })] }) })] }), _jsxs("div", { className: "chart-card", children: [_jsx("h3", { children: "Dystrybucja Protokolow" }), _jsx(ResponsiveContainer, { width: "100%", height: 240, children: _jsxs(PieChart, { children: [_jsx(Pie, { data: protocolData, cx: "50%", cy: "50%", labelLine: false, label: ({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`, outerRadius: 80, innerRadius: 40, fill: "#8884d8", dataKey: "value", strokeWidth: 0, children: protocolData.map((_entry, index) => (_jsx(Cell, { fill: colors[index % colors.length] }, `cell-${index}`))) }), _jsx(Tooltip, { contentStyle: chartTooltipStyle })] }) })] })] }) }));
}
function isPublicIp(ip) {
    if (!ip || ip === '0.0.0.0' || ip === '255.255.255.255')
        return false;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4)
        return false;
    if (parts[0] === 10)
        return false;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        return false;
    if (parts[0] === 192 && parts[1] === 168)
        return false;
    if (parts[0] === 127)
        return false;
    if (parts[0] === 169 && parts[1] === 254)
        return false;
    if (parts[0] >= 224)
        return false;
    return true;
}
function getServiceName(port) {
    const services = {
        20: 'FTP-Data',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        465: 'SMTPS',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt'
    };
    return services[port] || `Port-${port}`;
}
export default Charts;

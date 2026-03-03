import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import React, { useEffect, useMemo, useRef, useState } from 'react';
import Papa from 'papaparse';
import * as XLSX from 'xlsx';
const SearchIcon = () => (_jsxs("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: "2", strokeLinecap: "round", strokeLinejoin: "round", children: [_jsx("circle", { cx: "11", cy: "11", r: "8" }), _jsx("line", { x1: "21", y1: "21", x2: "16.65", y2: "16.65" })] }));
function DataTable({ connections, ipData, isPublic, focusRequest = null }) {
    const [searchTerm, setSearchTerm] = useState('');
    const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });
    const [highlightIp, setHighlightIp] = useState(null);
    const tableWrapperRef = useRef(null);
    const aggregatedData = useMemo(() => aggregateConnections(connections), [connections]);
    const filteredData = useMemo(() => {
        let data = [...aggregatedData];
        if (searchTerm) {
            const term = searchTerm.toLowerCase();
            data = data.filter((row) => row.src.toLowerCase().includes(term) ||
                row.dst.toLowerCase().includes(term) ||
                ipData[row.dst]?.asn?.toLowerCase().includes(term) ||
                ipData[row.dst]?.isp?.toLowerCase().includes(term) ||
                ipData[row.dst]?.country?.toLowerCase().includes(term));
        }
        if (sortConfig.key) {
            data.sort((a, b) => {
                let aValue = '';
                let bValue = '';
                const publicIpA = isPublicIp(a.dst) ? a.dst : a.src;
                const publicIpB = isPublicIp(b.dst) ? b.dst : b.src;
                const infoA = ipData[publicIpA] || {};
                const infoB = ipData[publicIpB] || {};
                switch (sortConfig.key) {
                    case 'ip':
                        aValue = publicIpA;
                        bValue = publicIpB;
                        break;
                    case 'asn':
                        aValue = infoA.asn || '';
                        bValue = infoB.asn || '';
                        break;
                    case 'isp':
                        aValue = infoA.isp || infoA.org || '';
                        bValue = infoB.isp || infoB.org || '';
                        break;
                    case 'country':
                        aValue = infoA.country || '';
                        bValue = infoB.country || '';
                        break;
                    case 'packets':
                        aValue = a.packetCount;
                        bValue = b.packetCount;
                        break;
                    case 'bytes':
                        aValue = a.bytes;
                        bValue = b.bytes;
                        break;
                    default:
                        break;
                }
                if (typeof aValue === 'number' && typeof bValue === 'number') {
                    return sortConfig.direction === 'asc' ? aValue - bValue : bValue - aValue;
                }
                const aStr = String(aValue).toLowerCase();
                const bStr = String(bValue).toLowerCase();
                if (aStr < bStr)
                    return sortConfig.direction === 'asc' ? -1 : 1;
                if (aStr > bStr)
                    return sortConfig.direction === 'asc' ? 1 : -1;
                return 0;
            });
        }
        return data;
    }, [aggregatedData, searchTerm, sortConfig, ipData]);
    useEffect(() => {
        if (!focusRequest || !isPublic)
            return;
        const targetIp = focusRequest.ip.trim();
        if (!targetIp)
            return;
        setSearchTerm(targetIp);
        setHighlightIp(targetIp);
        const scrollToTarget = () => {
            const rows = tableWrapperRef.current?.querySelectorAll('tr[data-public-ip]');
            if (!rows?.length)
                return;
            for (const row of Array.from(rows)) {
                if (row.dataset.publicIp === targetIp) {
                    row.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    break;
                }
            }
        };
        window.requestAnimationFrame(() => {
            window.requestAnimationFrame(scrollToTarget);
        });
        const timer = window.setTimeout(() => {
            setHighlightIp((current) => (current === targetIp ? null : current));
        }, 2600);
        return () => window.clearTimeout(timer);
    }, [focusRequest?.requestId, focusRequest?.ip, isPublic]);
    const handleSort = (key) => {
        setSortConfig((current) => ({
            key,
            direction: current.key === key && current.direction === 'asc' ? 'desc' : 'asc'
        }));
    };
    const getSortIndicator = (key) => {
        if (sortConfig.key !== key)
            return '<>';
        return sortConfig.direction === 'asc' ? '^' : 'v';
    };
    const exportToCSV = () => {
        const exportData = prepareExportData(filteredData, ipData, isPublic);
        const csv = Papa.unparse(exportData);
        downloadFile(csv, 'analiza-pcap.csv', 'text/csv');
    };
    const exportToJSON = () => {
        const exportData = prepareExportData(filteredData, ipData, isPublic);
        const json = JSON.stringify(exportData, null, 2);
        downloadFile(json, 'analiza-pcap.json', 'application/json');
    };
    const exportToExcel = () => {
        const exportData = prepareExportData(filteredData, ipData, isPublic);
        const ws = XLSX.utils.json_to_sheet(exportData);
        ws['!cols'] = buildExcelColumnWidths(exportData);
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'Analiza PCAP');
        XLSX.writeFile(wb, 'analiza-pcap.xlsx');
    };
    if (!connections.length) {
        return (_jsxs("div", { className: "empty-state", children: [_jsx("div", { className: "empty-state-icon", children: "No data" }), _jsx("h3", { children: "Brak danych" }), _jsx("p", { children: "Wczytaj plik PCAP aby zobaczyc analize" })] }));
    }
    return (_jsxs("div", { className: "table-container fade-in", children: [_jsxs("div", { className: "table-toolbar", children: [_jsxs("div", { className: "table-search", children: [_jsx("span", { className: "search-icon", children: _jsx(SearchIcon, {}) }), _jsx("input", { type: "text", placeholder: "Szukaj po IP, ASN, ISP, Kraju...", value: searchTerm, onChange: (e) => setSearchTerm(e.target.value) })] }), _jsxs("div", { className: "export-buttons", children: [_jsx("button", { className: "btn btn-secondary", onClick: exportToCSV, children: "CSV" }), _jsx("button", { className: "btn btn-secondary", onClick: exportToJSON, children: "JSON" }), _jsx("button", { className: "btn btn-primary", onClick: exportToExcel, children: "Excel" })] })] }), _jsx("div", { className: "data-table-wrapper", ref: tableWrapperRef, children: _jsxs("table", { className: "data-table", children: [_jsx("thead", { children: _jsxs("tr", { children: [isPublic && (_jsxs(_Fragment, { children: [_jsxs("th", { onClick: () => handleSort('ip'), children: ["Adres IP ", getSortIndicator('ip')] }), _jsxs("th", { onClick: () => handleSort('asn'), children: ["ASN ", getSortIndicator('asn')] }), _jsxs("th", { onClick: () => handleSort('isp'), children: ["ISP / Organizacja ", getSortIndicator('isp')] }), _jsxs("th", { onClick: () => handleSort('country'), children: ["Lokalizacja ", getSortIndicator('country')] }), _jsx("th", { className: "cidr-col", children: "Blok CIDR" })] })), !isPublic && (_jsxs(_Fragment, { children: [_jsx("th", { children: "IP Zrodlowe" }), _jsx("th", { children: "IP Docelowe" })] })), _jsx("th", { children: "Usluga" }), _jsxs("th", { onClick: () => handleSort('packets'), children: ["Pakiety ", getSortIndicator('packets')] }), _jsxs("th", { onClick: () => handleSort('bytes'), children: ["Bajty ", getSortIndicator('bytes')] }), isPublic && _jsx("th", { children: "Bezpieczenstwo" })] }) }), _jsx("tbody", { children: filteredData.map((row, index) => {
                                const publicIp = isPublicIp(row.dst) ? row.dst : row.src;
                                const info = ipData[publicIp] || {};
                                return (_jsxs("tr", { "data-public-ip": publicIp, className: highlightIp === publicIp ? 'pcap-focus-row' : undefined, children: [isPublic && (_jsxs(_Fragment, { children: [_jsx("td", { children: _jsx("span", { className: "ip-address", children: publicIp }) }), _jsx("td", { children: info.asn && _jsx("span", { className: "asn-badge", children: info.asn }) }), _jsx("td", { children: info.isp || info.org || 'Nieznane' }), _jsx("td", { children: _jsxs("div", { className: "country-flag", children: [_jsx("span", { className: "flag", children: info.country && getFlagEmoji(info.country) }), _jsxs("div", { children: [_jsx("div", { className: "country-name", children: info.country || 'Nieznane' }), info.city && _jsx("div", { className: "country-city", children: info.city })] })] }) }), _jsx("td", { className: "cidr-col", children: _jsx("span", { className: "cidr-block cidr-block-pcap", children: info.cidr || info.range || 'N/D' }) })] })), !isPublic && (_jsxs(_Fragment, { children: [_jsx("td", { children: _jsx("span", { className: "ip-address ip-local", children: row.src }) }), _jsx("td", { children: _jsx("span", { className: "ip-address ip-local", children: row.dst }) })] })), _jsx("td", { children: _jsxs("div", { className: "service-info", children: [_jsx("span", { className: "service-name", children: row.services || 'Nieznane' }), row.dstPort && _jsxs("span", { className: "port-number", children: ["Port ", row.dstPort] }), _jsx("span", { className: `protocol-badge ${row.protocol.toLowerCase()}`, children: row.protocol })] }) }), _jsx("td", { style: { fontFamily: "'Fira Code', monospace", fontSize: '0.8125rem' }, children: row.packetCount.toLocaleString() }), _jsx("td", { style: { fontFamily: "'Fira Code', monospace", fontSize: '0.8125rem' }, children: formatBytes(row.bytes) }), isPublic && (_jsx("td", { children: _jsx(SecurityAnalysis, { port: row.dstPort, protocol: row.protocol, isp: info.isp }) }))] }, index));
                            }) })] }) })] }));
}
function SecurityAnalysis({ port, protocol, isp }) {
    const analysis = [];
    let level = 'safe';
    if (port === 443 || port === 8443) {
        analysis.push('HTTPS Szyfrowane');
    }
    else if (port === 80) {
        analysis.push('HTTP Nieszyfrowane');
        level = 'warning';
    }
    else if (port === 53) {
        analysis.push('DNS Standard');
        level = protocol === 'UDP' ? 'warning' : 'safe';
    }
    else if (port === 22) {
        analysis.push('SSH Bezpieczne');
    }
    else if (port && port > 49152) {
        analysis.push('Port Dynamiczny');
        level = 'warning';
    }
    if (isp) {
        const trusted = ['microsoft', 'google', 'amazon', 'cloudflare', 'akamai'];
        const isTrusted = trusted.some((t) => isp.toLowerCase().includes(t));
        if (isTrusted) {
            analysis.push('Zaufany Dostawca');
        }
    }
    const className = `security-info security-${level}`;
    return _jsx("div", { className: className, children: analysis.join(' / ') || 'Ruch Standardowy' });
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
function getFlagEmoji(countryCode) {
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}
function formatBytes(bytes) {
    if (bytes === 0)
        return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}
export function isPublicIp(ip) {
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
export function aggregateConnections(connections) {
    const grouped = {};
    connections.forEach((conn) => {
        const key = `${conn.src}-${conn.dst}`;
        if (!grouped[key]) {
            grouped[key] = {
                src: conn.src,
                dst: conn.dst,
                protocol: conn.protocol,
                srcPort: conn.srcPort,
                dstPort: conn.dstPort,
                packetCount: 0,
                bytes: 0,
                services: new Set()
            };
        }
        grouped[key].packetCount += conn.packetCount || 1;
        grouped[key].bytes += conn.length || 0;
        if (conn.dstPort) {
            grouped[key].services.add(getServiceName(conn.dstPort));
        }
    });
    return Object.values(grouped).map((group) => ({
        src: group.src,
        dst: group.dst,
        protocol: group.protocol,
        srcPort: group.srcPort,
        dstPort: group.dstPort,
        packetCount: group.packetCount,
        bytes: group.bytes,
        services: Array.from(group.services).join(', ')
    }));
}
export function prepareExportData(data, ipData, _isPublic) {
    return data.map((row) => {
        const publicIp = isPublicIp(row.dst) ? row.dst : row.src;
        const info = ipData[publicIp] || {};
        return {
            'Adres IP': publicIp,
            ASN: info.asn || 'N/D',
            'ISP/Organizacja': info.isp || info.org || 'Nieznane',
            Kraj: info.country || 'Nieznane',
            Miasto: info.city || 'N/D',
            'Blok CIDR': info.cidr || info.range || 'N/D',
            Usluga: row.services || 'Nieznane',
            Port: row.dstPort || 'N/D',
            Protokol: row.protocol,
            Pakiety: row.packetCount,
            Bajty: row.bytes,
            'IP Zrodlowe': row.src,
            'IP Docelowe': row.dst
        };
    });
}
function buildExcelColumnWidths(rows) {
    const minWidth = 10;
    if (!rows.length)
        return [];
    const headers = Object.keys(rows[0]);
    return headers.map((header) => {
        let longest = header.length;
        for (const row of rows) {
            const value = row[header];
            const width = String(value ?? '').length;
            if (width > longest)
                longest = width;
        }
        return { wch: Math.max(minWidth, longest + 2) };
    });
}
function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
export default DataTable;

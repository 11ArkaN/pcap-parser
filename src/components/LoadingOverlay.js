import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React from 'react';
function LoadingOverlay({ progress }) {
    const percentage = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;
    return (_jsxs("div", { className: "loading-overlay", children: [_jsx("div", { className: "loading-spinner" }), _jsx("p", { className: "loading-text", children: progress.text }), progress.total > 0 && (_jsxs("div", { className: "progress-container", children: [_jsx("div", { className: "progress-bar", children: _jsx("div", { className: "progress-fill", style: { width: `${percentage}%` } }) }), _jsxs("div", { className: "progress-stats", children: [_jsxs("span", { children: [progress.current, " / ", progress.total] }), _jsxs("span", { children: [percentage, "%"] })] })] }))] }));
}
export default LoadingOverlay;

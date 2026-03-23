#!/usr/bin/env python3
"""
app.py — The Evidence Protector: Web Interface
Run: python app.py  →  http://localhost:5000
"""

from flask import Flask, request, render_template_string, jsonify, render_template
import os, tempfile, json
from integrity_check import detect_gaps

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Evidence Protector | Terminal</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
/* ── RESET & BASE ── */
*{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg: #000000;
  --surface: #0a0a0a;
  --surface2: #121212;
  --surface3: #1a1a1a;
  --border: #2a2a2a;
  --border2: #3a3a3a;
  
  --text: #e0e0e0;
  --text-dim: #888888;
  --text-muted: #555555;
  
  /* Bloomberg/Terminal Accents */
  --accent: #ff8c00; 
  --accent-dim: rgba(255,140,0,0.1);
  --critical: #ff3333;
  --critical-dim: rgba(255,51,51,0.1);
  --medium: #ffcc00;
  --medium-dim: rgba(255,204,0,0.1);
  --low: #00cc66;
  --low-dim: rgba(0,204,102,0.1);
}

html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'IBM Plex Mono', monospace;
  min-height: 100vh;
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* ── TYPOGRAPHY UTILS ── */
.sans { font-family: 'Inter', sans-serif; }
.mono { font-family: 'IBM Plex Mono', monospace; }

/* ── HEADER ── */
header {
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  padding: 0 24px;
  height: 54px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 100;
}
.logo {
  display: flex;
  align-items: center;
  gap: 16px;
}
.logo-block {
  background: var(--accent);
  color: #000;
  font-weight: 700;
  padding: 2px 8px;
  font-size: 12px;
  letter-spacing: 1px;
}
.logo-text {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  letter-spacing: 0.5px;
}
.sys-time {
  font-size: 12px;
  color: var(--text-dim);
}

/* ── LAYOUT ── */
.container { max-width: 1400px; margin: 0 auto; padding: 24px; }

/* ── UPLOAD ZONE ── */
.upload-section {
  display: flex;
  gap: 24px;
  margin-bottom: 24px;
  align-items: stretch;
}

.drop-zone {
  flex: 1;
  border: 1px dashed var(--border2);
  background: var(--surface);
  padding: 24px;
  display: flex;
  flex-direction: column;
  justify-content: center;
  cursor: pointer;
  position: relative;
  transition: all 0.2s;
}
.drop-zone:hover, .drop-zone.dragover {
  border-color: var(--accent);
  background: var(--surface2);
}
.drop-zone input[type=file] {
  position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
}
.drop-title { font-weight: 600; color: var(--accent); margin-bottom: 4px; }
.drop-sub { font-size: 11px; color: var(--text-dim); }
.drop-filename {
  margin-top: 12px; font-size: 12px; color: var(--bg);
  padding: 4px 8px; background: var(--accent);
  display: inline-block; font-weight: 600;
}

/* ── CONTROLS ── */
.controls {
  display: flex;
  flex-direction: column;
  gap: 16px;
  min-width: 300px;
  background: var(--surface);
  border: 1px solid var(--border);
  padding: 16px;
}
.ctrl-row { display: flex; justify-content: space-between; align-items: center; gap: 16px; }
.ctrl-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; }
.ctrl-input, .ctrl-select {
  background: var(--bg);
  border: 1px solid var(--border2);
  color: var(--text);
  padding: 6px 10px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  width: 140px;
}
.ctrl-input:focus, .ctrl-select:focus { outline: none; border-color: var(--accent); }

.btn {
  padding: 8px 16px;
  font-family: 'IBM Plex Mono', monospace;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.1s;
}
.btn-primary {
  background: var(--accent);
  color: #000;
  width: 100%;
  padding: 12px;
  margin-top: auto;
}
.btn-primary:hover:not(:disabled) { background: #ff9d2e; }
.btn-primary:disabled { background: var(--border2); color: var(--text-muted); cursor: not-allowed; }

.btn-outline {
  background: transparent;
  border-color: var(--border2);
  color: var(--text);
}
.btn-outline:hover { border-color: var(--accent); color: var(--accent); }

/* ── LOADER ── */
#loader { display: none; padding: 40px; text-align: center; border: 1px solid var(--border); background: var(--surface); margin-bottom: 24px;}
.loader-text { color: var(--accent); font-weight: 600; animation: blink 1s infinite; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }

/* ── RESULTS ── */
#results { display: none; }

/* ── STAT GRID ── */
.stat-panel {
  display: flex;
  border: 1px solid var(--border);
  margin-bottom: 24px;
  background: var(--surface);
}
.stat-box {
  flex: 1;
  padding: 16px;
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
}
.stat-box:last-child { border-right: none; }
.stat-val { font-size: 24px; font-weight: 500; margin-bottom: 4px; line-height: 1; }
.stat-lbl { font-size: 10px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }

.c-accent { color: var(--accent); }
.c-crit { color: var(--critical); }
.c-med { color: var(--medium); }
.c-low { color: var(--low); }

/* ── PANELS ── */
.panel {
  border: 1px solid var(--border);
  margin-bottom: 24px;
  background: var(--surface);
}
.panel-header {
  padding: 8px 16px;
  border-bottom: 1px solid var(--border);
  background: var(--surface2);
  font-size: 11px;
  font-weight: 600;
  color: var(--text-dim);
  text-transform: uppercase;
  letter-spacing: 1px;
  display: flex;
  justify-content: space-between;
}
.panel-body { padding: 16px; }

/* ── CHART CONTAINER ── */
.chart-container {
  position: relative;
  height: 300px;
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 16px;
}

/* ── META GRID ── */
.meta-grid { display: flex; gap: 32px; flex-wrap: wrap; }
.meta-item { display: flex; flex-direction: column; gap: 4px; }
.meta-key { font-size: 10px; color: var(--text-muted); text-transform: uppercase; }
.meta-val { font-size: 13px; color: var(--text); }

/* ── TIMELINE BAR (UPDATED) ── */
.timeline-wrap { width: 100%; }
.timeline-times { 
  display: flex; justify-content: space-between; align-items: center;
  font-size: 10px; color: var(--text-dim); margin-bottom: 8px; 
}
.timeline-center-text { font-style: italic; color: var(--text-muted); }
.timeline-bar {
  height: 36px; /* Taller bar for text */
  display: flex;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}
.tl-seg { 
  height: 100%; cursor: pointer; transition: opacity 0.2s; 
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 600; color: #000;
  white-space: nowrap; overflow: hidden;
  border-right: 1px solid #000;
}
.tl-seg:last-child { border-right: none; }
.tl-seg:hover { opacity: 0.8; }
.tl-seg.ok { background: #0a1f14; border-right: none; } /* Dark green/grey for normal */
.tl-seg.CRITICAL { background: var(--critical); }
.tl-seg.MEDIUM { background: var(--medium); }
.tl-seg.LOW { background: var(--low); }

/* Timeline Legend */
.tl-legend {
  display: flex; justify-content: space-between; align-items: center;
  margin-top: 16px; font-size: 10px; color: var(--text-dim); text-transform: uppercase;
}
.legend-group { display: flex; gap: 24px; }
.legend-item { display: flex; align-items: center; gap: 6px; }
.legend-box { width: 12px; height: 12px; border: 1px solid var(--border); border-radius: 2px; }
.legend-box.ok { background: #0a1f14; border-color: #113322; }
.legend-box.CRITICAL { background: var(--critical); }
.legend-box.MEDIUM { background: var(--medium); }
.legend-box.LOW { background: var(--low); }
.legend-hint { color: var(--text-muted); text-transform: none; }

/* ── DATA TABLE (GAPS) ── */
.data-table { width: 100%; border-collapse: collapse; }
.data-table th {
  text-align: left; padding: 8px 12px;
  font-size: 10px; color: var(--text-dim);
  border-bottom: 1px solid var(--border);
  text-transform: uppercase; font-weight: normal;
}
.data-table td {
  padding: 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  vertical-align: top;
}
.row-header { cursor: pointer; background: var(--bg); transition: background 0.1s; }
.row-header:hover { background: var(--surface2); }
.row-header.CRITICAL td:first-child { border-left: 3px solid var(--critical); }
.row-header.MEDIUM td:first-child { border-left: 3px solid var(--medium); }
.row-header.LOW td:first-child { border-left: 3px solid var(--low); }

.tag {
  padding: 2px 6px; font-size: 10px; font-weight: 600;
  border: 1px solid transparent;
}
.tag.CRITICAL { color: var(--critical); border-color: var(--critical); background: var(--critical-dim); }
.tag.MEDIUM { color: var(--medium); border-color: var(--medium); background: var(--medium-dim); }
.tag.LOW { color: var(--low); border-color: var(--low); background: var(--low-dim); }

/* ── FORENSIC EXPAND ── */
.row-details { display: none; background: var(--surface); }
.row-details.open { display: table-row; }
.ctx-wrapper { padding: 16px; border-bottom: 1px solid var(--border); }
.ctx-label { font-size: 10px; color: var(--accent); margin-bottom: 8px; text-transform: uppercase; }
.ctx-block {
  background: var(--bg); border: 1px solid var(--border);
  padding: 8px; font-size: 12px; line-height: 1.4;
  overflow-x: auto;
}
.ctx-line { display: flex; gap: 16px; }
.ctx-linenum { color: var(--text-muted); user-select: none; width: 40px; text-align: right; flex-shrink: 0; }
.ctx-text { color: var(--text); white-space: pre; }
.ctx-text .highlight { color: #000; background: var(--critical); padding: 0 4px; }

.gap-divider {
  padding: 8px 0; text-align: center; font-size: 11px;
  color: var(--text-dim); border-top: 1px dashed var(--border2); border-bottom: 1px dashed var(--border2);
  margin: 8px 0;
}

/* ── INSIGHTS ── */
.insight-row {
  display: flex; gap: 12px; padding: 12px;
  border-bottom: 1px solid var(--border); background: var(--bg);
}
.insight-row:last-child { border-bottom: none; }
.insight-row.critical { border-left: 2px solid var(--critical); }
.insight-row.medium { border-left: 2px solid var(--medium); }
.insight-row.ok { border-left: 2px solid var(--low); }

/* ── CLEAN STATE ── */
.clean-state { text-align: center; padding: 48px; }
.clean-title { font-size: 18px; color: var(--low); margin-bottom: 8px; text-transform: uppercase; }

/* ── ERROR ── */
.error-box {
  padding: 12px 16px; margin-bottom: 24px;
  background: var(--critical-dim); border: 1px solid var(--critical);
  color: var(--critical); font-size: 12px; font-weight: 600;
}

/* SCROLLBAR */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg); border-left: 1px solid var(--border); }
::-webkit-scrollbar-thumb { background: var(--border2); }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-block">EP</div>
    <div class="logo-text">EVIDENCE PROTECTOR</div>
  </div>
  <div class="sys-time sans" id="clock">SYS.RDY // 00:00:00</div>
</header>

<div class="container">

  <div class="upload-section">
    <div class="drop-zone" id="dropZone">
      <input type="file" id="fileInput" accept=".log,.txt,.json">
      <div class="drop-title">[ IMPORT LOG FILE OR JSON REPORT ]</div>
      <div class="drop-sub">Drag & drop or click to browse (.log / .txt / .json)</div>
      <div id="fileNameWrapper" style="display:none">
        <div class="drop-filename" id="fileName"></div>
      </div>
    </div>

    <div class="controls">
      <div class="ctrl-row">
        <span class="ctrl-label">Threshold (s)</span>
        <input class="ctrl-input" type="number" id="threshold" value="60" min="1"/>
      </div>
      <div class="ctrl-row">
        <span class="ctrl-label">Format</span>
        <select class="ctrl-select" id="logFormat">
          <option value="auto">Auto-Detect</option>
          <option value="default">Default</option>
          <option value="syslog">Syslog</option>
          <option value="apache">Apache/Nginx</option>
          <option value="iso8601">ISO 8601</option>
        </select>
      </div>
      <button class="btn btn-primary" id="scanBtn" disabled onclick="runScan()">
        Execute Scan
      </button>
    </div>
  </div>

  <div id="errorBox"></div>
  <div id="loader">
    <div class="loader-text">&gt; ANALYZING TEMPORAL INTEGRITY...</div>
  </div>

  <div id="results"></div>

</div>

<script>
// Simple Clock for Header
setInterval(() => {
  const d = new Date();
  document.getElementById('clock').innerText = `SYS.RDY // ${d.toISOString().split('T')[1].split('.')[0]} Z`;
}, 1000);

let scanData = null;
let scatterChart = null;

let customHighlightKw = "";
let currentFilter = "ALL";

// ── FILE HANDLING ──
const fileInput = document.getElementById('fileInput');
const dropZone  = document.getElementById('dropZone');

fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) setFile(fileInput.files[0].name);
});
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault(); dropZone.classList.remove('dragover');
  if (e.dataTransfer.files[0]) {
    fileInput.files = e.dataTransfer.files;
    setFile(e.dataTransfer.files[0].name);
  }
});
function setFile(name) {
  document.getElementById('fileName').textContent = name; 
  document.getElementById('fileNameWrapper').style.display = 'block';
  document.getElementById('scanBtn').disabled = false;
}

// ── SCAN ──
async function runScan() {
  const file = fileInput.files[0];
  if (!file) return;

  // HYDRATION: If JSON, read directly without server
  if (file.name.toLowerCase().endsWith('.json')) {
    document.getElementById('loader').style.display = 'block';
    const reader = new FileReader();
    reader.onload = function(e) {
      try {
        const data = JSON.parse(e.target.result);
        scanData = { gaps: data.gaps, stats: data.summary };
        render(scanData);
      } catch(err) {
        document.getElementById('errorBox').innerHTML = `<div class="error-box">[ERROR] Invalid JSON Report</div>`;
      } finally {
        document.getElementById('loader').style.display = 'none';
      }
    };
    reader.readAsText(file);
    return;
  }

  const form = new FormData();
  form.append('logfile', file);
  form.append('threshold', document.getElementById('threshold').value);
  form.append('format', document.getElementById('logFormat').value);

  document.getElementById('loader').style.display = 'block';
  document.getElementById('results').style.display = 'none';
  document.getElementById('results').innerHTML = '';
  document.getElementById('errorBox').innerHTML = '';

  try {
    const res  = await fetch('/scan', { method:'POST', body:form });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    scanData = data;
    render(data);
  } catch(e) {
    document.getElementById('errorBox').innerHTML =
      `<div class="error-box">[ERROR] ${e.message}</div>`;
  } finally {
    document.getElementById('loader').style.display = 'none';
  }
}

// ── RENDER ──
function render({ gaps, stats }) {
  const el = document.getElementById('results');
  el.style.display = 'block';

  el.innerHTML = [
    renderStats(stats),
    renderMeta(stats),
    renderTimeline(gaps, stats), // Restored and upgraded Visual Timeline
    gaps.length ? renderChartContainer() : '', 
    gaps.length ? renderGaps(gaps) : renderClean(),
    gaps.length ? renderInsights(gaps, stats) : '',
  ].join('');

  if (gaps.length) {
    initChart(gaps);
  }
}

// ── TIMELINE BAR (RESTORED) ──
function renderTimeline(gaps, stats) {
  if (!gaps.length) return '';
  const tStart = new Date(stats.log_start);
  const tEnd   = new Date(stats.log_end);
  const total  = (tEnd - tStart) / 1000;
  if (total <= 0) return '';

  let segs = '';
  let prev = 0;

  gaps.forEach(g => {
    const gStart = (new Date(g.start_time) - tStart) / 1000;
    const gEnd   = (new Date(g.end_time)   - tStart) / 1000;
    const okPct  = ((gStart - prev) / total * 100).toFixed(3);
    const gapPct = Math.max((gEnd - gStart) / total * 100, 0.5).toFixed(3);

    // Normal segment
    if (parseFloat(okPct) > 0)
      segs += `<div class="tl-seg ok" style="width:${okPct}%" title="Normal Activity"></div>`;

    // Gap segment with internal text (if wide enough)
    const labelText = parseFloat(gapPct) > 4 ? `${g.duration_seconds}s` : '';
    segs += `<div class="tl-seg ${g.severity}" style="width:${gapPct}%"
      title="GAP #${g.gap_number}: ${g.duration_seconds}s"
      onclick="toggleRow(${g.gap_number})">
      ${labelText}
    </div>`;
    prev = gEnd;
  });

  const trailPct = ((total - prev) / total * 100).toFixed(3);
  if (parseFloat(trailPct) > 0)
    segs += `<div class="tl-seg ok" style="width:${trailPct}%"></div>`;

  return `<div class="panel">
    <div class="panel-header">Visual Timeline</div>
    <div class="panel-body">
      <div class="timeline-wrap">
        <div class="timeline-times">
          <span>${stats.log_start.split(' ')[1] || stats.log_start}</span>
          <span class="timeline-center-text">&larr; full log duration &rarr;</span>
          <span>${stats.log_end.split(' ')[1] || stats.log_end}</span>
        </div>
        <div class="timeline-bar">${segs}</div>
        
        <div class="tl-legend">
          <div class="legend-group">
            <div class="legend-item"><div class="legend-box ok"></div> Normal</div>
            <div class="legend-item"><div class="legend-box LOW"></div> LOW gap</div>
            <div class="legend-item"><div class="legend-box MEDIUM"></div> MEDIUM gap</div>
            <div class="legend-item"><div class="legend-box CRITICAL"></div> CRITICAL gap</div>
          </div>
          <div class="legend-hint">Click a gap segment to jump to details</div>
        </div>
        
      </div>
    </div>
  </div>`;
}

// ── CHART LOGIC ──
function renderChartContainer() {
  return `<div class="panel">
    <div class="panel-header">Anomaly Distribution (Duration vs Sequence)</div>
    <div class="panel-body">
      <div class="chart-container">
        <canvas id="scatterCanvas"></canvas>
      </div>
    </div>
  </div>`;
}

function initChart(allGaps) {
  const ctx = document.getElementById('scatterCanvas').getContext('2d');
  if (scatterChart) scatterChart.destroy();

  const gaps = allGaps.filter(g => currentFilter === 'ALL' || g.severity === currentFilter);

  const chartData = gaps.map(g => ({
    x: g.gap_number, y: g.duration_seconds, severity: g.severity, time: g.start_time
  }));

  const colorMap = { 'CRITICAL': '#ff3333', 'MEDIUM': '#ffcc00', 'LOW': '#00cc66' };

  scatterChart = new Chart(ctx, {
    type: 'scatter',
    data: {
      datasets: [{
        label: 'Log Anomalies', data: chartData,
        backgroundColor: context => context.raw ? colorMap[context.raw.severity] : '#e0e0e0',
        borderColor: '#0a0a0a', borderWidth: 1, pointRadius: 6, pointHoverRadius: 9, hoverBackgroundColor: '#ffffff'
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1a1a1a', titleColor: '#e0e0e0', bodyColor: '#e0e0e0',
          borderColor: '#3a3a3a', borderWidth: 1, padding: 12, displayColors: false,
          callbacks: {
            label: ctx => [`Gap: #${ctx.raw.x}`, `Duration: ${ctx.raw.y}s`, `Severity: ${ctx.raw.severity}`, `Time: ${ctx.raw.time}`]
          }
        }
      },
      scales: {
        x: {
          title: { display: true, text: 'Sequence (Gap Number)', color: '#555555', font: { family: 'IBM Plex Mono' } },
          grid: { color: '#1a1a1a', drawBorder: false },
          ticks: { color: '#888888', font: { family: 'IBM Plex Mono' } }
        },
        y: {
          title: { display: true, text: 'Duration (Seconds)', color: '#555555', font: { family: 'IBM Plex Mono' } },
          grid: { color: '#1a1a1a', drawBorder: false },
          ticks: { color: '#888888', font: { family: 'IBM Plex Mono' } },
          beginAtZero: true
        }
      }
    }
  });
}

// ── STAT CARDS ──
function renderStats(s) {
  return `<div class="stat-panel">
    <div class="stat-box"><div class="stat-val c-accent">${s.total_gaps}</div><div class="stat-lbl">Total Gaps</div></div>
    <div class="stat-box"><div class="stat-val c-crit">${s.critical_gaps}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat-box"><div class="stat-val c-med">${s.medium_gaps}</div><div class="stat-lbl">Medium</div></div>
    <div class="stat-box"><div class="stat-val c-low">${s.low_gaps}</div><div class="stat-lbl">Low</div></div>
    <div class="stat-box"><div class="stat-val c-crit" style="font-weight:700">${s.time_reversals || 0}</div><div class="stat-lbl c-crit">Reversals</div></div>
    <div class="stat-box"><div class="stat-val" style="color:var(--text)">${s.parsed_lines}</div><div class="stat-lbl">Lines Parsed</div></div>
  </div>`;
}

// ── SCAN META ──
function renderMeta(s) {
  return `<div class="panel">
    <div class="panel-header">Execution Metadata</div>
    <div class="panel-body">
      <div class="meta-grid">
        <div class="meta-item"><span class="meta-key">Format Detected</span><span class="meta-val">${s.format_detected.toUpperCase()}</span></div>
        <div class="meta-item"><span class="meta-key">Time Range</span><span class="meta-val">${s.log_start} — ${s.log_end}</span></div>
        <div class="meta-item"><span class="meta-key">Threshold</span><span class="meta-val">${s.threshold_seconds}s</span></div>
        <div class="meta-item"><span class="meta-key">Total File Lines</span><span class="meta-val">${s.total_lines}</span></div>
        <div class="meta-item" style="margin-left:auto; display:flex; flex-direction:row; gap:8px;">
           <button class="btn btn-outline" onclick="exportData('csv')">Export CSV</button>
           <button class="btn btn-outline" onclick="exportData('json')">Export JSON</button>
        </div>
      </div>
    </div>
  </div>`;
}

// ── GAP DATA TABLE ──
function highlightSuspicious(text) {
  const patterns = [/rm\s+\S+/g, /\/bin\/bash/g, /COMMAND=.+/g, /Accepted password/g, /cat \/etc\/shadow/g];
  let t = text;
  patterns.forEach(p => { t = t.replace(p, m => `<span class="highlight">${m}</span>`); });
  
  if (customHighlightKw) {
     const customRegex = new RegExp(customHighlightKw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
     t = t.replace(customRegex, m => `<span class="highlight" style="background:var(--accent); color:#000">${m}</span>`);
  }
  return t;
}

function renderContextLines(lines) {
  if (!lines || !lines.length) return '<div class="ctx-line"><div class="ctx-text" style="color:var(--text-muted)">[No context captured]</div></div>';
  return lines.map(([ln, txt]) => `
    <div class="ctx-line">
      <div class="ctx-linenum">${ln}</div>
      <div class="ctx-text">${highlightSuspicious(txt.replace(/</g,'&lt;'))}</div>
    </div>`).join('');
}

function toggleRow(id) {
  const details = document.getElementById(`details-${id}`);
  if(details) {
      details.classList.toggle('open');
      details.scrollIntoView({behavior:'smooth', block:'nearest'});
  }
}

function renderGaps(allGaps) {
  const gaps = allGaps.filter(g => currentFilter === 'ALL' || g.severity === currentFilter);

  const rows = gaps.map(g => `
    <tr class="row-header ${g.severity}" onclick="toggleRow(${g.gap_number})">
      <td><span class="tag ${g.severity}">${g.severity}</span> ${g.is_reversal ? `<span style="color:var(--critical); font-weight:bold; font-size:10px; margin-left:4px">REVERSAL</span>` : ``}</td>
      <td>${g.is_reversal ? `<span style="color:var(--critical);">${g.duration_seconds}s</span>` : `${g.duration_seconds}s`}</td>
      <td>${g.start_time}</td>
      <td>${g.end_time}</td>
      <td style="color:var(--text-muted)">L${g.start_line} &rarr; L${g.end_line}</td>
      <td style="text-align:right; color:var(--text-dim)">[+]</td>
    </tr>
    <tr class="row-details" id="details-${g.gap_number}">
      <td colspan="6" style="padding:0;">
        <div class="ctx-wrapper">
          <div class="ctx-label">Pre-Gap Log Tail</div>
          <div class="ctx-block">${renderContextLines(g.before_context)}</div>
          
          <div class="gap-divider">[ ${g.duration_seconds} SECONDS UNACCOUNTED ]</div>
          
          <div class="ctx-label">Post-Gap Log Head</div>
          <div class="ctx-block">${renderContextLines(g.after_context)}</div>
        </div>
      </td>
    </tr>`).join('');

  const filterBtns = `
    <div style="display:flex; gap:8px; margin-left:16px;">
      <button onclick="currentFilter='ALL'; render(scanData)" class="btn ${currentFilter==='ALL'?'btn-primary':'btn-outline'}" style="padding:4px 8px;">ALL</button>
      <button onclick="currentFilter='CRITICAL'; render(scanData)" class="btn ${currentFilter==='CRITICAL'?'btn-primary':'btn-outline'}" style="padding:4px 8px;">CRIT</button>
      <button onclick="currentFilter='MEDIUM'; render(scanData)" class="btn ${currentFilter==='MEDIUM'?'btn-primary':'btn-outline'}" style="padding:4px 8px;">MED</button>
      <button onclick="currentFilter='LOW'; render(scanData)" class="btn ${currentFilter==='LOW'?'btn-primary':'btn-outline'}" style="padding:4px 8px;">LOW</button>
    </div>
  `;

  return `<div class="panel">
    <div class="panel-header" style="align-items:center;">
      <span>Discrepancy Ledger <span>(Click row to expand)</span></span>
      ${filterBtns}
      <input type="text" id="customKw" placeholder="Custom Term Search (Regex allowed)" 
        style="background:var(--bg); color:var(--text); border:1px solid var(--border2); font-size:10px; padding:6px 8px; width:220px; margin-left:auto; font-family:'IBM Plex Mono';" 
        onchange="customHighlightKw=this.value; render(scanData);" value="${customHighlightKw}">
    </div>
    <table class="data-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Duration</th>
          <th>Start Time</th>
          <th>End Time</th>
          <th>Lines</th>
          <th></th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

// ── INSIGHTS ──
function renderInsights(gaps, stats) {
  const items = [];
  if (stats.critical_gaps > 0) items.push({ cls:'critical', text:`[!] ${stats.critical_gaps} CRITICAL gap(s) detected. Recommend immediate forensic verification.` });
  else if (stats.medium_gaps > 0) items.push({ cls:'medium', text:`[*] ${stats.medium_gaps} MEDIUM gap(s) found. Review surrounding network/auth activity.` });
  else items.push({ cls:'ok', text:`[+] Only LOW severity gaps found. Routine system latency likely.` });

  return `<div class="panel">
    <div class="panel-header">System Intelligence</div>
    <div>
      ${items.map(i => `<div class="insight-row ${i.cls}"><div>${i.text}</div></div>`).join('')}
    </div>
  </div>`;
}

function renderClean() {
  return `<div class="panel">
    <div class="clean-state">
      <div class="clean-title">LOG INTEGRITY: NOMINAL</div>
      <div style="color:var(--text-dim)">No temporal discrepancies detected beyond threshold.</div>
    </div>
  </div>`;
}

// ── EXPORT ──
function exportData(fmt) {
  if (!scanData) return;
  if (fmt === 'json') {
    const clean = { summary: scanData.stats, gaps: scanData.gaps.map(g => {
      const { before_context, after_context, after_line_num, ...rest } = g; return rest;
    })};
    dl(new Blob([JSON.stringify(clean,null,2)],{type:'application/json'}), 'evidence_report.json');
  } else {
    const cols = ['gap_number','start_time','end_time','start_line','end_line','duration_seconds','severity'];
    const rows = [cols.join(','), ...scanData.gaps.map(g => cols.map(c=>g[c]).join(','))];
    dl(new Blob([rows.join('\n')],{type:'text/csv'}), 'evidence_report.csv');
  }
}
function dl(blob, name) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
}
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template_string(HTML)

@app.route("/docs")
def docs():
    try:
        with open("README.md", "r", encoding="utf-8") as f:
            content = f.read()
            # Basic HTML escape to prevent XSS and formatting issues
            content = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"<pre style='margin:0; padding:2rem; background:#050505; color:#f0f0f0; font-family:\"IBM Plex Mono\", monospace; line-height:1.6; white-space:pre-wrap; word-wrap:break-word;'>{content}</pre>"
    except Exception as e:
        return str(e), 500

@app.route("/scan", methods=["POST"])
def scan():
    if "logfile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file      = request.files["logfile"]
    threshold = int(request.form.get("threshold", 60))
    fmt       = request.form.get("format", "auto")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".log", mode="wb") as tmp:
        file.save(tmp); tmp_path = tmp.name

    try:
        gaps, stats = detect_gaps(tmp_path, threshold, fmt)
        for g in gaps:
            g["before_context"] = [list(x) for x in g.get("before_context", [])]
            g["after_context"]  = [list(x) for x in g.get("after_context",  [])]
        return jsonify({"gaps": gaps, "stats": stats})
    finally:
        os.unlink(tmp_path)

if __name__ == "__main__":
    print("\n🛡  Evidence Protector — Web UI")
    print("   http://localhost:5000\n")
    app.run(debug=True, port=5000)
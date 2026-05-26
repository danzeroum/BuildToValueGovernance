/**
 * BuildToValue — Chart.js Wrappers
 * Dark-themed charts for trust timeline, latency, risk distribution.
 */

const BtvCharts = (() => {
  const chartDefaults = {
    color: '#7d8590',
    borderColor: 'rgba(255,255,255,0.06)',
    font: { family: "'JetBrains Mono', monospace", size: 10 },
  };

  function darkScales(yLabel = '') {
    return {
      x: {
        ticks: { color: '#7d8590', font: chartDefaults.font, maxTicksLimit: 8 },
        grid:  { color: 'rgba(255,255,255,0.04)' },
      },
      y: {
        ticks: { color: '#7d8590', font: chartDefaults.font, callback: v => yLabel ? v + yLabel : v },
        grid:  { color: 'rgba(255,255,255,0.04)' },
      },
    };
  }

  function shadeColor(action) {
    const m = { ALLOW:'rgba(63,185,80,.7)', BLOCK:'rgba(248,81,73,.7)', EDUCATE:'rgba(210,153,34,.7)', LOG:'rgba(88,166,255,.7)', REDACT:'rgba(188,140,255,.7)' };
    return m[action] || 'rgba(125,133,144,.7)';
  }

  // ── Trust Timeline ─────────────────────────────────────
  function createTrustTimeline(canvasId, history = []) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const labels = history.map((_, i) => i + 1);
    const values = history.map(h => h.value);
    const colors = history.map(h => shadeColor(h.action));

    const chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Trust Score',
            data: values,
            borderColor: '#388bfd',
            backgroundColor: 'rgba(56,139,253,.08)',
            pointBackgroundColor: colors,
            pointBorderColor: colors,
            pointRadius: 4,
            tension: 0.35,
            fill: true,
          },
          {
            label: 'Média Móvel (3pt)',
            data: _movingAvg(values, 3),
            borderColor: 'rgba(210,153,34,.6)',
            borderDash: [4, 3],
            pointRadius: 0,
            tension: 0.4,
            fill: false,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => `Trust: ${ctx.raw?.toFixed(3)} (${history[ctx.dataIndex]?.action || ''})`,
            },
            backgroundColor: '#161b22',
            borderColor: 'rgba(255,255,255,.08)',
            borderWidth: 1,
          },
        },
        scales: {
          ...darkScales(),
          y: {
            min: 0, max: 1,
            ticks: { color: '#7d8590', font: chartDefaults.font, stepSize: 0.2 },
            grid: { color: 'rgba(255,255,255,.04)' },
          },
        },
      },
      plugins: [{
        id: 'zones',
        beforeDraw(chart) {
          const { ctx, chartArea, scales } = chart;
          if (!chartArea) return;
          ctx.save();
          const zones = [
            { min: 0,   max: 0.3, color: 'rgba(248,81,73,.06)' },
            { min: 0.3, max: 0.6, color: 'rgba(210,153,34,.06)' },
            { min: 0.6, max: 1.0, color: 'rgba(63,185,80,.06)' },
          ];
          zones.forEach(z => {
            const y1 = scales.y.getPixelForValue(z.max);
            const y2 = scales.y.getPixelForValue(z.min);
            ctx.fillStyle = z.color;
            ctx.fillRect(chartArea.left, y1, chartArea.width, y2 - y1);
          });
          ctx.restore();
        },
      }],
    });
    return chart;
  }

  function updateTrustTimeline(chart, point) {
    if (!chart) return;
    chart.data.labels.push(chart.data.labels.length + 1);
    chart.data.datasets[0].data.push(point.value);
    chart.data.datasets[0].pointBackgroundColor.push(shadeColor(point.action));
    chart.data.datasets[0].pointBorderColor.push(shadeColor(point.action));
    const all = chart.data.datasets[0].data;
    chart.data.datasets[1].data = _movingAvg(all, 3);
    chart.update('none');
  }

  // ── Latency Bar Chart ──────────────────────────────────
  function createLatencyChart(canvasId, data = []) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;

    const latencies = data.slice(-30);
    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels: latencies.map((_, i) => i + 1),
        datasets: [{
          data: latencies,
          backgroundColor: latencies.map(v => v < 50 ? 'rgba(63,185,80,.6)' : v < 150 ? 'rgba(210,153,34,.6)' : 'rgba(248,81,73,.6)'),
          borderColor: latencies.map(v => v < 50 ? '#3fb950' : v < 150 ? '#d29922' : '#f85149'),
          borderWidth: 1,
          borderRadius: 3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 200 },
        plugins: { legend: { display: false }, tooltip: {
          callbacks: { label: ctx => `${ctx.raw?.toFixed(1)}ms` },
          backgroundColor: '#161b22', borderColor: 'rgba(255,255,255,.08)', borderWidth: 1,
        }},
        scales: darkScales('ms'),
      },
    });
  }

  function updateLatencyChart(chart, ms) {
    if (!chart) return;
    chart.data.labels.push(chart.data.labels.length + 1);
    chart.data.datasets[0].data.push(ms);
    chart.data.datasets[0].backgroundColor.push(ms < 50 ? 'rgba(63,185,80,.6)' : ms < 150 ? 'rgba(210,153,34,.6)' : 'rgba(248,81,73,.6)');
    chart.data.datasets[0].borderColor.push(ms < 50 ? '#3fb950' : ms < 150 ? '#d29922' : '#f85149');
    if (chart.data.labels.length > 30) {
      chart.data.labels.shift();
      chart.data.datasets[0].data.shift();
      chart.data.datasets[0].backgroundColor.shift();
      chart.data.datasets[0].borderColor.shift();
    }
    chart.update('none');
  }

  // ── Doughnut / Action Distribution ────────────────────
  function createActionDistChart(canvasId, counts = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    const labels = Object.keys(counts);
    const colorMap = { ALLOW:'#3fb950', BLOCK:'#f85149', EDUCATE:'#d29922', LOG:'#58a6ff', REDACT:'#bc8cff', INSPECT:'#79c0ff', REPORT:'#e3b341', REFUSE:'#f85149' };
    return new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data: labels.map(l => counts[l] || 0), backgroundColor: labels.map(l => colorMap[l] || '#7d8590'), borderWidth: 0, hoverOffset: 4 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#7d8590', font: { size: 11 }, boxWidth: 12, padding: 8 } },
          tooltip: { backgroundColor: '#161b22', borderColor: 'rgba(255,255,255,.08)', borderWidth: 1 },
        },
        cutout: '65%',
      },
    });
  }

  // ── Helpers ────────────────────────────────────────────
  function _movingAvg(data, window) {
    return data.map((_, i) => {
      const slice = data.slice(Math.max(0, i - window + 1), i + 1);
      return slice.reduce((a, b) => a + b, 0) / slice.length;
    });
  }

  function percentile(arr, p) {
    if (!arr.length) return 0;
    const sorted = [...arr].sort((a, b) => a - b);
    const idx = Math.ceil(p / 100 * sorted.length) - 1;
    return sorted[Math.max(0, idx)] || 0;
  }

  return { createTrustTimeline, updateTrustTimeline, createLatencyChart, updateLatencyChart, createActionDistChart, percentile };
})();

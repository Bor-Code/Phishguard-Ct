from phishguard import __version__


def render_dashboard_html() -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>PhishGuard-CT | SOC Threat Intelligence Dashboard</title>
  <style>
    :root {{
      --bg-primary: #070b14;
      --bg-sidebar: #0d1324;
      --bg-card: #121a2f;
      --bg-card-hover: #17223d;
      --bg-input: #1a2542;
      --border: #243256;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-glow: rgba(56, 189, 248, 0.2);
      --danger: #f43f5e;
      --success: #10b981;
      --warning: #f59e0b;
      --purple: #a855f7;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-main);
      line-height: 1.5;
      display: flex;
      min-height: 100vh;
    }}
    /* Sidebar */
    .sidebar {{
      width: 250px;
      background: var(--bg-sidebar);
      border-right: 1px solid var(--border);
      padding: 1.5rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
      flex-shrink: 0;
    }}
    .brand-box {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0 0.5rem 1rem;
      border-bottom: 1px solid var(--border);
    }}
    .shield-icon {{
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: linear-gradient(135deg, #38bdf8, #2563eb);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #fff;
      font-size: 1.1rem;
      box-shadow: 0 0 16px var(--accent-glow);
    }}
    .brand-box h1 {{
      font-size: 1.05rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }}
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      font-size: 0.7rem;
      font-weight: 600;
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.3);
    }}
    .nav-list {{
      display: flex;
      flex-direction: column;
      gap: 0.35rem;
    }}
    .nav-btn {{
      background: transparent;
      color: var(--text-muted);
      border: 1px solid transparent;
      text-align: left;
      padding: 0.65rem 0.9rem;
      border-radius: 0.5rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .nav-btn:hover {{
      background: var(--bg-card);
      color: var(--text-main);
    }}
    .nav-btn.active {{
      background: rgba(56, 189, 248, 0.14);
      color: var(--accent);
      border-color: rgba(56, 189, 248, 0.35);
    }}
    .sidebar-footer {{
      margin-top: auto;
      font-size: 0.78rem;
      color: var(--text-muted);
      padding: 0.75rem;
      background: var(--bg-card);
      border-radius: 0.5rem;
      border: 1px solid var(--border);
    }}
    /* Main Workspace */
    .workspace {{
      flex: 1;
      padding: 1.5rem 2rem;
      overflow-y: auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1.15rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .header-actions {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 0.7rem;
      padding: 1.25rem;
    }}
    .kpi-label {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
    }}
    .kpi-value {{
      font-size: 2rem;
      font-weight: 800;
      margin-top: 0.3rem;
    }}
    .charts-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1.2rem;
      margin-bottom: 1.5rem;
    }}
    .main-grid {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 1.2rem;
      margin-bottom: 1.5rem;
    }}
    @media (max-width: 1100px) {{
      .charts-grid, .main-grid {{ grid-template-columns: 1fr; }}
      body {{ flex-direction: column; }}
      .sidebar {{ width: 100%; border-right: none; border-bottom: 1px solid var(--border); }}
    }}
    h2 {{
      font-size: 0.98rem;
      font-weight: 600;
      margin-bottom: 1rem;
      color: var(--accent);
      letter-spacing: 0.01em;
    }}
    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}
    .scan-form {{
      display: flex;
      gap: 0.6rem;
      margin-bottom: 0.85rem;
    }}
    input[type="text"], input[type="number"], select, textarea {{
      background: var(--bg-input);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.55rem 0.8rem;
      border-radius: 0.45rem;
      font-size: 0.88rem;
      flex: 1;
      font-family: inherit;
    }}
    textarea {{
      width: 100%;
      min-height: 120px;
      resize: vertical;
      margin-bottom: 0.8rem;
    }}
    button {{
      background: var(--accent);
      color: #070b14;
      font-weight: 600;
      border: none;
      padding: 0.55rem 1.05rem;
      border-radius: 0.45rem;
      cursor: pointer;
      font-size: 0.86rem;
      transition: opacity 0.15s;
    }}
    button:hover {{ opacity: 0.9; }}
    .btn-outline {{
      background: var(--bg-input);
      color: var(--text-main);
      border: 1px solid var(--border);
    }}
    .btn-sm {{
      padding: 0.25rem 0.55rem;
      font-size: 0.74rem;
      border-radius: 0.35rem;
      margin-right: 0.25rem;
    }}
    .btn-inspect {{
      background: rgba(56, 189, 248, 0.18);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.4);
    }}
    .btn-confirm {{
      background: rgba(244, 63, 94, 0.2);
      color: var(--danger);
      border: 1px solid rgba(244, 63, 94, 0.4);
    }}
    .btn-dismiss {{
      background: rgba(148, 163, 184, 0.15);
      color: var(--text-muted);
      border: 1px solid rgba(148, 163, 184, 0.3);
    }}
    .scan-options {{
      display: flex;
      gap: 1.25rem;
      font-size: 0.84rem;
      color: var(--text-muted);
      margin-bottom: 1rem;
    }}
    .scan-result {{
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 0.95rem;
      font-size: 0.85rem;
      display: none;
    }}
    .signal-row {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-top: 0.45rem;
    }}
    .signal-name {{ width: 105px; color: var(--text-muted); font-size: 0.82rem; }}
    .signal-bar-bg {{
      flex: 1;
      height: 8px;
      background: #070b14;
      border-radius: 4px;
      overflow: hidden;
    }}
    .signal-bar-fill {{
      height: 100%;
      background: linear-gradient(90deg, #38bdf8, #818cf8);
      transition: width 0.3s ease;
    }}
    /* Donut Chart */
    .donut-wrap {{
      display: flex;
      align-items: center;
      gap: 1.2rem;
    }}
    .donut-legend {{
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      font-size: 0.82rem;
      flex: 1;
    }}
    .legend-item {{
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .legend-dot {{
      display: inline-block;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      margin-right: 0.45rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.86rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.7rem 0.75rem;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.75rem;
      text-transform: uppercase;
    }}
    tbody tr:hover {{ background: var(--bg-card-hover); }}
    .status-pill {{
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      font-size: 0.73rem;
      font-weight: 600;
    }}
    .pill-danger {{ background: rgba(244, 63, 94, 0.18); color: var(--danger); }}
    .pill-success {{ background: rgba(16, 185, 129, 0.18); color: var(--success); }}
    .pill-warning {{ background: rgba(245, 158, 11, 0.18); color: var(--warning); }}
    .toolbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.9rem;
      gap: 0.75rem;
      flex-wrap: wrap;
    }}
    .watchlist-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 1rem;
    }}
    .tag {{
      display: inline-block;
      background: var(--bg-input);
      border: 1px solid var(--border);
      padding: 0.12rem 0.45rem;
      border-radius: 0.3rem;
      font-size: 0.74rem;
      margin: 0.15rem;
      color: var(--text-muted);
    }}
    /* Modal */
    .modal-backdrop {{
      position: fixed;
      inset: 0;
      background: rgba(7, 11, 20, 0.78);
      backdrop-filter: blur(4px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 1rem;
    }}
    .modal-backdrop.open {{ display: flex; }}
    .modal-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 0.8rem;
      width: 100%;
      max-width: 640px;
      padding: 1.5rem;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
    }}
    .kv-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.65rem;
      margin: 1rem 0;
      font-size: 0.84rem;
    }}
    .kv-box {{
      background: var(--bg-input);
      padding: 0.55rem 0.75rem;
      border-radius: 0.4rem;
      border: 1px solid var(--border);
    }}
    .kv-label {{ color: var(--text-muted); font-size: 0.73rem; text-transform: uppercase; }}
  </style>
</head>
<body>
  <aside class="sidebar">
    <div class="brand-box">
      <div class="shield-icon">PG</div>
      <div>
        <h1>PhishGuard-CT</h1>
        <span class="badge">v{__version__}</span>
      </div>
    </div>
    <nav class="nav-list">
      <button class="nav-btn active" onclick="switchTab('overview', this)">Overview &amp; Charts</button>
      <button class="nav-btn" onclick="switchTab('threats', this)">Threat Explorer</button>
      <button class="nav-btn" onclick="switchTab('scanner', this)">Live &amp; Batch Scanner</button>
      <button class="nav-btn" onclick="switchTab('watchlist', this)">Brand Watchlist</button>
    </nav>
    <div class="sidebar-footer">
      <div><strong>Engine Status:</strong> <span style="color: var(--success);">ONLINE</span></div>
      <div style="margin-top: 0.35rem;">CT Stream &amp; Multi-Signal Heuristics Ready</div>
    </div>
  </aside>

  <main class="workspace">
    <header>
      <div>
        <h1 style="font-size: 1.35rem; font-weight: 700;">PhishGuard-CT SOC Console</h1>
        <p style="font-size: 0.83rem; color: var(--text-muted);">Real-time Certificate Transparency Phishing Detection &amp; Triage Interface</p>
      </div>
      <div class="header-actions">
        <label style="font-size: 0.82rem; color: var(--text-muted); margin-right: 0.4rem;">
          <input type="checkbox" id="auto-refresh" onchange="toggleAutoRefresh()" /> Auto-Refresh (10s)
        </label>
        <button class="btn-outline" onclick="window.location='/export?format=json'">Export JSON</button>
        <button class="btn-outline" onclick="window.location='/export?format=csv'">Export CSV</button>
        <button onclick="refreshAll()">Refresh Telemetry</button>
      </div>
    </header>

    <section class="kpi-grid">
      <div class="card">
        <div class="kpi-label">Flagged Domains</div>
        <div class="kpi-value" id="kpi-total">0</div>
      </div>
      <div class="card">
        <div class="kpi-label">Live Reachable Threats</div>
        <div class="kpi-value" id="kpi-live" style="color: var(--danger);">0</div>
      </div>
      <div class="card">
        <div class="kpi-label">Alerts Dispatched</div>
        <div class="kpi-value" id="kpi-alerts" style="color: var(--warning);">0</div>
      </div>
      <div class="card">
        <div class="kpi-label">Protected Brands</div>
        <div class="kpi-value" id="kpi-brands" style="color: var(--success);">0</div>
      </div>
    </section>

    <!-- TAB 1: OVERVIEW & CHARTS -->
    <div id="tab-overview" class="tab-pane active">
      <section class="charts-grid">
        <div class="card">
          <h2>Triage Status Breakdown</h2>
          <div class="donut-wrap">
            <svg width="110" height="110" viewBox="0 0 42 42" id="status-donut">
              <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#1a2542" stroke-width="5"></circle>
            </svg>
            <div class="donut-legend" id="status-legend">Loading...</div>
          </div>
        </div>

        <div class="card">
          <h2>Risk Severity Distribution</h2>
          <div id="severity-bars">Loading severity metrics...</div>
        </div>

        <div class="card">
          <h2>Mean Signal Telemetry</h2>
          <div id="signal-averages">Loading signal averages...</div>
        </div>
      </section>

      <section class="main-grid">
        <div class="card">
          <h2>On-Demand Domain Analyzer</h2>
          <div class="scan-form">
            <input type="text" id="scan-input" placeholder="Enter domain or URL (e.g. paypa1-secure-login.com)" />
            <button onclick="runScan()">Analyze</button>
          </div>
          <div class="scan-options">
            <label><input type="checkbox" id="scan-verify" /> Active HTTP/TLS/DNS Probe</label>
            <label><input type="checkbox" id="scan-save" checked /> Persist Suspect to DB</label>
          </div>
          <div class="scan-result" id="scan-result"></div>
        </div>

        <div class="card">
          <h2>Detections by Target Brand</h2>
          <div id="brand-breakdown" style="font-size: 0.86rem; color: var(--text-muted);">
            Loading brand telemetry...
          </div>
        </div>
      </section>
    </div>

    <!-- TAB 2: THREAT EXPLORER -->
    <div id="tab-threats" class="tab-pane" style="display: block;">
      <section class="card">
        <div class="toolbar">
          <h2 style="margin-bottom: 0;">Flagged Phishing Domains</h2>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            <input type="text" id="filter-brand" placeholder="Filter by brand..." style="max-width: 165px;" />
            <select id="filter-status" style="max-width: 150px;">
              <option value="">All Statuses</option>
              <option value="flagged">flagged</option>
              <option value="alert_sent">alert_sent</option>
              <option value="confirmed">confirmed</option>
              <option value="dismissed">dismissed</option>
            </select>
            <input type="number" id="filter-score" placeholder="Min Score (0.0)" step="0.05" min="0" max="1" style="max-width: 135px;" />
            <button onclick="loadDomains()">Filter</button>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>Target Brand</th>
              <th>Matched Token</th>
              <th>Confidence</th>
              <th>Reachable</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="domains-tbody">
            <tr><td colspan="7" style="color: var(--text-muted);">No detections loaded.</td></tr>
          </tbody>
        </table>
      </section>
    </div>

    <!-- TAB 3: BATCH & LIVE SCANNER -->
    <div id="tab-scanner" class="tab-pane">
      <section class="card">
        <h2>Bulk Domain Threat Analyzer</h2>
        <p style="font-size: 0.84rem; color: var(--text-muted); margin-bottom: 0.75rem;">
          Paste one domain or URL per line to evaluate multiple candidates against all protected brands simultaneously.
        </p>
        <textarea id="batch-input" placeholder="paypa1-account-verify.com&#10;g00gle-workspace-login.xyz&#10;apple-icloud-support.top"></textarea>
        <div class="scan-options">
          <label><input type="checkbox" id="batch-verify" /> Active Probe</label>
          <label><input type="checkbox" id="batch-save" checked /> Save Suspects to Database</label>
          <button onclick="runBatchScan()">Run Batch Scan</button>
        </div>
        <div id="batch-results" style="margin-top: 1rem;"></div>
      </section>
    </div>

    <!-- TAB 4: BRAND WATCHLIST -->
    <div id="tab-watchlist" class="tab-pane">
      <section class="card">
        <h2>Protected Brand Watchlist &amp; Allowlist</h2>
        <div id="watchlist-container" class="watchlist-grid">Loading watchlist...</div>
      </section>
    </div>
  </main>

  <!-- DOMAIN INSPECTOR MODAL -->
  <div class="modal-backdrop" id="detail-modal" onclick="if(event.target===this) closeModal()">
    <div class="modal-card" id="modal-content"></div>
  </div>

  <script>
    let refreshTimer = null;

    function switchTab(tabName, btn) {{
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      const panes = ['overview', 'threats', 'scanner', 'watchlist'];
      panes.forEach(p => {{
        const el = document.getElementById('tab-' + p);
        if (!el) return;
        if (tabName === 'overview') {{
          el.style.display = (p === 'overview' || p === 'threats') ? 'block' : 'none';
        }} else {{
          el.style.display = (p === tabName) ? 'block' : 'none';
        }}
      }});
      if (tabName === 'watchlist') loadWatchlist();
    }}

    function toggleAutoRefresh() {{
      const enabled = document.getElementById('auto-refresh').checked;
      if (refreshTimer) clearInterval(refreshTimer);
      if (enabled) refreshTimer = setInterval(refreshAll, 10000);
    }}

    function renderDonut(byStatus, total) {{
      const svg = document.getElementById('status-donut');
      const legend = document.getElementById('status-legend');
      const palette = {{
        flagged: '#f59e0b',
        alert_sent: '#38bdf8',
        confirmed: '#f43f5e',
        dismissed: '#64748b'
      }};
      const keys = ['flagged', 'alert_sent', 'confirmed', 'dismissed'];
      let offset = 25;
      let circles = '<circle cx="21" cy="21" r="15.915" fill="transparent" stroke="#1a2542" stroke-width="5"></circle>';
      keys.forEach(k => {{
        const val = (byStatus && byStatus[k]) || 0;
        if (total > 0 && val > 0) {{
          const pct = (val / total) * 100;
          circles += `<circle cx="21" cy="21" r="15.915" fill="transparent" stroke="${{palette[k]}}" stroke-width="5" stroke-dasharray="${{pct}} ${{100 - pct}}" stroke-dashoffset="${{offset}}"></circle>`;
          offset = (offset - pct + 100) % 100;
        }}
      }});
      svg.innerHTML = circles;
      legend.innerHTML = keys.map(k => `
        <div class="legend-item">
          <span><span class="legend-dot" style="background:${{palette[k]}}"></span>${{k}}</span>
          <strong>${{(byStatus && byStatus[k]) || 0}}</strong>
        </div>
      `).join('');
    }}

    async function loadStats() {{
      const res = await fetch('/stats');
      const data = await res.json();
      document.getElementById('kpi-total').textContent = data.total_flagged;
      document.getElementById('kpi-live').textContent = data.live_domains;
      document.getElementById('kpi-alerts').textContent = data.alerts_sent;
      document.getElementById('kpi-brands').textContent = data.watchlist_brands_count;

      renderDonut(data.by_status || {{}}, data.total_flagged || 0);

      const sev = data.severity_buckets || {{ critical: 0, high: 0, medium: 0 }};
      const maxSev = Math.max(sev.critical, sev.high, sev.medium, 1);
      document.getElementById('severity-bars').innerHTML = `
        <div class="signal-row"><span class="signal-name">Critical (&ge;0.90)</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="background:var(--danger);width:${{Math.round((sev.critical/maxSev)*100)}}%"></div></div><strong>${{sev.critical}}</strong></div>
        <div class="signal-row"><span class="signal-name">High (0.75-0.89)</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="background:var(--warning);width:${{Math.round((sev.high/maxSev)*100)}}%"></div></div><strong>${{sev.high}}</strong></div>
        <div class="signal-row"><span class="signal-name">Medium (&lt;0.75)</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="background:var(--accent);width:${{Math.round((sev.medium/maxSev)*100)}}%"></div></div><strong>${{sev.medium}}</strong></div>
      `;

      const avg = data.signal_averages || {{}};
      document.getElementById('signal-averages').innerHTML = [
        ['Levenshtein', avg.levenshtein || 0],
        ['Keyboard', avg.keyboard || 0],
        ['Homoglyph', avg.homoglyph || 0],
        ['Affix / Token', avg.subdomain_or_affix || 0]
      ].map(([label, val]) => `
        <div class="signal-row">
          <span class="signal-name">${{label}}</span>
          <div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{Math.round(val*100)}}%"></div></div>
          <span>${{Number(val).toFixed(2)}}</span>
        </div>
      `).join('');

      const container = document.getElementById('brand-breakdown');
      const entries = Object.entries(data.by_brand || {{}});
      if (entries.length === 0) {{
        container.innerHTML = '<p>No brand detections recorded yet.</p>';
        return;
      }}
      const maxCount = Math.max(...entries.map(e => e[1]), 1);
      container.innerHTML = entries.map(([brand, count]) => {{
        const pct = Math.round((count / maxCount) * 100);
        return `
          <div class="signal-row">
            <span class="signal-name"><strong>${{brand}}</strong></span>
            <div class="signal-bar-bg"><div class="signal-bar-fill" style="width: ${{pct}}%"></div></div>
            <span style="width: 32px; text-align: right;">${{count}}</span>
          </div>`;
      }}).join('');
    }}

    async function loadDomains() {{
      const brand = document.getElementById('filter-brand').value.trim();
      const status = document.getElementById('filter-status').value;
      const minScore = document.getElementById('filter-score').value.trim();
      const params = new URLSearchParams();
      if (brand) params.set('brand', brand);
      if (status) params.set('status', status);
      if (minScore) params.set('min_score', minScore);
      const query = params.toString() ? `?${{params.toString()}}` : '';
      const res = await fetch('/domains' + query);
      const data = await res.json();
      const tbody = document.getElementById('domains-tbody');
      if (!data.items || data.items.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="7" style="color: var(--text-muted);">No flagged domains matching criteria.</td></tr>';
        return;
      }}
      tbody.innerHTML = data.items.map(item => `
        <tr>
          <td><code>${{item.domain}}</code></td>
          <td><strong>${{item.target_brand}}</strong></td>
          <td><code>${{item.matched_term}}</code></td>
          <td><strong>${{item.final_confidence_score.toFixed(4)}}</strong></td>
          <td><span class="status-pill ${{item.is_live ? 'pill-danger' : 'pill-success'}}">${{item.is_live ? 'YES' : 'NO'}}</span></td>
          <td><span class="status-pill ${{item.status === 'confirmed' ? 'pill-danger' : (item.status === 'dismissed' ? 'pill-success' : 'pill-warning')}}">${{item.status}}</span></td>
          <td>
            <button class="btn-sm btn-inspect" onclick="inspectDomainModal('${{item.domain}}')">Inspect</button>
            <button class="btn-sm btn-confirm" onclick="updateDomainStatus('${{item.domain}}', 'confirmed')">Confirm</button>
            <button class="btn-sm btn-dismiss" onclick="updateDomainStatus('${{item.domain}}', 'dismissed')">Dismiss</button>
          </td>
        </tr>
      `).join('');
    }}

    async function inspectDomainModal(domain) {{
      const res = await fetch(`/domains/${{encodeURIComponent(domain)}}`);
      if (!res.ok) return;
      const d = await res.json();
      const s = d.signals || {{}};
      const risks = (d.risk_factors && d.risk_factors.length)
        ? d.risk_factors.map(r => `<span class="tag" style="color:var(--danger);border-color:rgba(244,63,94,0.4);">${{r}}</span>`).join('')
        : '<span style="color:var(--text-muted);">None recorded</span>';

      document.getElementById('modal-content').innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border);padding-bottom:0.8rem;">
          <div>
            <h2 style="margin:0;"><code>${{d.domain}}</code></h2>
            <span style="font-size:0.8rem;color:var(--text-muted);">Detected: ${{d.detected_at || '-'}}</span>
          </div>
          <button class="btn-outline btn-sm" onclick="closeModal()">Close</button>
        </div>
        <div class="kv-grid">
          <div class="kv-box"><div class="kv-label">Target Brand</div><strong>${{d.target_brand}}</strong> (matched: <code>${{d.matched_term}}</code>)</div>
          <div class="kv-box"><div class="kv-label">Final Confidence</div><strong>${{d.final_confidence_score.toFixed(4)}}</strong> (x${{d.confidence_multiplier}})</div>
          <div class="kv-box"><div class="kv-label">HTTP Probe</div>Status: <strong>${{d.http_status || 'N/A'}}</strong> | Live: <strong>${{d.is_live ? 'YES' : 'NO'}}</strong></div>
          <div class="kv-box"><div class="kv-label">TLS Certificate</div>Issuer: <strong>${{d.cert_issuer || 'N/A'}}</strong> (${{d.is_free_ca ? 'Free CA' : 'Standard'}})</div>
          <div class="kv-box"><div class="kv-label">Page Title</div>${{d.page_title || 'N/A'}}</div>
          <div class="kv-box"><div class="kv-label">Credential Forms</div>Password Input: <strong>${{d.has_password_input ? 'YES' : 'NO'}}</strong></div>
        </div>
        <div style="margin-bottom:0.9rem;">
          <div class="kv-label" style="margin-bottom:0.35rem;">Similarity Signal Breakdown</div>
          <div class="signal-row"><span class="signal-name">Levenshtein</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.levenshtein||0)*100}}%"></div></div><span>${{(s.levenshtein||0).toFixed(2)}}</span></div>
          <div class="signal-row"><span class="signal-name">Keyboard</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.keyboard||0)*100}}%"></div></div><span>${{(s.keyboard||0).toFixed(2)}}</span></div>
          <div class="signal-row"><span class="signal-name">Homoglyph</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.homoglyph||0)*100}}%"></div></div><span>${{(s.homoglyph||0).toFixed(2)}}</span></div>
          <div class="signal-row"><span class="signal-name">Affix</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.subdomain_or_affix||0)*100}}%"></div></div><span>${{(s.subdomain_or_affix||0).toFixed(2)}}</span></div>
        </div>
        <div style="margin-bottom:1.1rem;">
          <div class="kv-label" style="margin-bottom:0.3rem;">Risk Factors</div>
          ${{risks}}
        </div>
        <div style="display:flex;justify-content:flex-end;gap:0.5rem;">
          <button class="btn-confirm" onclick="updateDomainStatus('${{d.domain}}', 'confirmed'); closeModal();">Confirm Phishing</button>
          <button class="btn-dismiss" onclick="updateDomainStatus('${{d.domain}}', 'dismissed'); closeModal();">Dismiss False Positive</button>
        </div>
      `;
      document.getElementById('detail-modal').classList.add('open');
    }}

    function closeModal() {{
      document.getElementById('detail-modal').classList.remove('open');
    }}

    async function updateDomainStatus(domain, status) {{
      await fetch(`/domains/${{encodeURIComponent(domain)}}`, {{
        method: 'PATCH',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ status }})
      }});
      refreshAll();
    }}

    async function runScan() {{
      const domain = document.getElementById('scan-input').value.trim();
      if (!domain) return;
      const verify = document.getElementById('scan-verify').checked;
      const save = document.getElementById('scan-save').checked;
      const box = document.getElementById('scan-result');
      box.style.display = 'block';
      box.innerHTML = 'Analyzing domain...';

      const res = await fetch('/scan', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ domain, verify, save }})
      }});
      const r = await res.json();
      if (r.error) {{
        box.innerHTML = `<span style="color: var(--danger);">${{r.error}}</span>`;
        return;
      }}
      const verdict = r.is_legitimate
        ? '<span class="status-pill pill-success">LEGITIMATE</span>'
        : (r.is_phishing_suspect
            ? '<span class="status-pill pill-danger">PHISHING SUSPECT</span>'
            : '<span class="status-pill pill-success">CLEAN / LOW RISK</span>');
      const s = r.signals || {{}};
      box.innerHTML = `
        <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
          <strong>${{r.domain}}</strong> ${{verdict}}
        </div>
        <div>Target Brand: <strong>${{r.target_brand || '-'}}</strong> | Matched: <code>${{r.matched_term || '-'}}</code> | Score: <strong>${{(r.final_confidence_score || 0).toFixed(4)}}</strong></div>
        <div class="signal-row"><span class="signal-name">Levenshtein</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.levenshtein||0)*100}}%"></div></div><span>${{(s.levenshtein||0).toFixed(2)}}</span></div>
        <div class="signal-row"><span class="signal-name">Keyboard</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.keyboard||0)*100}}%"></div></div><span>${{(s.keyboard||0).toFixed(2)}}</span></div>
        <div class="signal-row"><span class="signal-name">Homoglyph</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.homoglyph||0)*100}}%"></div></div><span>${{(s.homoglyph||0).toFixed(2)}}</span></div>
        <div class="signal-row"><span class="signal-name">Affix</span><div class="signal-bar-bg"><div class="signal-bar-fill" style="width:${{(s.subdomain_or_affix||0)*100}}%"></div></div><span>${{(s.subdomain_or_affix||0).toFixed(2)}}</span></div>
      `;
      refreshAll();
    }}

    async function runBatchScan() {{
      const raw = document.getElementById('batch-input').value;
      const domains = raw.split(/\\r?\\n/).map(s => s.trim()).filter(Boolean);
      if (!domains.length) return;
      const verify = document.getElementById('batch-verify').checked;
      const save = document.getElementById('batch-save').checked;
      const container = document.getElementById('batch-results');
      container.innerHTML = 'Running batch scan...';

      const res = await fetch('/batch-scan', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ domains, verify, save }})
      }});
      const data = await res.json();
      if (data.error) {{
        container.innerHTML = `<span style="color:var(--danger);">${{data.error}}</span>`;
        return;
      }}
      container.innerHTML = `
        <div style="margin-bottom:0.6rem;font-size:0.86rem;">
          Scanned: <strong>${{data.total_scanned}}</strong> | Suspects Detected: <strong style="color:var(--danger);">${{data.suspects_detected}}</strong>
        </div>
        <table>
          <thead><tr><th>Domain</th><th>Target Brand</th><th>Matched</th><th>Confidence</th><th>Verdict</th></tr></thead>
          <tbody>
            ${{data.results.map(r => `
              <tr>
                <td><code>${{r.domain}}</code></td>
                <td>${{r.target_brand || '-'}}</td>
                <td><code>${{r.matched_term || '-'}}</code></td>
                <td><strong>${{(r.final_confidence_score || 0).toFixed(4)}}</strong></td>
                <td><span class="status-pill ${{r.is_phishing_suspect ? 'pill-danger' : 'pill-success'}}">${{r.is_phishing_suspect ? 'SUSPECT' : 'CLEAN'}}</span></td>
              </tr>
            `).join('')}}
          </tbody>
        </table>
      `;
      refreshAll();
    }}

    async function loadWatchlist() {{
      const res = await fetch('/watchlist');
      const data = await res.json();
      const box = document.getElementById('watchlist-container');
      box.innerHTML = (data.brands || []).map(b => `
        <div class="card" style="background:var(--bg-input);">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
            <strong style="font-size:1rem;text-transform:capitalize;">${{b.name}}</strong>
            <span class="badge">Threshold: ${{b.similarity_threshold}}</span>
          </div>
          <div class="kv-label" style="margin-top:0.4rem;">Monitored Keywords</div>
          <div>${{b.keywords.map(k => `<span class="tag">${{k}}</span>`).join('')}}</div>
          <div class="kv-label" style="margin-top:0.5rem;">Allowlisted Domains</div>
          <div>${{b.legitimate_domains.map(d => `<span class="tag" style="color:var(--success);">${{d}}</span>`).join('')}}</div>
        </div>
      `).join('');
    }}

    function refreshAll() {{
      loadStats();
      loadDomains();
    }}
    refreshAll();
  </script>
</body>
</html>"""

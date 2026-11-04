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
      --bg-primary: #0b0f19;
      --bg-card: #131b2e;
      --bg-input: #1c263f;
      --border: #263354;
      --text-main: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #f43f5e;
      --success: #10b981;
      --warning: #f59e0b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-main);
      line-height: 1.5;
      padding: 1.5rem 2rem;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 1.25rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 1.5rem;
    }}
    .brand-title {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .brand-title h1 {{
      font-size: 1.4rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: rgba(56, 189, 248, 0.15);
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.3);
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }}
    .card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 0.6rem;
      padding: 1.2rem;
    }}
    .kpi-label {{
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
    }}
    .kpi-value {{
      font-size: 1.9rem;
      font-weight: 700;
      margin-top: 0.35rem;
    }}
    .main-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }}
    @media (max-width: 960px) {{
      .main-grid {{ grid-template-columns: 1fr; }}
    }}
    h2 {{
      font-size: 1rem;
      font-weight: 600;
      margin-bottom: 1rem;
      color: var(--accent);
    }}
    .scan-form {{
      display: flex;
      gap: 0.6rem;
      margin-bottom: 0.85rem;
    }}
    input[type="text"], select {{
      background: var(--bg-input);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 0.55rem 0.8rem;
      border-radius: 0.4rem;
      font-size: 0.9rem;
      flex: 1;
    }}
    button {{
      background: var(--accent);
      color: #0b0f19;
      font-weight: 600;
      border: none;
      padding: 0.55rem 1.1rem;
      border-radius: 0.4rem;
      cursor: pointer;
      font-size: 0.9rem;
    }}
    button:hover {{ opacity: 0.9; }}
    .btn-sm {{
      padding: 0.25rem 0.6rem;
      font-size: 0.75rem;
      border-radius: 0.3rem;
      margin-right: 0.3rem;
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
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 1rem;
    }}
    .scan-result {{
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 0.45rem;
      padding: 0.9rem;
      font-size: 0.85rem;
      display: none;
    }}
    .signal-row {{
      display: flex;
      align-items: center;
      gap: 0.6rem;
      margin-top: 0.4rem;
    }}
    .signal-name {{ width: 95px; color: var(--text-muted); }}
    .signal-bar-bg {{
      flex: 1;
      height: 8px;
      background: #0b0f19;
      border-radius: 4px;
      overflow: hidden;
    }}
    .signal-bar-fill {{
      height: 100%;
      background: var(--accent);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.7rem 0.75rem;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      color: var(--text-muted);
      font-weight: 600;
      font-size: 0.78rem;
      text-transform: uppercase;
    }}
    .status-pill {{
      padding: 0.15rem 0.55rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .pill-danger {{ background: rgba(244, 63, 94, 0.18); color: var(--danger); }}
    .pill-success {{ background: rgba(16, 185, 129, 0.18); color: var(--success); }}
    .toolbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.9rem;
      gap: 0.75rem;
    }}
  </style>
</head>
<body>
  <header>
    <div class="brand-title">
      <h1>PhishGuard-CT SOC Console</h1>
      <span class="badge">v{__version__}</span>
    </div>
    <div>
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

  <section class="main-grid">
    <div class="card">
      <h2>On-Demand Domain Analyzer</h2>
      <div class="scan-form">
        <input type="text" id="scan-input" placeholder="Enter domain or URL (e.g. paypa1-secure.com)" />
        <button onclick="runScan()">Analyze</button>
      </div>
      <div class="scan-options">
        <label><input type="checkbox" id="scan-verify" /> Active HTTP/TLS Probe</label>
        <label><input type="checkbox" id="scan-save" checked /> Persist Suspect to DB</label>
      </div>
      <div class="scan-result" id="scan-result"></div>
    </div>

    <div class="card">
      <h2>Detections by Target Brand</h2>
      <div id="brand-breakdown" style="font-size: 0.88rem; color: var(--text-muted);">
        Loading brand telemetry...
      </div>
    </div>
  </section>

  <section class="card">
    <div class="toolbar">
      <h2 style="margin-bottom: 0;">Flagged Phishing Domains</h2>
      <div style="display: flex; gap: 0.5rem;">
        <input type="text" id="filter-brand" placeholder="Filter by brand..." style="max-width: 180px;" />
        <select id="filter-status" style="max-width: 160px;">
          <option value="">All Statuses</option>
          <option value="flagged">flagged</option>
          <option value="alert_sent">alert_sent</option>
          <option value="confirmed">confirmed</option>
          <option value="dismissed">dismissed</option>
        </select>
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

  <script>
    async function loadStats() {{
      const res = await fetch('/stats');
      const data = await res.json();
      document.getElementById('kpi-total').textContent = data.total_flagged;
      document.getElementById('kpi-live').textContent = data.live_domains;
      document.getElementById('kpi-alerts').textContent = data.alerts_sent;
      document.getElementById('kpi-brands').textContent = data.watchlist_brands_count;

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
      const params = new URLSearchParams();
      if (brand) params.set('brand', brand);
      if (status) params.set('status', status);
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
          <td>${{item.target_brand}}</td>
          <td>${{item.matched_term}}</td>
          <td><strong>${{item.final_confidence_score.toFixed(4)}}</strong></td>
          <td><span class="status-pill ${{item.is_live ? 'pill-danger' : 'pill-success'}}">${{item.is_live ? 'YES' : 'NO'}}</span></td>
          <td>${{item.status}}</td>
          <td>
            <button class="btn-sm btn-confirm" onclick="updateDomainStatus('${{item.domain}}', 'confirmed')">Confirm</button>
            <button class="btn-sm btn-dismiss" onclick="updateDomainStatus('${{item.domain}}', 'dismissed')">Dismiss</button>
          </td>
        </tr>
      `).join('');
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

    function refreshAll() {{
      loadStats();
      loadDomains();
    }}
    refreshAll();
  </script>
</body>
</html>"""

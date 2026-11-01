(function () {
  'use strict';

  const API_BASE = '';
  const STATE = {
    view: 'overview',
  };

  const els = {
    tabs: document.querySelectorAll('.tabs [role="tab"]'),
    panels: {
      overview: document.getElementById('panel-overview'),
      findings: document.getElementById('panel-findings'),
      assets: document.getElementById('panel-assets'),
      cases: document.getElementById('panel-cases'),
      integrations: document.getElementById('panel-integrations'),
    },
    demoStatus: document.getElementById('demoStatus'),
    apiStatus: document.getElementById('apiStatus'),
    mOrgs: document.getElementById('mOrgs'),
    mAssets: document.getElementById('mAssets'),
    mFindings: document.getElementById('mFindings'),
    mCases: document.getElementById('mCases'),
    priorityList: document.getElementById('priorityList'),
    lastRun: document.getElementById('lastRun'),
    findingsBody: document.getElementById('findingsBody'),
    findingsEmpty: document.getElementById('findingsEmpty'),
    assetsBody: document.getElementById('assetsBody'),
    assetsEmpty: document.getElementById('assetsEmpty'),
    casesBody: document.getElementById('casesBody'),
    casesEmpty: document.getElementById('casesEmpty'),
    intelBody: document.getElementById('intelBody'),
    intelEmpty: document.getElementById('intelEmpty'),
    btnRunDetection: document.getElementById('btnRunDetection'),
    btnRunDetectionFindings: document.getElementById('btnRunDetectionFindings'),
    btnResetDemo: document.getElementById('btnResetDemo'),
    btnRefreshIntel: document.getElementById('btnRefreshIntel'),
    btnRefreshIntelEmpty: document.getElementById('btnRefreshIntelEmpty'),
    btnConnectModel: document.getElementById('btnConnectModel'),
  };

  async function api(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`API ${path} failed (${res.status})${body ? ': ' + body.slice(0, 200) : ''}`);
    }
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
  }

  function formatDate(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch (e) {
      return String(iso);
    }
  }

  function setStatus(element, text, kind = 'neutral') {
    element.textContent = text;
    element.className = 'status-pill status-' + kind;
  }

  async function loadHealth() {
    try {
      const data = await api('/health');
      setStatus(
        els.demoStatus,
        `Local demo status — ${data.mode || 'local_demo'}`,
        data.mode === 'local_demo' ? 'ok' : 'neutral'
      );
      setStatus(
        els.apiStatus,
        `API — ok (${data.mode || 'local_demo'})`,
        'ok'
      );
    } catch (err) {
      setStatus(els.demoStatus, 'Local demo status — unreachable', 'danger');
      setStatus(els.apiStatus, 'API — error', 'danger');
    }
  }

  async function loadOverview() {
    try {
      const data = await api('/api/overview');
      els.mOrgs.textContent = data.organizations ?? '—';
      els.mAssets.textContent = data.assets ?? '—';
      els.mFindings.textContent = data.open_findings ?? '—';
      els.mCases.textContent = data.active_cases ?? '—';

      const list = els.priorityList;
      list.innerHTML = '';
      const priorities = data.priorities || {};
      const keys = Object.keys(priorities);
      if (keys.length === 0) {
        list.innerHTML = '<div class="priority-empty">No open findings. Run detection to populate the demo scenario.</div>';
      } else {
        const priorityRank = (value) => {
          const match = String(value).match(/^P([1-4])/);
          return match ? Number(match[1]) : 5;
        };
        keys
          .slice()
          .sort((a, b) => priorityRank(a) - priorityRank(b) || priorities[b] - priorities[a])
          .forEach((key) => {
            const row = document.createElement('div');
            row.className = 'priority-row';
            const cls = priorityClass(key);
            row.innerHTML =
              `<span class="priority-chip ${cls}" aria-hidden="true"></span>
               <span class="priority-label">${escapeHtml(key)}</span>
               <span class="priority-count">${priorities[key]}</span>`;
            list.appendChild(row);
          });
      }

      const lastRunPanel = els.lastRun;
      const run = data.last_run;
      if (!run) {
        lastRunPanel.innerHTML = '<h2>Last detection run</h2><div class="empty">No scan run recorded yet.</div>';
        return;
      }
      const summary = run.summary || {};
      lastRunPanel.innerHTML =
        '<h2>Last detection run</h2>' +
        '<div class="run-meta">' +
        '<div><b>Run ID</b><span>' + escapeHtml(run.id) + '</span></div>' +
        '<div><b>Mode</b><span>' + escapeHtml(run.mode) + '</span></div>' +
        '<div><b>Status</b><span>' + escapeHtml(run.status) + '</span></div>' +
        '<div><b>Completed</b><span>' + formatDate(run.completed_at) + '</span></div>' +
        '<div><b>Findings</b><span>' + (summary.findings ?? '—') + '</span></div>' +
        '<div><b>Cases</b><span>' + (summary.cases ?? '—') + '</span></div>' +
        '<div><b>Components checked</b><span>' + (summary.components_checked ?? '—') + '</span></div>' +
        '<div><b>Coverage</b><span>' + escapeHtml(String(summary.coverage ?? '—')) + '</span></div>' +
        '<div><b>Source mode</b><span>' + escapeHtml(String(summary.source_mode ?? '—')) + '</span></div>' +
        '</div>';
    } catch (err) {
      els.demoStatus.textContent = 'Local demo status — error';
      console.error('overview load failed', err);
    }
  }

  function priorityClass(priority) {
    if (!priority) return 'p4';
    const m = String(priority).match(/P([1-4])/);
    return m ? 'p' + m[1] : 'p4';
  }

  function matchLabel(state) {
    const map = {
      affected: 'Affected',
      confirmed_affected: 'Confirmed affected',
      not_affected: 'Not affected',
      unverified: 'Unverified',
    };
    return map[String(state)] || String(state);
  }

  async function loadFindings() {
    try {
      const findings = await api('/api/findings');
      const body = els.findingsBody;
      const empty = els.findingsEmpty;
      body.innerHTML = '';
      if (!findings || findings.length === 0) {
        body.hidden = true;
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      body.hidden = false;
      findings.forEach((f) => {
        const tr = document.createElement('tr');
        const evidence = f.evidence || {};
        const osv = evidence.osv || {};
        const cisa = evidence.cisa_kev || {};
        const cve = f.cve_id || (osv.aliases && osv.aliases[0]) || '—';
        const kev = cisa.status || 'unknown';
        tr.innerHTML =
          '<td class="finding-id" data-label="Finding ID">' +
          escapeHtml(f.id) +
          '</td>' +
          '<td data-label="Asset">' +
          escapeHtml(f.hostname) +
          '</td>' +
          '<td data-label="Package">' +
          escapeHtml(osv.package || f.package_name || '—') +
          ' <span style="color:var(--text-dim)">@' +
          escapeHtml(osv.version || f.version || '') +
          '</span></td>' +
          '<td data-label="CVE">' +
          escapeHtml(cve) +
          '</td>' +
          '<td data-label="Match state">' +
          escapeHtml(matchLabel(f.match_state)) +
          '</td>' +
          '<td data-label="KEV">' +
          '<span class="kev-badge ' +
          (kev === 'listed' ? 'yes' : kev === 'not_listed' ? 'no' : 'unknown') +
          '">' +
          escapeHtml(kev === 'listed' ? 'Listed' : kev === 'not_listed' ? 'Not listed' : 'Unknown') +
          '</span></td>' +
          '<td data-label="Priority">' +
          '<span class="priority-badge ' +
          priorityClass(f.priority) +
          '">' +
          escapeHtml(String(f.priority)) +
          '</span></td>' +
          '<td data-label="Status">' +
          '<span class="status-badge">' +
          escapeHtml(String(f.status).replace(/_/g, ' ')) +
          '</span></td>' +
          '<td data-label="Updated">' +
          formatDate(f.updated_at) +
          '</td>';
        body.appendChild(tr);
      });
    } catch (err) {
      console.error('findings load failed', err);
      els.findingsEmpty.querySelector('p').textContent = 'Failed to load findings.';
      els.findingsBody.hidden = true;
      els.findingsEmpty.classList.remove('hidden');
    }
  }

  async function loadAssets() {
    try {
      const assets = await api('/api/assets');
      const body = els.assetsBody;
      const empty = els.assetsEmpty;
      body.innerHTML = '';
      if (!assets || assets.length === 0) {
        body.hidden = true;
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      body.hidden = false;
      assets.forEach((a) => {
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td data-label="Hostname">' +
          escapeHtml(a.hostname) +
          '</td>' +
          '<td data-label="Organization">' +
          escapeHtml(a.organization) +
          '</td>' +
          '<td data-label="Criticality">' +
          '<span class="status-badge">' +
          escapeHtml(String(a.criticality).replace(/_/g, ' ')) +
          '</span></td>' +
          '<td data-label="Internet exposed">' +
          (a.internet_exposed ? 'Yes' : 'No') +
          '</td>' +
          '<td data-label="Components">' +
          (Array.isArray(a.components) ? a.components.length : 0) +
          '</td>';
        body.appendChild(tr);
      });
    } catch (err) {
      console.error('assets load failed', err);
      els.assetsEmpty.querySelector('p').textContent = 'Failed to load assets.';
      els.assetsBody.hidden = true;
      els.assetsEmpty.classList.remove('hidden');
    }
  }

  function caseStatusOptions(current) {
    const allowed = ['open', 'in_progress', 'resolved', 'accepted_risk'];
    return allowed
      .map(
        (s) =>
          `<option value="${escapeHtml(s)}" ${s === current ? 'selected' : ''}>${escapeHtml(s.replace(/_/g, ' '))}</option>`
      )
      .join('');
  }

  async function loadCases() {
    try {
      const cases = await api('/api/cases');
      const body = els.casesBody;
      const empty = els.casesEmpty;
      body.innerHTML = '';
      if (!cases || cases.length === 0) {
        body.hidden = true;
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      body.hidden = false;
      cases.forEach((c) => {
        const tr = document.createElement('tr');
        const sel = document.createElement('select');
        sel.className = 'status-badge';
        sel.setAttribute('aria-label', `Status for ${c.id}`);
        sel.style.padding = '0.14rem 0.5rem';
        sel.style.fontSize = '0.75rem';
        sel.style.border = '1px solid var(--border)';
        sel.style.borderRadius = '999px';
        sel.style.background = 'var(--surface)';
        sel.style.color = 'var(--text-muted)';
        sel.innerHTML = caseStatusOptions(c.status);
        sel.addEventListener('change', async () => {
          const assigneeSel = tr.querySelector('.case-assignee');
          try {
            const saved = await api(`/api/cases/${encodeURIComponent(c.id)}`, {
              method: 'PATCH',
              body: JSON.stringify({ status: sel.value, assignee: assigneeSel ? assigneeSel.value.trim() : '' }),
            });
            c.status = saved.status;
            tr.querySelector('[data-label="Updated"]').textContent = formatDate(saved.updated_at);
          } catch (err) {
            alert('Failed to update case status.');
            sel.value = c.status;
          }
        });

        const assigneeSel = document.createElement('input');
        assigneeSel.className = 'case-assignee';
        assigneeSel.type = 'text';
        assigneeSel.setAttribute('aria-label', `Assignee for ${c.id}`);
        assigneeSel.value = c.assignee || '';
        assigneeSel.placeholder = 'Assignee';
        assigneeSel.style.padding = '0.14rem 0.45rem';
        assigneeSel.style.fontSize = '0.75rem';
        assigneeSel.style.border = '1px solid var(--border)';
        assigneeSel.style.borderRadius = '6px';
        assigneeSel.style.background = 'var(--surface)';
        assigneeSel.style.maxWidth = '130px';
        assigneeSel.addEventListener('change', async () => {
          try {
            const saved = await api(`/api/cases/${encodeURIComponent(c.id)}`, {
              method: 'PATCH',
              body: JSON.stringify({ status: sel.value, assignee: assigneeSel.value.trim() }),
            });
            c.assignee = saved.assignee;
            tr.querySelector('[data-label="Updated"]').textContent = formatDate(saved.updated_at);
          } catch (err) {
            alert('Failed to update assignee.');
            assigneeSel.value = c.assignee || '';
          }
        });

        tr.innerHTML =
          '<td class="finding-id" data-label="Case ID">' +
          escapeHtml(c.id) +
          '</td>' +
          '<td data-label="Finding / CVE">' +
          escapeHtml(c.cve_id || '—') +
          '</td>' +
          '<td data-label="Package">' +
          escapeHtml(c.package_name || '—') +
          '</td>' +
          '<td data-label="Priority">' +
          '<span class="priority-badge ' +
          priorityClass(c.priority) +
          '">' +
          escapeHtml(String(c.priority)) +
          '</span></td>' +
          '<td data-label="Status"></td>' +
          '<td data-label="Assignee"></td>' +
          '<td data-label="Updated">' +
          formatDate(c.updated_at) +
          '</td>';
        tr.querySelector('[data-label="Status"]').appendChild(sel);
        tr.querySelector('[data-label="Assignee"]').appendChild(assigneeSel);
        body.appendChild(tr);
      });
    } catch (err) {
      console.error('cases load failed', err);
      els.casesEmpty.querySelector('p').textContent = 'Failed to load cases.';
      els.casesBody.hidden = true;
      els.casesEmpty.classList.remove('hidden');
    }
  }

  async function loadIntegrations() {
    try {
      const feeds = await api('/api/intelligence/status');
      const body = els.intelBody;
      const empty = els.intelEmpty;
      body.innerHTML = '';
      if (!feeds || feeds.length === 0) {
        body.hidden = true;
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');
      body.hidden = false;
      feeds.forEach((f) => {
        const tr = document.createElement('tr');
        const statusKind = f.status === 'available' ? 'ok' : f.status === 'degraded' ? 'warn' : 'neutral';
        tr.innerHTML =
          '<td data-label="Source">' +
          escapeHtml(f.source) +
          '</td>' +
          '<td data-label="Status">' +
          '<span class="status-badge">' +
          escapeHtml(String(f.status)) +
          '</span></td>' +
          '<td data-label="Mode">' +
          escapeHtml(String(f.mode)) +
          '</td>' +
          '<td data-label="Checked at">' +
          formatDate(f.checked_at) +
          '</td>' +
          '<td data-label="Last success">' +
          formatDate(f.last_success_at) +
          '</td>' +
          '<td data-label="Version">' +
          escapeHtml(f.source_version || '—') +
          '</td>' +
          '<td data-label="Last error">' +
          escapeHtml(f.last_error || '—') +
          '</td>';
        body.appendChild(tr);
      });
    } catch (err) {
      console.error('intelligence status load failed', err);
      els.intelEmpty.querySelector('p').textContent = 'Failed to load source freshness.';
      els.intelBody.hidden = true;
      els.intelEmpty.classList.remove('hidden');
    }
  }

  function showView(name, focusTab = false) {
    STATE.view = name;
    els.tabs.forEach((tab) => {
      const active = tab.dataset.tab === name;
      tab.setAttribute('aria-selected', String(active));
      tab.tabIndex = active ? 0 : -1;
      if (active && focusTab) tab.focus();
    });
    Object.entries(els.panels).forEach(([key, panel]) => {
      panel.hidden = key !== name;
    });
    if (name === 'overview') loadOverview();
    else if (name === 'findings') loadFindings();
    else if (name === 'assets') loadAssets();
    else if (name === 'cases') loadCases();
    else if (name === 'integrations') loadIntegrations();
  }

  async function runDetection(btn = els.btnRunDetection) {
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Running detection…';
    try {
      await api('/api/detection/run', { method: 'POST', body: JSON.stringify({ mode: 'demo' }) });
      showView(STATE.view);
    } catch (err) {
      alert('Detection run failed: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  async function refreshIntelligence(btn = els.btnRefreshIntel) {
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Refreshing…';
    try {
      await api('/api/intelligence/refresh', { method: 'POST' });
      loadIntegrations();
      loadOverview();
    } catch (err) {
      alert('Intelligence refresh failed: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  async function resetDemo() {
    if (!confirm('Reset all demo data? This clears findings, cases, assets, and source state.')) return;
    const btn = els.btnResetDemo;
    const prev = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Resetting…';
    try {
      await api('/api/demo/reset', { method: 'POST' });
      showView(STATE.view);
    } catch (err) {
      alert('Demo reset failed: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  }

  function init() {
    els.tabs.forEach((tab) => {
      tab.addEventListener('click', () => showView(tab.dataset.tab, true));
      tab.addEventListener('keydown', (event) => {
        const current = Array.from(els.tabs).indexOf(tab);
        let next = null;
        if (event.key === 'ArrowRight') next = (current + 1) % els.tabs.length;
        if (event.key === 'ArrowLeft') next = (current - 1 + els.tabs.length) % els.tabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = els.tabs.length - 1;
        if (next !== null) {
          event.preventDefault();
          showView(els.tabs[next].dataset.tab, true);
        }
      });
    });
    els.btnRunDetection.addEventListener('click', () => runDetection(els.btnRunDetection));
    els.btnRunDetectionFindings.addEventListener('click', () => runDetection(els.btnRunDetectionFindings));
    els.btnResetDemo.addEventListener('click', resetDemo);
    els.btnRefreshIntel.addEventListener('click', () => refreshIntelligence(els.btnRefreshIntel));
    els.btnRefreshIntelEmpty.addEventListener('click', () => refreshIntelligence(els.btnRefreshIntelEmpty));
    els.btnConnectModel.addEventListener('click', () => {
      alert('Local model connector placeholder — not connected. No backend integration is wired in this demo.');
    });

    loadHealth();
    showView('overview');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

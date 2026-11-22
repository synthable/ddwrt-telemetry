(() => {
  const state = {
    range: "all",
    client: "",
    status: "all",
    qtype: "all",
    q: "",
    hidePtr: false,
    limit: 120,
    offset: 0,
    domainTab: "domains",
    autoTimer: null,
    lastData: null,
  };

  const $ = (id) => document.getElementById(id);

  function fmtNum(n) {
    return Number(n || 0).toLocaleString();
  }

  function fmtPct(part, total) {
    if (!total) return "0.0%";
    return `${((part / total) * 100).toFixed(1)}%`;
  }

  function fmtClock(ts) {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function fmtRelative(ts) {
    if (!ts) return "idle";
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function buildParams(includePaging = true) {
    const p = new URLSearchParams();
    p.set("range", state.range);
    if (state.client) p.set("client", state.client);
    if (state.status !== "all") p.set("status", state.status);
    if (state.qtype !== "all") p.set("qtype", state.qtype);
    if (state.q) p.set("q", state.q);
    if (state.hidePtr) p.set("hide_ptr", "1");
    if (includePaging) {
      p.set("limit", String(state.limit));
      p.set("offset", String(state.offset));
    }
    return p;
  }

  async function loadData() {
    try {
      const res = await fetch(`/api/data?${buildParams(true).toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      state.lastData = data;
      renderAll(data);
    } catch (err) {
      showError(`Failed to load dashboard data: ${err.message}`);
    }
  }

  async function syncRouter() {
    const btn = $("syncBtn");
    const label = $("syncBtnLabel");
    const icon = btn.querySelector(".sync-icon");
    const led = $("syncLed");

    btn.disabled = true;
    label.textContent = "Syncing…";
    icon.classList.add("spinning");
    led.className = "led syncing";
    hideError();

    try {
      const res = await fetch("/api/sync", { method: "POST" });
      const body = await res.json();
      if (!res.ok || body.status === "error") {
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      led.className = "led";
      await loadData();
    } catch (err) {
      led.className = "led error";
      showError(`Router sync failed: ${err.message}`);
    } finally {
      btn.disabled = false;
      label.textContent = "Sync Router";
      icon.classList.remove("spinning");
    }
  }

  function showError(msg) {
    const el = $("errorBanner");
    el.textContent = msg;
    el.classList.remove("hidden");
  }

  function hideError() {
    $("errorBanner").classList.add("hidden");
  }

  function renderAll(data) {
    renderMeta(data.meta);
    renderFilters();
    renderKpis(data);
    renderTimeline(data.timeline);
    renderDevices(data.devices);
    renderLeaderboard(data);
    renderQtypes(data.qtypes);
    renderTable(data.queries);
  }

  function renderMeta(meta) {
    const routerName = meta.router_name || "DD-WRT Router";
    $("routerNameTitle").textContent = routerName;
    document.title = `${routerName} · DNS Telemetry`;
    $("metaRouter").textContent = meta.router_host || "192.168.1.1:8789";
    const mode = meta.transport || (meta.stream_connected ? "SSE Live" : "HTTP");
    $("metaSync").textContent = meta.last_sync_ts
      ? `${mode} · ${fmtClock(meta.last_sync_ts)}`
      : mode;
    $("metaSources").textContent = `${meta.sources.length} log file${meta.sources.length === 1 ? "" : "s"} (${fmtNum(meta.total_stored)} total)`;
    if (meta.last_sync_error) {
      showError(meta.last_sync_error);
    } else {
      hideError();
    }
  }

  function renderFilters() {
    const chips = [];
    if (state.client) {
      const dev = state.lastData?.devices?.find((d) => d.ip === state.client);
      const label = dev ? `${dev.name} (${dev.ip})` : state.client;
      chips.push({ key: "client", text: `device: ${label}` });
    }
    if (state.status !== "all") {
      chips.push({ key: "status", text: `status: ${state.status}` });
    }
    if (state.qtype !== "all") {
      chips.push({ key: "qtype", text: `type: ${state.qtype}` });
    }
    if (state.q) {
      chips.push({ key: "q", text: `search: "${state.q}"` });
    }

    const bar = $("activeFilterBar");
    const box = $("activeFilterChips");
    if (!chips.length) {
      bar.classList.add("hidden");
      box.innerHTML = "";
      return;
    }

    bar.classList.remove("hidden");
    box.innerHTML = chips
      .map(
        (c) =>
          `<span class="chip">${escHtml(c.text)}<button data-clear="${c.key}" aria-label="Remove filter">×</button></span>`
      )
      .join("");
  }

  function renderKpis(data) {
    const s = data.summary;
    $("kpiTotal").textContent = fmtNum(s.total);
    $("kpiQpm").textContent = `${s.qpm} /m`;

    if (data.meta.earliest_ts && data.meta.latest_ts) {
      const from = new Date(data.meta.earliest_ts * 1000).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
      const to = fmtClock(data.meta.latest_ts);
      $("kpiSpan").textContent = `${from} → ${to}`;
    } else {
      $("kpiSpan").textContent = "Awaiting log data";
    }

    $("kpiBlocked").textContent = fmtNum(s.blocked);
    $("kpiBlockedPct").textContent = fmtPct(s.blocked, s.total);

    $("kpiCachedPct").textContent = fmtPct(s.cached, s.total);
    $("kpiCachedCount").textContent = `${fmtNum(s.cached)} hits`;

    $("kpiClients").textContent = fmtNum(s.active_clients);
    $("kpiNxCount").textContent = `${fmtNum(s.nxdomain)} NX`;

    const topDev = data.devices.find((d) => d.total > 0);
    $("kpiTopClient").textContent = topDev
      ? `Top talker: ${topDev.name} (${fmtNum(topDev.total)})`
      : "Top talker: —";
  }

  function renderTimeline(buckets) {
    const svg = $("timelineSvg");
    const axis = $("timelineAxis");
    const empty = $("timelineEmpty");
    const tooltip = $("chartTooltip");
    tooltip.classList.add("hidden");

    if (!buckets || !buckets.length) {
      svg.innerHTML = "";
      axis.innerHTML = "";
      svg.setAttribute("aria-label", "DNS query activity timeline: no queries in selected window");
      $("timelineSummary").textContent = "No DNS queries in selected time window.";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    const sumAllowed = buckets.reduce((a, b) => a + b.allowed, 0);
    const sumCached = buckets.reduce((a, b) => a + b.cached, 0);
    const sumBlocked = buckets.reduce((a, b) => a + b.blocked, 0);
    const sumNx = buckets.reduce((a, b) => a + b.nxdomain, 0);
    const sumAll = sumAllowed + sumCached + sumBlocked + sumNx;
    const summaryText = `Stacked DNS query timeline from ${buckets[0].label} to ${buckets[buckets.length - 1].label}: ${fmtNum(sumAll)} total queries (${fmtNum(sumAllowed)} allowed, ${fmtNum(sumCached)} cached, ${fmtNum(sumBlocked)} blocked, ${fmtNum(sumNx)} NXDOMAIN).`;
    svg.setAttribute("aria-label", summaryText);
    $("timelineSummary").textContent = summaryText;

    const W = 800;
    const H = 160;
    const maxVal = Math.max(
      1,
      ...buckets.map((b) => b.allowed + b.cached + b.blocked + b.nxdomain)
    );
    const slotW = W / buckets.length;
    const barW = Math.max(3, Math.min(24, slotW * 0.72));

    const cs = getComputedStyle(document.documentElement);
    const cAllowed = cs.getPropertyValue("--allowed").trim() || "#38bdf8";
    const cCached = cs.getPropertyValue("--cached").trim() || "#34d399";
    const cNx = cs.getPropertyValue("--nxdomain").trim() || "#fbbf24";
    const cBlocked = cs.getPropertyValue("--blocked").trim() || "#f43f5e";
    const cGrid = cs.getPropertyValue("--chart-grid").trim() || "rgba(255,255,255,0.05)";
    const cInk = cs.getPropertyValue("--ink").trim() || "#f8fafc";

    let html = "";
    // Horizontal reference gridlines
    for (let i = 1; i <= 3; i++) {
      const y = (H / 4) * i;
      html += `<line x1="0" y1="${y}" x2="${W}" y2="${y}" stroke="${cGrid}" stroke-width="1" />`;
    }

    buckets.forEach((b, idx) => {
      const xSlot = idx * slotW;
      const xBar = xSlot + (slotW - barW) / 2;
      let yCursor = H;

      const segments = [
        { val: b.allowed, color: cAllowed },
        { val: b.cached, color: cCached },
        { val: b.nxdomain, color: cNx },
        { val: b.blocked, color: cBlocked },
      ];

      let rects = `<rect class="bar-hit" x="${xSlot}" y="0" width="${slotW}" height="${H}" fill="transparent" />`;
      for (const seg of segments) {
        if (!seg.val) continue;
        const h = Math.max(1.5, (seg.val / maxVal) * (H - 8));
        yCursor -= h;
        rects += `<rect class="bar-seg" x="${xBar.toFixed(1)}" y="${yCursor.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" rx="1.5" fill="${seg.color}" />`;
      }
      html += `<g class="chart-bar-group" data-idx="${idx}">${rects}</g>`;
    });

    svg.innerHTML = html;

    // Sparse X-axis labels
    const labelCount = Math.min(6, buckets.length);
    const axisLabels = [];
    for (let i = 0; i < labelCount; i++) {
      const idx =
        labelCount === 1
          ? 0
          : Math.round((i / (labelCount - 1)) * (buckets.length - 1));
      axisLabels.push(`<span>${escHtml(buckets[idx].label)}</span>`);
    }
    axis.innerHTML = axisLabels.join("");

    // Hover tooltip
    svg.querySelectorAll(".chart-bar-group").forEach((g) => {
      g.addEventListener("mouseenter", (e) => {
        const b = buckets[Number(g.dataset.idx)];
        const total = b.allowed + b.cached + b.blocked + b.nxdomain;
        tooltip.innerHTML = `
          <div style="color:${cInk};font-weight:600;margin-bottom:4px">${escHtml(b.label)} · ${fmtNum(total)} queries</div>
          <div style="color:${cAllowed}">Allowed:  ${fmtNum(b.allowed)}</div>
          <div style="color:${cCached}">Cached:   ${fmtNum(b.cached)}</div>
          <div style="color:${cBlocked}">Blocked:  ${fmtNum(b.blocked)}</div>
          <div style="color:${cNx}">NXDOMAIN: ${fmtNum(b.nxdomain)}</div>
        `;
        tooltip.classList.remove("hidden");
        positionTooltip(e);
      });
      g.addEventListener("mousemove", positionTooltip);
      g.addEventListener("mouseleave", () => tooltip.classList.add("hidden"));
    });
  }

  function positionTooltip(e) {
    const wrap = $("timelineWrap").getBoundingClientRect();
    const tt = $("chartTooltip");
    const left = Math.min(wrap.width - tt.offsetWidth - 10, Math.max(8, e.clientX - wrap.left + 12));
    const top = Math.max(8, e.clientY - wrap.top - 10);
    tt.style.left = `${left}px`;
    tt.style.top = `${top}px`;
  }

  function renderDevices(devices) {
    $("deviceTotalBadge").textContent = `${devices.length}`;
    const list = $("deviceList");
    if (!devices.length) {
      list.innerHTML = `<div class="muted" style="padding:12px 0">No LAN devices discovered yet.</div>`;
      return;
    }

    list.innerHTML = devices
      .map((d) => {
        const selected = state.client === d.ip;
        const idle = d.total === 0;
        const tot = Math.max(1, d.total);
        const pAllowed = (d.allowed / tot) * 100;
        const pCached = (d.cached / tot) * 100;
        const pNx = (d.nxdomain / tot) * 100;
        const pBlocked = (d.blocked / tot) * 100;

        const srBreakdown = d.total
          ? `Resolution breakdown: ${pAllowed.toFixed(0)}% allowed, ${pCached.toFixed(0)}% cached, ${pBlocked.toFixed(0)}% blocked, ${pNx.toFixed(0)}% NXDOMAIN.`
          : "No queries in selected window.";

        return `
          <button type="button" class="device-card ${selected ? "selected" : ""} ${idle ? "idle" : ""}" data-ip="${escHtml(d.ip)}" aria-pressed="${selected ? "true" : "false"}">
            <div class="device-top">
              <div>
                <span class="device-name">${escHtml(d.name)}</span>
                <span class="device-ip mono">${escHtml(d.ip)}</span>
              </div>
              <span class="device-total mono">${fmtNum(d.total)}</span>
            </div>
            <div class="device-bar" aria-hidden="true">
              <span style="width:${pAllowed}%;background:var(--allowed)"></span>
              <span style="width:${pCached}%;background:var(--cached)"></span>
              <span style="width:${pNx}%;background:var(--nxdomain)"></span>
              <span style="width:${pBlocked}%;background:var(--blocked)"></span>
            </div>
            <span class="sr-only">${escHtml(srBreakdown)}</span>
            <div class="device-meta mono">
              <span>${d.blocked ? `${fmtNum(d.blocked)} blk (${fmtPct(d.blocked, d.total)})` : "0 blocked"}</span>
              <span>${fmtRelative(d.last_seen)}</span>
            </div>
          </button>
        `;
      })
      .join("");
  }

  function renderLeaderboard(data) {
    const map = {
      domains: { rows: data.top_domains, color: "var(--allowed)" },
      blocked: { rows: data.top_blocked, color: "var(--blocked)" },
      nxdomain: { rows: data.top_nxdomain, color: "var(--nxdomain)" },
    };
    const cfg = map[state.domainTab] || map.domains;
    const box = $("domainLeaderboard");

    if (!cfg.rows || !cfg.rows.length) {
      box.innerHTML = `<div class="muted" style="padding:16px 4px;font-size:12px">No entries for this view.</div>`;
      return;
    }
    const maxC = Math.max(1, cfg.rows[0].count);
    box.innerHTML = cfg.rows
      .map((r) => {
        const pct = (r.count / maxC) * 100;
        return `
          <button class="bar-row" data-domain="${escHtml(r.domain)}" title="Filter queries by ${escHtml(r.domain)}">
            <span class="bar-fill" style="width:${pct}%;background:${cfg.color}"></span>
            <span class="bar-domain mono">${escHtml(r.domain)}</span>
            <span class="bar-count mono">${fmtNum(r.count)}</span>
          </button>
        `;
      })
      .join("");
  }

  function renderQtypes(qtypes) {
    const box = $("qtypeGrid");
    if (!qtypes || !qtypes.length) {
      box.innerHTML = `<span class="muted">—</span>`;
      return;
    }
    box.innerHTML = qtypes
      .map(
        (qt) => `
        <button type="button" class="qtype-pill ${state.qtype === qt.type ? "active" : ""}" data-qtype="${escHtml(qt.type)}" aria-pressed="${state.qtype === qt.type ? "true" : "false"}">
          <span>${escHtml(qt.type)}</span>
          <span class="muted">${fmtNum(qt.count)}</span>
        </button>`
      )
      .join("");
  }

  function renderTable(qData) {
    const tbody = $("queryTableBody");
    const empty = $("tableEmpty");
    const rows = qData.rows || [];

    const start = qData.total ? qData.offset + 1 : 0;
    const end = qData.offset + rows.length;
    $("streamCountLabel").textContent = `Showing ${fmtNum(start)}–${fmtNum(end)} of ${fmtNum(qData.total)}`;
    $("pageStatus").textContent = `Page ${Math.floor(qData.offset / qData.limit) + 1} / ${Math.max(1, Math.ceil(qData.total / qData.limit))}`;
    $("prevPageBtn").disabled = qData.offset <= 0;
    $("nextPageBtn").disabled = end >= qData.total;

    if (!rows.length) {
      tbody.innerHTML = "";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    tbody.innerHTML = rows
      .map((r) => {
        const ans = r.answers.length
          ? r.answers.join(", ")
          : r.upstream || "—";
        return `
          <tr class="${r.status === "blocked" ? "row-blocked" : ""}">
            <th scope="row" class="mono muted row-time" title="${escHtml(r.ts_iso)}">${fmtClock(r.ts)}</th>
            <td>
              <button type="button" class="cell-link" data-filter-ip="${escHtml(r.client_ip)}" title="Filter by ${escHtml(r.client_name)} (${escHtml(r.client_ip)})">
                <strong>${escHtml(r.client_name)}</strong>
              </button>
            </td>
            <td><span class="type-tag">${escHtml(r.qtype)}</span></td>
            <td class="domain-cell mono" title="${escHtml(r.domain)}">
              <button type="button" class="cell-link" data-filter-domain="${escHtml(r.domain)}">${escHtml(r.domain)}</button>
            </td>
            <td><span class="status-tag st-${escHtml(r.status)}" aria-label="Status: ${escHtml(r.status)}">${escHtml(r.status)}</span></td>
            <td class="answer-cell mono" title="${escHtml(ans)}">${escHtml(ans)}</td>
          </tr>
        `;
      })
      .join("");
  }

  function enableArrowNav(container) {
    container.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      const items = Array.from(container.querySelectorAll("button"));
      const idx = items.indexOf(document.activeElement);
      if (idx === -1) return;
      e.preventDefault();
      const next = items[(idx + (e.key === "ArrowRight" ? 1 : -1) + items.length) % items.length];
      next.focus();
      next.click();
    });
  }

  function setStatus(status) {
    state.status = status;
    state.offset = 0;
    document.querySelectorAll("#statusPills button").forEach((b) => {
      const on = b.dataset.status === status;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    document.querySelectorAll("[data-status-click]").forEach((card) => {
      card.setAttribute("aria-pressed", card.dataset.statusClick === status ? "true" : "false");
    });
    loadData();
  }

  // Event Wiring
  enableArrowNav($("rangeSelector"));
  enableArrowNav($("statusPills"));
  enableArrowNav($("domainTabs"));

  $("rangeSelector").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-range]");
    if (!btn) return;
    state.range = btn.dataset.range;
    state.offset = 0;
    $("rangeSelector").querySelectorAll("button").forEach((b) => {
      const on = b === btn;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    loadData();
  });

  $("hidePtrToggle").addEventListener("change", (e) => {
    state.hidePtr = e.target.checked;
    state.offset = 0;
    loadData();
  });

  $("autoRefreshSelect").addEventListener("change", (e) => {
    const secs = Number(e.target.value);
    if (state.autoTimer) clearInterval(state.autoTimer);
    state.autoTimer = secs > 0 ? setInterval(loadData, secs * 1000) : null;
  });

  $("syncBtn").addEventListener("click", syncRouter);

  $("exportBtn").addEventListener("click", () => {
    window.location.href = `/api/export.csv?${buildParams(false).toString()}`;
  });

  $("statusPills").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-status]");
    if (!btn) return;
    setStatus(btn.dataset.status);
  });

  document.querySelectorAll("[data-status-click]").forEach((card) => {
    const toggle = () => {
      const target = card.dataset.statusClick;
      setStatus(state.status === target ? "all" : target);
    };
    card.addEventListener("click", toggle);
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
    });
  });

  $("deviceList").addEventListener("click", (e) => {
    const card = e.target.closest(".device-card");
    if (!card) return;
    const ip = card.dataset.ip;
    state.client = state.client === ip ? "" : ip;
    state.offset = 0;
    loadData();
  });

  $("domainTabs").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-tab]");
    if (!btn) return;
    state.domainTab = btn.dataset.tab;
    $("domainTabs").querySelectorAll("button").forEach((b) => {
      const on = b === btn;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    if (state.lastData) renderLeaderboard(state.lastData);
  });

  $("domainLeaderboard").addEventListener("click", (e) => {
    const row = e.target.closest(".bar-row");
    if (!row) return;
    state.q = row.dataset.domain;
    $("searchInput").value = state.q;
    state.offset = 0;
    loadData();
  });

  $("qtypeGrid").addEventListener("click", (e) => {
    const pill = e.target.closest(".qtype-pill");
    if (!pill) return;
    const qt = pill.dataset.qtype;
    state.qtype = state.qtype === qt ? "all" : qt;
    state.offset = 0;
    loadData();
  });

  $("queryTableBody").addEventListener("click", (e) => {
    const ipBtn = e.target.closest("[data-filter-ip]");
    if (ipBtn) {
      state.client = ipBtn.dataset.filterIp;
      state.offset = 0;
      loadData();
      return;
    }
    const domBtn = e.target.closest("[data-filter-domain]");
    if (domBtn) {
      state.q = domBtn.dataset.filterDomain;
      $("searchInput").value = state.q;
      state.offset = 0;
      loadData();
    }
  });

  let searchDebounce = null;
  $("searchInput").addEventListener("input", (e) => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => {
      state.q = e.target.value.trim();
      state.offset = 0;
      loadData();
    }, 180);
  });

  $("activeFilterChips").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-clear]");
    if (!btn) return;
    const k = btn.dataset.clear;
    if (k === "client") state.client = "";
    if (k === "status") setStatus("all");
    if (k === "qtype") state.qtype = "all";
    if (k === "q") {
      state.q = "";
      $("searchInput").value = "";
    }
    state.offset = 0;
    loadData();
  });

  $("clearFiltersBtn").addEventListener("click", () => {
    state.client = "";
    state.status = "all";
    state.qtype = "all";
    state.q = "";
    state.offset = 0;
    $("searchInput").value = "";
    document.querySelectorAll("#statusPills button").forEach((b) => {
      b.classList.toggle("active", b.dataset.status === "all");
    });
    loadData();
  });

  $("prevPageBtn").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    loadData();
  });

  $("nextPageBtn").addEventListener("click", () => {
    state.offset += state.limit;
    loadData();
  });

  function syncThemeButton() {
    const isLight = document.documentElement.dataset.theme === "light";
    $("themeToggleIcon").textContent = isLight ? "☾" : "☀";
    $("themeToggleLabel").textContent = isLight ? "Dark" : "Light";
    $("themeToggleBtn").setAttribute("aria-pressed", isLight ? "true" : "false");
  }

  $("themeToggleBtn").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("ddwrt-theme", next); } catch (_) {}
    syncThemeButton();
    if (state.lastData) renderTimeline(state.lastData.timeline);
  });

  syncThemeButton();
  // Initial load + start live UI refresh (reads live SSE-fed local memory)
  loadData();
  state.autoTimer = setInterval(loadData, 3000);
})();

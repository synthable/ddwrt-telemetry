(() => {
  const state = {
    verdict: "blocked",
    range: "all",
    src: "",
    category: "all",
    proto: "all",
    port: "",
    q: "",
    hideStale: false,
    limit: 120,
    offset: 0,
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
    return new Date(ts * 1000).toLocaleTimeString([], {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function fmtRelative(ts) {
    if (!ts) return "—";
    const diff = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function buildParams(includePaging = true) {
    const p = new URLSearchParams();
    p.set("verdict", state.verdict);
    p.set("range", state.range);
    if (state.src) p.set("src", state.src);
    if (state.category !== "all") p.set("category", state.category);
    if (state.proto !== "all") p.set("proto", state.proto);
    if (state.port) p.set("port", state.port);
    if (state.q) p.set("q", state.q);
    if (state.hideStale) p.set("hide_stale", "1");
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
      showError(`Failed to load firewall data: ${err.message}`);
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
    led.className = "pulse-dot syncing";
    hideError();

    try {
      const res = await fetch("/api/sync", { method: "POST" });
      const body = await res.json();
      if (!res.ok || body.status === "error") {
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      led.className = "pulse-dot";
      await loadData();
    } catch (err) {
      led.className = "pulse-dot error";
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
    renderKernelCounters(data.kernel_counters);
    renderFilters();
    renderKpis(data);
    renderTimeline(data.timeline);
    renderSources(data.top_sources);
    renderPorts(data.top_ports);
    renderProtos(data.protos);
    renderTable(data.events);
  }

  const CATEGORY_TOOLTIPS = {
    probe: "Inferred probe: well-known/privileged destination port, TCP SYN, non-TCP/UDP protocol, or portscan/bruteforce rule",
    stale: "Inferred stale return: late UDP from port 443/80/53 or TCP RST/FIN/ACK teardown to an ephemeral port (view-filterable; raw event preserved)",
    ping: "ICMP packet dropped by firewall",
    other: "Unsolicited dropped packet not matching probe, ping, or stale-return heuristics",
    outbound: "Accepted connection egressing the configured WAN interface",
    local: "Accepted connection staying on LAN or terminating at the router",
  };

  function renderMeta(meta) {
    const routerName = meta.router_name || "DD-WRT Router";
    $("routerNameTitle").textContent = routerName;
    document.title = `${routerName} · Perimeter Firewall`;
    $("metaRouter").textContent = meta.router_host || "192.168.1.1:8789";
    const scopeEl = $("metaScope");
    if (scopeEl) {
      const ipScope = meta.ip_scope || "IPv4 iptables";
      const wanIface = meta.wan_iface || "wan";
      scopeEl.textContent = `${ipScope} · WAN: ${wanIface}`;
    }
    const mode = meta.transport || (meta.stream_connected ? "SSE Live" : "HTTP");
    $("metaSync").textContent = meta.last_sync_ts ? `${mode} · ${fmtClock(meta.last_sync_ts)}` : mode;
    $("metaSources").textContent = `${meta.sources.length} sources · ${fmtNum(meta.blocked_stored)} blocked / ${fmtNum(meta.allowed_stored)} allowed`;
    if (meta.last_sync_error) showError(meta.last_sync_error);
    else hideError();
  }

  function renderKernelCounters(items) {
    const box = $("kernelCounters");
    if (!items || !items.length) {
      box.innerHTML = `<span class="muted mono">No kernel counter snapshot yet</span>`;
      return;
    }
    box.innerHTML = items
      .map((c) => {
        const available = c.available !== false && c.pkts !== null && c.pkts !== undefined;
        const title = available
          ? `${escHtml(c.bytes ?? "0")} bytes since last firewall reload`
          : "Rule or WAN interface not matched in current iptables snapshot (unavailable, not measured zero)";
        const valHtml = available
          ? `<span class="k-val">${fmtNum(c.pkts)}</span>`
          : `<span class="k-val muted">N/A</span>`;
        return `
        <span class="kernel-pill mono" title="${title}">
          <span class="k-name">${escHtml(c.label)}</span>
          ${valHtml}
        </span>`;
      })
      .join("");
  }

  function renderFilters() {
    const chips = [];
    if (state.hideStale) chips.push({ key: "hideStale", text: "view: hiding inferred stale return (raw events preserved)" });
    if (state.src) chips.push({ key: "src", text: `src: ${state.src}` });
    if (state.category !== "all") chips.push({ key: "category", text: `category: ${state.category}` });
    if (state.proto !== "all") chips.push({ key: "proto", text: `proto: ${state.proto}` });
    if (state.port) chips.push({ key: "port", text: `target: ${state.port}` });
    if (state.q) chips.push({ key: "q", text: `search: "${state.q}"` });

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
    $("kpiEpm").textContent = `${s.epm} /m`;
    if (data.meta.earliest_ts && data.meta.latest_ts) {
      const from = new Date(data.meta.earliest_ts * 1000).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
      $("kpiSpan").textContent = `${from} → ${fmtClock(data.meta.latest_ts)}`;
    } else {
      $("kpiSpan").textContent = "Awaiting firewall log data";
    }

    $("kpiProbes").textContent = fmtNum(s.probe);
    $("kpiProbePct").textContent = fmtPct(s.probe, s.total);
    $("kpiPingSub").textContent = `${fmtNum(s.ping)} ICMP pings · ${fmtNum(s.other)} other`;

    $("kpiSources").textContent = fmtNum(s.unique_sources);
    $("kpiStaleBadge").textContent = `${fmtNum(s.stale)} stale`;
    const topSrc = data.top_sources[0];
    $("kpiTopSource").textContent = topSrc ? `Top: ${topSrc.ip} (${fmtNum(topSrc.count)})` : "Top: —";

    $("kpiTargets").textContent = fmtNum(s.unique_targets);
    const topPort = data.top_ports[0];
    $("kpiTopPortBadge").textContent = topPort ? `${topPort.port}` : "—";
    $("kpiTopPortSub").textContent = topPort
      ? `Most hit: ${topPort.service} (${fmtNum(topPort.count)})`
      : "Distinct destination ports / protos";
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
      svg.setAttribute("aria-label", "Perimeter firewall timeline: no events in selected window");
      $("timelineSummary").textContent = "No firewall events in selected time window.";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    const sumProbe = buckets.reduce((a, b) => a + b.probe, 0);
    const sumPing = buckets.reduce((a, b) => a + b.ping, 0);
    const sumOther = buckets.reduce((a, b) => a + b.other, 0);
    const sumStale = buckets.reduce((a, b) => a + b.stale, 0);
    const sumOut = buckets.reduce((a, b) => a + (b.outbound || 0), 0);
    const sumLoc = buckets.reduce((a, b) => a + (b.local || 0), 0);
    const sumAll = sumProbe + sumPing + sumOther + sumStale + sumOut + sumLoc;
    const summaryText = `Firewall timeline from ${buckets[0].label} to ${buckets[buckets.length - 1].label}: ${fmtNum(sumAll)} events (${fmtNum(sumProbe)} probes, ${fmtNum(sumPing)} pings, ${fmtNum(sumOther)} other, ${fmtNum(sumStale)} stale, ${fmtNum(sumOut)} outbound, ${fmtNum(sumLoc)} local).`;
    svg.setAttribute("aria-label", summaryText);
    $("timelineSummary").textContent = summaryText;

    const W = 800;
    const H = 158;
    const maxVal = Math.max(
      1,
      ...buckets.map((b) => b.probe + b.ping + b.other + b.stale + (b.outbound || 0) + (b.local || 0))
    );
    const slotW = W / buckets.length;
    const barW = Math.max(3, Math.min(24, slotW * 0.72));

    const cs = getComputedStyle(document.documentElement);
    const cProbe = cs.getPropertyValue("--probe").trim() || "#f43f5e";
    const cPing = cs.getPropertyValue("--ping").trim() || "#fbbf24";
    const cOther = cs.getPropertyValue("--other").trim() || "#38bdf8";
    const cLocal = cs.getPropertyValue("--local").trim() || "#34d399";
    const cStale = cs.getPropertyValue("--stale").trim() || "#94a3b8";
    const cGrid = cs.getPropertyValue("--chart-grid").trim() || "rgba(255,255,255,0.05)";
    const cInk = cs.getPropertyValue("--ink").trim() || "#f8fafc";

    let html = "";
    for (let i = 1; i <= 3; i++) {
      const y = (H / 4) * i;
      html += `<line x1="0" y1="${y}" x2="${W}" y2="${y}" stroke="${cGrid}" stroke-width="1" />`;
    }

    buckets.forEach((b, idx) => {
      const xSlot = idx * slotW;
      const xBar = xSlot + (slotW - barW) / 2;
      let yCursor = H;

      const segs = [
        { val: b.outbound || 0, color: cOther },
        { val: b.local || 0, color: cLocal },
        { val: b.stale, color: cStale },
        { val: b.other, color: cOther },
        { val: b.ping, color: cPing },
        { val: b.probe, color: cProbe },
      ];

      let rects = `<rect class="bar-hit" x="${xSlot}" y="0" width="${slotW}" height="${H}" fill="transparent" />`;
      for (const seg of segs) {
        if (!seg.val) continue;
        const h = Math.max(1.5, (seg.val / maxVal) * (H - 8));
        yCursor -= h;
        rects += `<rect class="bar-seg" x="${xBar.toFixed(1)}" y="${yCursor.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" rx="1.5" fill="${seg.color}" />`;
      }
      html += `<g class="chart-bar-group" data-idx="${idx}">${rects}</g>`;
    });

    svg.innerHTML = html;

    const labelCount = Math.min(6, buckets.length);
    const labels = [];
    for (let i = 0; i < labelCount; i++) {
      const idx = labelCount === 1 ? 0 : Math.round((i / (labelCount - 1)) * (buckets.length - 1));
      labels.push(`<span>${escHtml(buckets[idx].label)}</span>`);
    }
    axis.innerHTML = labels.join("");

    svg.querySelectorAll(".chart-bar-group").forEach((g) => {
      g.addEventListener("mouseenter", (e) => {
        const b = buckets[Number(g.dataset.idx)];
        const total = b.probe + b.ping + b.other + b.stale + (b.outbound || 0) + (b.local || 0);
        tooltip.innerHTML = `
          <div style="color:${cInk};font-weight:600;margin-bottom:4px">${escHtml(b.label)} · ${fmtNum(total)} events</div>
          ${b.probe ? `<div style="color:${cProbe}">Probes:   ${fmtNum(b.probe)}</div>` : ""}
          ${b.ping ? `<div style="color:${cPing}">Pings:    ${fmtNum(b.ping)}</div>` : ""}
          ${b.other ? `<div style="color:${cOther}">Other:    ${fmtNum(b.other)}</div>` : ""}
          ${b.stale ? `<div style="color:${cStale}">Stale:    ${fmtNum(b.stale)}</div>` : ""}
          ${b.outbound ? `<div style="color:${cOther}">Outbound: ${fmtNum(b.outbound)}</div>` : ""}
          ${b.local ? `<div style="color:${cLocal}">Local:    ${fmtNum(b.local)}</div>` : ""}
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

  function renderSources(sources) {
    $("srcCountBadge").textContent = `${sources.length}`;
    const box = $("sourceList");
    if (!sources.length) {
      box.innerHTML = `<div class="muted" style="padding:12px 0">No source IPs logged yet.</div>`;
      return;
    }

    box.innerHTML = sources
      .map((s) => {
        const selected = state.src === s.ip;
        const multiPort = s.unique_ports >= 3 && s.probes > 0;
        const label = s.name ? `${s.name} (${s.ip})` : s.ip;
        return `
          <button type="button" class="src-card ${selected ? "selected" : ""}" data-src="${escHtml(s.ip)}" aria-pressed="${selected ? "true" : "false"}">
            <div class="src-top">
              <div>
                <span class="src-ip mono">${escHtml(label)}</span>
                ${multiPort ? `<span class="scanner-tag mono">SCANNER</span>` : ""}
              </div>
              <span class="src-count mono">${fmtNum(s.count)}</span>
            </div>
            <div class="src-meta mono">
              <span>${escHtml(s.protos.join("/"))} · ${s.unique_ports} port${s.unique_ports === 1 ? "" : "s"}</span>
              <span>${fmtRelative(s.last_seen)}</span>
            </div>
          </button>
        `;
      })
      .join("");
  }

  function renderPorts(ports) {
    const box = $("portLeaderboard");
    if (!ports.length) {
      box.innerHTML = `<div class="muted" style="padding:12px 0">No targeted ports.</div>`;
      return;
    }
    const maxC = Math.max(1, ports[0].count);
    box.innerHTML = ports
      .map((p) => {
        const pct = (p.count / maxC) * 100;
        const isStale = p.service.startsWith("Late ");
        const color = isStale ? "var(--stale)" : p.proto === "ICMP" ? "var(--ping)" : "var(--probe)";
        return `
          <button class="bar-row" data-port="${escHtml(p.port)}" title="Filter drops targeting ${escHtml(p.port)} (${escHtml(p.service)})">
            <span class="bar-fill" style="width:${pct}%;background:${color}"></span>
            <span class="bar-left">
              <span class="bar-port mono">${escHtml(p.port)}</span>
              <span class="bar-svc">${escHtml(p.service)}</span>
            </span>
            <span class="bar-count mono">${fmtNum(p.count)}</span>
          </button>
        `;
      })
      .join("");
  }

  function renderProtos(protos) {
    const box = $("protoGrid");
    if (!protos.length) {
      box.innerHTML = `<span class="muted">—</span>`;
      return;
    }
    box.innerHTML = protos
      .map(
        (p) => `
        <button type="button" class="proto-pill ${state.proto === p.proto.toUpperCase() ? "active" : ""}" data-proto="${escHtml(p.proto.toUpperCase())}" aria-pressed="${state.proto === p.proto.toUpperCase() ? "true" : "false"}">
          <span>${escHtml(p.proto)}</span>
          <span class="muted">${fmtNum(p.count)}</span>
        </button>`
      )
      .join("");
  }

  function renderTable(evData) {
    const tbody = $("eventTableBody");
    const empty = $("tableEmpty");
    const rows = evData.rows || [];
    const start = evData.total ? evData.offset + 1 : 0;
    const end = evData.offset + rows.length;

    $("streamCountLabel").textContent = `Showing ${fmtNum(start)}–${fmtNum(end)} of ${fmtNum(evData.total)}`;
    $("pageStatus").textContent = `Page ${Math.floor(evData.offset / evData.limit) + 1} / ${Math.max(1, Math.ceil(evData.total / evData.limit))}`;
    $("prevPageBtn").disabled = evData.offset <= 0;
    $("nextPageBtn").disabled = end >= evData.total;

    if (!rows.length) {
      tbody.innerHTML = "";
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");

    tbody.innerHTML = rows
      .map((r) => {
        const srcLabel = r.src_name ? `${r.src_name}` : r.src_ip;
        const srcFull = r.spt !== null && !r.src_name ? `${srcLabel}:${r.spt}` : srcLabel;
        const dstPrefix = r.verdict === "allowed" && r.dst_ip ? `${r.dst_name || r.dst_ip}` : "";
        const targetDisp =
          r.dpt !== null
            ? `<button class="cell-link mono" data-filter-port="${r.dpt}">${dstPrefix ? `<span class="muted">${escHtml(dstPrefix)}</span>` : ""}<strong>:${r.dpt}</strong> <span class="muted">${escHtml(r.service)}</span></button>`
            : `<span class="mono">${dstPrefix ? `${escHtml(dstPrefix)} · ` : ""}${escHtml(r.service)}</span>`;
        const flagsHtml = r.flags.map((f) => `<span class="flag-tag">${escHtml(f)}</span>`).join("");
        const metaParts = [];
        if (r.in_iface && r.out_iface) metaParts.push(`${r.in_iface}→${r.out_iface}`);
        else if (r.in_iface) metaParts.push(`in:${r.in_iface}`);
        if (r.length !== null) metaParts.push(`${r.length}B`);
        if (r.ttl !== null) metaParts.push(`ttl:${r.ttl}`);
        if (r.action !== "DROP" && r.action !== "ACCEPT") metaParts.push(r.action);

        const catTip = CATEGORY_TOOLTIPS[r.category] || "Heuristic traffic classification";
        return `
          <tr class="${r.category === "probe" ? "row-probe" : ""}">
            <th scope="row" class="mono muted row-time" title="${escHtml(r.ts_iso)}">${fmtClock(r.ts)}</th>
            <td><span class="cat-tag cat-${escHtml(r.category)}" title="${escHtml(catTip)}" aria-label="Inferred category: ${escHtml(r.category)}">${escHtml(r.category)}</span></td>
            <td><span class="proto-tag">${escHtml(r.proto)}</span></td>
            <td class="mono">
              <button type="button" class="cell-link" data-filter-src="${escHtml(r.src_ip)}" title="${escHtml(r.src_ip)}${r.spt ? ":" + r.spt : ""}">${escHtml(srcFull)}</button>
            </td>
            <td>${targetDisp}</td>
            <td class="mono muted" style="font-size:11.5px">${flagsHtml}${escHtml(metaParts.join(" · "))}</td>
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

  function setCategory(cat) {
    state.category = cat;
    state.offset = 0;
    document.querySelectorAll("#catPills button").forEach((b) => {
      const on = b.dataset.cat === cat;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    document.querySelectorAll("[data-cat-click]").forEach((card) => {
      card.setAttribute("aria-pressed", card.dataset.catClick === cat ? "true" : "false");
    });
    loadData();
  }

  // Event wiring
  enableArrowNav($("verdictSelector"));
  enableArrowNav($("rangeSelector"));
  enableArrowNav($("catPills"));

  $("verdictSelector").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-verdict]");
    if (!btn) return;
    state.verdict = btn.dataset.verdict;
    state.category = "all";
    state.src = "";
    state.port = "";
    state.offset = 0;
    $("verdictSelector").querySelectorAll("button").forEach((b) => {
      const on = b === btn;
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    document.querySelectorAll("#catPills button").forEach((b) => {
      const on = b.dataset.cat === "all";
      b.classList.toggle("active", on);
      b.setAttribute("aria-checked", on ? "true" : "false");
    });
    loadData();
  });

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

  $("hideStaleToggle").addEventListener("change", (e) => {
    state.hideStale = e.target.checked;
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

  $("catPills").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-cat]");
    if (!btn) return;
    setCategory(btn.dataset.cat);
  });

  document.querySelectorAll("[data-cat-click]").forEach((card) => {
    const toggle = () => {
      const target = card.dataset.catClick;
      setCategory(state.category === target ? "all" : target);
    };
    card.addEventListener("click", toggle);
    card.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
    });
  });

  $("sourceList").addEventListener("click", (e) => {
    const card = e.target.closest(".src-card");
    if (!card) return;
    const ip = card.dataset.src;
    state.src = state.src === ip ? "" : ip;
    state.offset = 0;
    loadData();
  });

  $("portLeaderboard").addEventListener("click", (e) => {
    const row = e.target.closest(".bar-row");
    if (!row) return;
    const p = row.dataset.port;
    state.port = state.port === p ? "" : p;
    state.offset = 0;
    loadData();
  });

  $("protoGrid").addEventListener("click", (e) => {
    const pill = e.target.closest(".proto-pill");
    if (!pill) return;
    const pr = pill.dataset.proto;
    state.proto = state.proto === pr ? "all" : pr;
    state.offset = 0;
    loadData();
  });

  $("eventTableBody").addEventListener("click", (e) => {
    const srcBtn = e.target.closest("[data-filter-src]");
    if (srcBtn) {
      state.src = srcBtn.dataset.filterSrc;
      state.offset = 0;
      loadData();
      return;
    }
    const portBtn = e.target.closest("[data-filter-port]");
    if (portBtn) {
      state.port = portBtn.dataset.filterPort;
      state.offset = 0;
      loadData();
    }
  });

  let searchTimer = null;
  $("searchInput").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = e.target.value.trim();
      state.offset = 0;
      loadData();
    }, 180);
  });

  $("activeFilterChips").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-clear]");
    if (!btn) return;
    const k = btn.dataset.clear;
    if (k === "hideStale") {
      state.hideStale = false;
      $("hideStaleToggle").checked = false;
    }
    if (k === "src") state.src = "";
    if (k === "category") setCategory("all");
    if (k === "proto") state.proto = "all";
    if (k === "port") state.port = "";
    if (k === "q") {
      state.q = "";
      $("searchInput").value = "";
    }
    state.offset = 0;
    loadData();
  });

  $("clearFiltersBtn").addEventListener("click", () => {
    state.hideStale = false;
    $("hideStaleToggle").checked = false;
    state.src = "";
    state.category = "all";
    state.proto = "all";
    state.port = "";
    state.q = "";
    state.offset = 0;
    $("searchInput").value = "";
    document.querySelectorAll("#catPills button").forEach((b) => {
      b.classList.toggle("active", b.dataset.cat === "all");
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
  loadData();
  state.autoTimer = setInterval(loadData, 3000);
})();

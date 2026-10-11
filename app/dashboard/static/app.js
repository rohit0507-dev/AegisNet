"use strict";

// DOM helpers and value formatting.
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const esc = (v) =>
  String(v ?? "—").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const paths = {
  network:
    '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 8v4H5v4m7-4h7v4"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  activity: '<path d="M3 13h4l3-8 4 14 3-8h4"/>',
  alert: '<path d="m12 3 10 18H2Zm0 5v6m0 3h.01"/>',
  history: '<path d="M3 10a9 9 0 1 1 1 7M3 4v6h6m3-3v5l4 2"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5Zm-9 9 9 5 9-5M3 17l9 5 9-5"/>',
  book: '<path d="M12 6s-3-3-9-2v15c6-1 9 2 9 2s3-3 9-2V4c-6-1-9 2-9 2Zm0 0v15"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  pause: '<path d="M8 5v14M16 5v14"/>',
  play: '<path d="m7 4 13 8-13 8Z"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
};
const icon = (name) =>
  /* HTML */ `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
    ${paths[name] || paths.arrow}
  </svg>`;
function icons(root = document) {
  root
    .querySelectorAll("[data-icon]")
    .forEach((el) => (el.innerHTML = icon(el.dataset.icon)));
}
const fmt = (n) => Number(n || 0).toLocaleString("en-US");
function bytes(n) {
  n = Number(n || 0);
  const i = Math.min(
    4,
    Math.max(0, Math.floor(Math.log(n || 1) / Math.log(1024))),
  );
  return `${(n / 1024 ** i).toLocaleString("en-US", { maximumFractionDigits: i ? 1 : 0 })} ${["B", "KiB", "MiB", "GiB", "TiB"][i]}`;
}
function rate(n, packet = false) {
  if (packet)
    return `${Number(n || 0).toLocaleString("en-US", { maximumFractionDigits: 1 })} pkt/s`;
  const i = n >= 1e9 ? 3 : n >= 1e6 ? 2 : n >= 1e3 ? 1 : 0;
  return `${(Number(n || 0) / 1000 ** i).toLocaleString("en-US", { maximumFractionDigits: 1 })} ${["bit/s", "Kbit/s", "Mbit/s", "Gbit/s"][i]}`;
}
const time = (t) => (t ? String(t).split("T").pop().slice(0, 8) : "—");
function date(t) {
  if (!t) return "No saved records";
  const d = new Date(t);
  return Number.isNaN(d.valueOf())
    ? String(t)
    : d.toLocaleDateString("en-GB", {
        day: "2-digit",
        month: "short",
        year: "numeric",
      });
}
const titleCase = (s) =>
  String(s || "")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (x) => x.toUpperCase());
const badge = (text, kind = "") =>
  /* HTML */ `<span class="badge ${esc(kind)}">${esc(text)}</span>`;
const empty = (heading, copy = "") =>
  /* HTML */ `<div class="empty">
    <strong>${esc(heading)}</strong>
    <p>${esc(copy)}</p>
  </div>`;

// Filters and the data currently shown in the browser.
const state = {
  page: "home",
  range: "5m",
  paused: false,
  data: null,
  chart: "bps",
  pageNumber: 1,
  pages: 1,
  query: "",
  protocol: "all",
  kind: "all",
  sort: "newest",
  capture: { state: "stopped" },
};
const pages = {
  home: [
    "Project home",
    "Real-Time Network Traffic Monitoring and Intrusion Detection System",
  ],
  overview: [
    "Dashboard",
    "Packet counts, protocol distribution, and recent flow records.",
  ],
  traffic: [
    "Traffic records",
    "Search the captured flows and inspect their network fields.",
  ],
  detections: [
    "Alerts",
    "Rule matches and ML outliers in the selected time range.",
  ],
  responses: [
    "Response history",
    "Window scores and simulated response decisions.",
  ],
  lab: [
    "Computer Networks tools",
    "Subnetting, error-control calculations, and the OSI model.",
  ],
  project: [
    "Project details",
    "Team members, implemented features, and limitations.",
  ],
};
let toastTimer,
  dashboardRequest = 0,
  flowRequest = 0,
  searchTimer;
function toast(message) {
  $("#toast").textContent = message;
  $("#toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("#toast").hidden = true), 3800);
}

// All dashboard requests use the local Flask API.
async function api(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const r = await fetch(path, { ...options, signal: controller.signal });
    let j;
    try {
      j = await r.json();
    } catch {
      throw Error(
        "The server returned an unreadable response. Check its terminal.",
      );
    }
    if (!r.ok || j.success === false)
      throw Error(j.error || `Request failed (${r.status}).`);
    return j;
  } finally {
    clearTimeout(timer);
  }
}
function showError(err) {
  $("#error-banner").textContent =
    err.name === "AbortError"
      ? "The server took too long to respond. Use Refresh to retry."
      : err.message;
  $("#error-banner").hidden = false;
  $("#updated-label").textContent =
    "Connection issue · displayed values may be stale";
}

// Workspace navigation becomes a keyboard-accessible drawer on narrow screens.
const mobileNavigation = window.matchMedia("(max-width: 960px)");
function setNavigationOpen(open) {
  const show = open && mobileNavigation.matches;
  document.body.classList.toggle("navigation-open", show);
  $("#menu-button").setAttribute("aria-expanded", String(show));
  $("#menu-button").setAttribute(
    "aria-label",
    show ? "Close navigation" : "Open navigation",
  );
  $("#nav-overlay").hidden = !show;
  $("#sidebar").inert = mobileNavigation.matches && !show;
  $(".workspace").inert = show;
  if (show) $("#sidebar .nav-link.active").focus();
}
mobileNavigation.addEventListener("change", () => setNavigationOpen(false));

// Tab navigation and automatic refresh.
function navigate() {
  let page = location.hash.slice(1) || "home";
  if (!pages[page]) page = "overview";
  state.page = page;
  document.body.classList.toggle("is-home", page === "home");
  $(".page-heading").hidden = page === "home";
  $(".workspace-topbar").hidden = page === "home";
  $(".main-footer").hidden = page === "home";
  $$(".page").forEach((el) => (el.hidden = el.id !== `page-${page}`));
  $$(".nav-link").forEach((el) => {
    el.classList.toggle("active", el.dataset.page === page);
    if (el.dataset.page === page) el.setAttribute("aria-current", "page");
    else el.removeAttribute("aria-current");
  });
  $("#page-title").textContent = pages[page][0];
  $("#breadcrumb").textContent = pages[page][0];
  setNavigationOpen(false);
  $("#page-description").textContent = pages[page][1];
  document.title = `AegisNet · ${pages[page][0]}`;
  $("#context-bar").hidden = ["home", "lab", "project"].includes(page);
  $("#capture-banner").hidden = ["home", "lab", "project"].includes(page);
  $("#export-report").hidden = ["home", "lab", "project"].includes(page);
  if (page === "traffic") loadFlows();
  if (state.data) {
    renderSecondary();
    if (page === "overview") renderTrafficChart();
  }
  if (page === "lab" && !$("#subnet-results").innerHTML) calculateSubnet();
  window.scrollTo({ top: 0, behavior: "instant" });
  if (page !== "home") $("#main").focus({ preventScroll: true });
}
function flowParams() {
  return new URLSearchParams({
    range: state.range,
    q: state.query,
    protocol: state.protocol,
    kind: state.kind,
    sort: state.sort,
    page: state.pageNumber,
  });
}
async function loadDashboard() {
  const generation = ++dashboardRequest;
  try {
    const result = await api(`/api/dashboard?range=${state.range}`);
    if (generation !== dashboardRequest) return;
    state.data = result.data;
    state.capture = result.data.capture;
    $("#error-banner").hidden = true;
    renderOverview();
    renderSecondary();
    renderCapture();
    $("#updated-label").textContent =
      `Updated ${new Date().toLocaleTimeString("en-GB")} · ${state.paused ? "updates paused" : "refreshes every 5s"}`;
    if (state.page === "traffic") loadFlows();
  } catch (e) {
    if (generation === dashboardRequest) showError(e);
  }
}

// Capture status and the main dashboard.
function renderCapture() {
  const c = state.capture;
  const running = c.state === "running";
  const starting = c.state === "starting";
  $("#sensor-dot").classList.toggle("running", running);
  $("#data-dot").classList.toggle("running", running);
  $("#sensor-name").textContent = running
    ? "Capture running"
    : starting
      ? "Starting capture"
      : c.state === "error"
        ? "Capture needs attention"
        : "Capture stopped";
  $("#data-status").textContent = running
    ? "Live capture"
    : starting
      ? "Starting capture"
      : "Saved traffic";
  $("#mode-tag").textContent = running ? "Live capture" : "Saved data";
  $("#capture-banner").classList.toggle("live", running);
  const last = state.data?.bounds.last;
  $("#data-date").textContent = last
    ? `${date(last)} · ${time(last)} host time`
    : "No records yet";
  $("#capture-message").textContent = running
    ? `Receiving packets on ${c.interface}. ${c.ml_loaded ? "ML model loaded." : "ML unavailable; rule-based analysis continues."} Response actions are simulated.`
    : last
      ? `Showing stored traffic from ${date(last)}. Start capture to monitor this device.`
      : "No saved records yet. Choose a network adapter in Capture controls to begin.";
  $("#capture-status-card").innerHTML = /* HTML */ `<strong
      >${esc(titleCase(c.state))}</strong
    >${c.interface ? ` · ${esc(c.interface)}` : ""}
    <p>
      ${c.ml_loaded === true ? "Isolation Forest loaded" : c.ml_loaded === false ? "ML model unavailable · rule-based detection remains active" : "ML status available when capture starts"}
    </p>
    ${c.message ? /* HTML */ `<p>${esc(c.message)}</p>` : ""}`;
  $("#start-capture").disabled = running || starting;
  $("#stop-capture").disabled = !c.managed;
  $("#adapter-select").disabled = running || starting;
}
function renderOverview() {
  const d = state.data,
    s = d.summary;
  $("#m-packets").textContent = fmt(s.packets);
  $("#m-packets-sub").textContent = `${fmt(s.flows)} directional flow records`;
  const size = bytes(s.bytes).split(" ");
  $("#m-bytes").innerHTML = `${esc(size[0])}<small>${esc(size[1])}</small>`;
  $("#m-bytes-sub").textContent =
    `${bytes(s.average_packet_size)} average packet size`;
  $("#m-endpoints").textContent = fmt(s.endpoints);
  $("#m-flagged").textContent = fmt(s.flagged);
  $("#m-flagged-sub").textContent =
    `${fmt(s.rule_alerts)} rule alerts · ${fmt(s.anomalies)} ML anomalies`;
  $("#alert-count").textContent =
    s.rule_alerts > 999 ? "999+" : fmt(s.rule_alerts);
  $("#alert-count").title =
    `${fmt(s.rule_alerts)} rule-alert instances in range`;
  renderTrafficChart();
  renderProtocols();
  $("#talker-list").innerHTML = d.talkers.length
    ? d.talkers
        .map(
          (t) =>
            /* HTML */ `<div class="talker">
              <button
                class="mono"
                data-source="${esc(t.source_ip)}"
                title="Explore ${esc(t.source_ip)}"
              >
                ${esc(t.source_ip)}
              </button>
              <div class="talker-bar">
                <i
                  style="width:${Math.max(1, (100 * t.bytes) / (d.talkers[0].bytes || 1))}%"
                ></i>
              </div>
              <span>${bytes(t.bytes)}</span>
            </div>`,
        )
        .join("")
    : empty(
        "No traffic in this range",
        "Start capture or choose a wider range.",
      );
  $("#signal-list").innerHTML = d.flagged.length
    ? d.flagged
        .slice(0, 3)
        .map(
          (f) =>
            /* HTML */ `<button class="signal" data-flow="${f.id}">
              <div>
                <strong
                  >${esc(f.alerts.length ? titleCase(f.alerts[0]) : "ML anomaly")}</strong
                >
                <p class="mono">
                  ${esc(f.source_ip)} → ${esc(f.destination_ip)}
                </p>
              </div>
              <div class="signal-right">
                ${badge(f.alert_count ? "Rule alert" : "ML anomaly", "warn")}<small
                  >${time(f.timestamp)}</small
                >
              </div>
            </button>`,
        )
        .join("")
    : empty(
        "No flagged flows in this range",
        "The available records contain no rule or ML flags.",
      );
  $("#recent-table").innerHTML = flowTable(d.recent, true);
}
function renderProtocols() {
  const rows = state.data.protocols;
  const total = state.data.summary.packets;
  if (!rows.length) {
    $("#protocol-list").innerHTML = empty("No packets in this range");
    return;
  }
  const heading =
    '<div class="protocol-labels"><span>Protocol</span><span>Packets · share</span></div>';
  const bars = rows
    .map((row) => {
      const percentage = (row.packets / (total || 1)) * 100;
      return `
      <div class="protocol-row">
        <strong>${esc(row.protocol)}</strong>
        <span class="protocol-count">${fmt(row.packets)} · ${percentage.toFixed(1)}%</span>
        <div class="protocol-bar" aria-hidden="true">
          <span style="width:${percentage}%"></span>
        </div>
      </div>`;
    })
    .join("");
  $("#protocol-list").innerHTML = heading + bars;
}

// Draw a line chart in SVG; no external chart library is needed.
function lineChart(target, rows, key, { max = null, score = false } = {}) {
  const el = $(target);
  if (!rows.length) {
    el.innerHTML =
      '<div class="empty-chart">No data in the selected range</div>';
    return;
  }
  const w = Math.max(300, el.clientWidth - 28),
    h = 205,
    left = score ? 34 : 50,
    right = 13,
    top = 12,
    bottom = 32,
    cw = w - left - right,
    ch = h - top - bottom;
  const values = rows.map((r) => Number(r[key] || 0));
  const peak = max || Math.max(...values, 1) * 1.14;
  let unit = 1,
    suffix = "";
  if (!score && key === "bps") {
    unit = peak >= 1e6 ? 1e6 : peak >= 1e3 ? 1e3 : 1;
    suffix = unit === 1e6 ? "M" : unit === 1e3 ? "k" : "";
  }
  const point = (v, i) => [
    left + (rows.length === 1 ? 0.5 : i / (rows.length - 1)) * cw,
    top + ch - (v / peak) * ch,
  ];
  const pts = values.map(point);
  const path = pts
    .map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)},${p[1].toFixed(1)}`)
    .join(" ");
  let grid = "";
  for (let i = 0; i <= 4; i++) {
    const y = top + (ch * i) / 4;
    grid += /* HTML */ `<line
        class="chart-grid"
        x1="${left}"
        x2="${w - right}"
        y1="${y}"
        y2="${y}"
      /><text x="${left - 9}" y="${y + 3}" text-anchor="end"
        >${((peak * (1 - i / 4)) / unit).toLocaleString("en-US", { maximumFractionDigits: peak / unit < 10 ? 1 : 0 })}${suffix}</text
      >`;
  }
  const labelCount = Math.min(w < 500 ? 3 : 5, rows.length);
  let labels = "";
  for (let i = 0; i < labelCount; i++) {
    const index = Math.round(
      (i / Math.max(1, labelCount - 1)) * (rows.length - 1),
    );
    const [x] = point(0, index);
    labels += /* HTML */ `<text
      x="${x}"
      y="${h - 7}"
      text-anchor="${i === 0 ? "start" : i === labelCount - 1 ? "end" : "middle"}"
      >${esc(time(rows[index].time || rows[index].timestamp))}</text
    >`;
  }
  el.innerHTML = /* HTML */ `<svg
    viewBox="0 0 ${w} ${h}"
    role="img"
    aria-label="${score ? "Fused threat score" : "Captured traffic"} over time"
  >
    ${grid}
    <path class="chart-line" d="${path}" />
    ${pts.map((p, i) => /* HTML */ `<circle cx="${p[0]}" cy="${p[1]}" r="${rows.length === 1 ? 4 : 6}" fill="${rows.length === 1 ? "var(--accent)" : "transparent"}"><title>${esc(time(rows[i].time || rows[i].timestamp))} · ${score ? values[i].toFixed(2) : rate(values[i], key === "pps")}</title></circle>`).join("")}${labels}
  </svg>`;
}
function renderTrafficChart() {
  const d = state.data;
  const isPackets = state.chart === "pps";
  const avg = d.series.length
    ? d.series.reduce((s, r) => s + r[state.chart], 0) / d.series.length
    : 0;
  $("#average-rate").textContent = rate(avg, isPackets);
  $("#chart-series-label").textContent = isPackets
    ? "Captured packet rate"
    : "Captured bit rate";
  $("#bucket-label").textContent = `${d.interval}s buckets`;
  lineChart("#traffic-chart", d.series, state.chart);
}

// Traffic records, detection summaries, and the detail dialog.
function flowTable(rows, short = false) {
  if (!rows.length)
    return empty(
      "No matching flow records",
      "Try a wider time range or clear the search filters.",
    );
  return /* HTML */ `<table>
    <thead>
      <tr>
        <th>Time</th>
        <th>Source → Destination</th>
        <th>Protocol</th>
        ${short ? "" : "<th>Service hint</th>"}
        <th>Packets</th>
        <th>Traffic</th>
        <th>Evidence</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      ${rows
        .map(
          (f) =>
            /* HTML */ `<tr data-flow="${f.id}">
              <td class="mono">
                ${time(f.timestamp)}<small>${date(f.timestamp)}</small>
              </td>
              <td>
                <span class="mono"
                  >${esc(f.source_ip)}<span class="ip-arrow">→</span
                  >${esc(f.destination_ip)}</span
                ><small
                  >${f.source_port || "—"} → ${f.destination_port || "—"}
                  &nbsp;·&nbsp; ${esc(f.family)}</small
                >
              </td>
              <td>${badge(f.protocol, f.protocol)}</td>
              ${short ? "" : /* HTML */ `<td>${esc(f.service)}</td>`}
              <td class="mono">${fmt(f.packet_count)}</td>
              <td>${bytes(f.total_bytes)}</td>
              <td>
                ${f.alert_count ? badge("Rule alert", "warn") : f.ml_anomaly ? badge("ML anomaly", "warn") : f.ml_available === 0 ? badge("Rules only") : badge("No flags", "good")}
              </td>
              <td>
                <button
                  class="row-open"
                  data-flow="${f.id}"
                  aria-label="Inspect flow ${f.id}"
                >
                  Inspect ${icon("arrow")}
                </button>
              </td>
            </tr>`,
        )
        .join("")}
    </tbody>
  </table>`;
}
async function loadFlows() {
  const generation = ++flowRequest;
  try {
    const r = await api(`/api/flows?${flowParams()}`);
    if (generation !== flowRequest) return;
    state.pageNumber = r.page;
    state.pages = r.pages;
    $("#flows-table").innerHTML = flowTable(r.data);
    $("#flow-count").textContent = r.total
      ? `${fmt((r.page - 1) * r.limit + 1)}–${fmt(Math.min(r.total, r.page * r.limit))} of ${fmt(r.total)} flow records`
      : "0 matching flow records";
    $("#page-number").textContent = `${r.page} / ${r.pages}`;
    $("#prev-page").disabled = r.page <= 1;
    $("#next-page").disabled = r.page >= r.pages;
  } catch (e) {
    if (generation === flowRequest) showError(e);
  }
}
function metric(label, value, caption) {
  return `
    <article class="metric">
      <h2>${esc(label)}</h2>
      <div class="metric-value">${esc(value)}</div>
      <p>${esc(caption)}</p>
    </article>`;
}
function renderSecondary() {
  if (!state.data) return;
  const d = state.data,
    s = d.summary;
  if (state.page === "detections") {
    $("#detection-metrics").innerHTML =
      metric(
        "Rule-alert instances",
        fmt(s.rule_alerts),
        "Counts may include multiple alerts per flow",
      ) +
      metric(
        "ML anomaly records",
        fmt(s.anomalies),
        "Statistical outliers · not confirmed attacks",
      ) +
      metric(
        "Flagged flow share",
        `${((100 * s.flagged) / (s.flows || 1)).toFixed(1)}%`,
        `${fmt(s.flagged)} of ${fmt(s.flows)} flow records`,
      );
    $("#detection-list").innerHTML = d.flagged.length
      ? d.flagged
          .map(
            (f) =>
              /* HTML */ `<div
                class="detection-item"
                role="button"
                tabindex="0"
                data-flow="${f.id}"
              >
                <div>
                  <h3>
                    ${esc(f.alerts.length ? f.alerts.map(titleCase).join(" · ") : "ML anomaly")}
                  </h3>
                  ${badge("Needs review", "warn")}
                </div>
                <span class="mono"
                  >${esc(f.source_ip)} → ${esc(f.destination_ip)}</span
                >
                <p>
                  ${time(f.timestamp)} · ${esc(f.protocol)} ·
                  ${fmt(f.packet_count)} packets · ${bytes(f.total_bytes)}
                </p>
                <div class="evidence-tags">
                  ${badge(`Flow score ${Number(f.threat_score || 0).toFixed(1)}/100`)}${f.ml_anomaly ? badge("ML flag", "info") : ""}${badge(`${f.temporal_streak || 0} persistence windows`)}
                </div>
              </div>`,
          )
          .join("") +
        '<div class="panel-note">Latest 5 flagged records. Use Traffic records to inspect all matching flows.</div>'
      : empty(
          "No detection signals in this range",
          "Choose a wider range to review earlier records.",
        );
  }
  if (state.page === "responses") {
    const latest = d.events[0];
    $("#response-metrics").innerHTML =
      metric(
        "Latest fused score",
        latest ? `${Number(latest.threat_score || 0).toFixed(1)} / 100` : "—",
        latest
          ? `Recorded at ${time(latest.timestamp)} · ${date(latest.timestamp)}`
          : "No recorded response event",
      ) +
      metric(
        "Recorded state",
        latest ? titleCase(latest.threat_state) : "—",
        "Latest saved window-level assessment",
      ) +
      metric(
        "Response events",
        fmt(d.event_count),
        "Actions are simulated; no firewall changes",
      );
    lineChart("#threat-chart", [...d.events].reverse(), "threat_score", {
      max: 100,
      score: true,
    });
    $("#responses-table").innerHTML = d.events.length
      ? /* HTML */ `<table>
          <thead>
            <tr>
              <th>Recorded time</th>
              <th>Source</th>
              <th>Fused score</th>
              <th>Transition</th>
              <th>Simulated action</th>
              <th>Feedback</th>
            </tr>
          </thead>
          <tbody>
            ${d.events
              .map(
                (e) =>
                  /* HTML */ `<tr>
                    <td class="mono">
                      ${time(e.timestamp)}<small>${date(e.timestamp)}</small>
                    </td>
                    <td class="mono">${esc(e.source_ip)}</td>
                    <td>${Number(e.threat_score || 0).toFixed(2)}</td>
                    <td>
                      ${esc(titleCase(e.previous_state))} →
                      ${esc(titleCase(e.threat_state))}
                    </td>
                    <td>
                      ${badge(titleCase(e.action), e.action === "MONITOR" ? "good" : "warn")}
                    </td>
                    <td>
                      ${esc(e.effectiveness ? titleCase(e.effectiveness) : "Not evaluated")}<small
                        >${esc(e.recommendation ? titleCase(e.recommendation) : "")}</small
                      >
                    </td>
                  </tr>`,
              )
              .join("")}
          </tbody>
        </table>`
      : empty("No response decisions recorded");
  }
}
async function inspectFlow(id) {
  try {
    const { data: f } = await api(`/api/flows/${id}`);
    $("#flow-dialog-title").textContent = `Flow #${f.id}`;
    const fields = [
      ["Protocol", f.protocol],
      ["Network family", f.family],
      ["Packets", fmt(f.packet_count)],
      ["Captured bytes", bytes(f.total_bytes)],
      ["Flow duration", `${Number(f.duration || 0).toFixed(4)} s`],
      ["Average packet size", bytes(f.average_packet_size)],
      [
        "Flow packet rate",
        f.duration >= 0.001
          ? rate(f.packets_per_second, true)
          : "Not enough elapsed time",
      ],
      ["Window ID", f.window_id ?? "—"],
    ];
    $("#flow-detail").innerHTML = /* HTML */ `<div class="detail-info">
        ${badge(f.protocol, f.protocol)}<span
          >${esc(date(f.timestamp))} · ${time(f.timestamp)} · capture host
          time</span
        >
      </div>
      <div class="flow-route">
        <div>
          <small>Source</small><strong class="mono">${esc(f.source_ip)}</strong>
          <p>Port ${f.source_port || "not applicable"}</p>
        </div>
        ${icon("arrow")}
        <div>
          <small>Destination</small
          ><strong class="mono">${esc(f.destination_ip)}</strong>
          <p>Port ${f.destination_port || "not applicable"}</p>
        </div>
      </div>
      <div class="result-grid">
        ${fields.map(([k, v]) => /* HTML */ `<div><label>${esc(k)}</label><strong>${esc(v)}</strong></div>`).join("")}
      </div>
      <div class="detail-section">
        <h3>Protocol layers</h3>
        <p>
          <strong>${esc(f.family)}</strong> →
          <strong>${esc(f.protocol)}</strong> → ${esc(f.service)}.
          ${f.service.includes("port hint") ? "A familiar port suggests a service; it does not verify application payload." : ""}
        </p>
      </div>
      ${
        f.protocol === "TCP"
          ? /* HTML */ `<div class="detail-section">
              <h3>TCP control flags</h3>
              <div class="flag-grid">
                ${["syn", "ack", "fin", "rst"].map((k) => /* HTML */ `<div class="flag-box"><span>${k.toUpperCase()}</span><strong>${fmt(f[k + "_count"])}</strong><small>${(100 * Number(f[k + "_ratio"] || 0)).toFixed(1)}% of packets</small></div>`).join("")}
              </div>
              <p>
                One packet can carry multiple flags. Counts are directional and
                do not prove handshake failure.
              </p>
            </div>`
          : ""
      }
      <div class="detail-section">
        <h3>Detection evidence</h3>
        <div class="evidence-tags">
          ${badge(`Flow score ${Number(f.threat_score || 0).toFixed(2)}/100`)}${f.alerts.map((a) => badge(titleCase(a), "warn")).join("")}${badge(f.ml_available === 0 ? "ML not evaluated" : f.ml_anomaly ? "ML anomaly" : "No ML flag", f.ml_anomaly ? "warn" : "info")}
        </div>
        <p>
          Isolation Forest decision value:
          <strong
            >${f.ml_available === 0 ? "not available" : Number(f.ml_anomaly_score || 0).toFixed(5)}</strong
          >. Negative decision values indicate outliers; this is not a
          probability.
          ${f.ml_available === null ? "This legacy record does not store model availability." : ""}
        </p>
        <p>
          Temporal state: ${esc(titleCase(f.temporal_state))} · persistence
          streak: ${f.temporal_streak || 0} windows.
        </p>
      </div>
      <div class="soft-note" style="margin:20px 0 0">
        This is an aggregated flow record, not a raw packet or a confirmed
        intrusion. Response decisions combine evidence at the capture-window
        level.
      </div>`;
    icons($("#flow-detail"));
    $("#flow-dialog").showModal();
  } catch (e) {
    toast(e.message);
  }
}

// Start and stop the local capture process.
async function openCapture() {
  setNavigationOpen(false);
  $("#capture-error").hidden = true;
  $("#capture-dialog").showModal();
  renderCapture();
  try {
    const result = await api("/api/interfaces");
    const selected = $("#adapter-select").value;
    $("#adapter-select").innerHTML =
      '<option value="">Select an adapter…</option>' +
      result.data
        .map(
          (i) =>
            /* HTML */ `<option value="${esc(i.id)}">
              ${esc(i.name)} · ${esc(i.ip)}
            </option>`,
        )
        .join("");
    if (result.data.some((i) => i.id === selected))
      $("#adapter-select").value = selected;
  } catch (e) {
    $("#adapter-select").innerHTML =
      '<option value="">Adapters unavailable</option>';
    $("#capture-error").textContent = e.message;
    $("#capture-error").hidden = false;
  }
}
async function captureAction(action) {
  $("#capture-error").hidden = true;
  const button = $(`#${action}-capture`);
  button.disabled = true;
  try {
    const r = await api("/api/capture", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-AegisNet": "local-dashboard",
      },
      body: JSON.stringify({ action, interface: $("#adapter-select").value }),
    });
    state.capture = r.data;
    renderCapture();
    toast(
      action === "start"
        ? "Starting capture. Waiting for packets…"
        : "Saving the final capture window…",
    );
    setTimeout(loadDashboard, 1000);
  } catch (e) {
    $("#capture-error").textContent = e.message;
    $("#capture-error").hidden = false;
    renderCapture();
  }
}

// CN tools: display the results of the networking calculations.
async function calculateSubnet() {
  try {
    const { data: d } = await api(
      `/api/subnet?cidr=${encodeURIComponent($("#subnet-input").value.trim())}`,
    );
    const fields = [
      ["Network / prefix", d.network],
      ["Netmask", d.netmask],
      ["Total addresses", d.addresses],
      ["Usable IPv4 addresses", d.usable],
      ["First usable IPv4", d.first],
      ["Last usable IPv4", d.last],
      ["Broadcast", d.broadcast],
      ["Address family", `IPv${d.version}`],
    ];
    $("#subnet-results").innerHTML = /* HTML */ `<div class="result-grid">
        ${fields.map(([k, v]) => /* HTML */ `<div><label>${esc(k)}</label><strong class="mono">${esc(v)}</strong></div>`).join("")}
      </div>
      <p>
        /31 uses both addresses for point-to-point links; /32 identifies one
        IPv4 host. IPv6 does not use IPv4 host-count rules.
      </p>`;
  } catch (e) {
    $("#subnet-results").innerHTML = /* HTML */ `<div class="inline-message">
      ${esc(e.message)}
    </div>`;
  }
}
let hammingCode = [],
  receivedCode = [];
function renderHamming() {
  let syndrome = 0;
  for (let i = 1; i <= 7; i++) if (receivedCode[i - 1]) syndrome ^= i;
  const errors = receivedCode.filter((x, i) => x !== hammingCode[i]).length;
  const corrected = [...receivedCode];
  if (syndrome) corrected[syndrome - 1] ^= 1;
  $("#error-results").innerHTML = /* HTML */ `<label
      >Codeword · positions 1 to 7</label
    >
    <div class="lab-result-code mono">${hammingCode.join("")}</div>
    <p>
      Click a bit below to introduce an error. Parity bits occupy positions 1,
      2, and 4.
    </p>
    <div class="hamming-bits">
      ${receivedCode.map((b, i) => /* HTML */ `<button class="bit-button ${b !== hammingCode[i] ? "flipped" : ""}" data-bit="${i}" aria-label="Flip bit ${i + 1}"><span>${b}</span><small>${i + 1}</small></button>`).join("")}
    </div>
    <p>
      Syndrome: <strong>${syndrome}</strong>.
      ${errors > 1 ? "More than one bit has been changed. Hamming (7,4) cannot reliably correct multiple errors." : syndrome ? `Single error at position ${syndrome}. Corrected data: ${[2, 4, 5, 6].map((i) => corrected[i]).join("")}.` : "No parity error detected."}
    </p>`;
}
function calculateError() {
  const method = $("#error-method").value,
    input = $("#error-input").value.trim();
  try {
    if (method === "crc") {
      const gen = $("#crc-generator").value.trim();
      if (!/^[01]{1,256}$/.test(input) || !/^1[01]{0,30}1$/.test(gen))
        throw Error(
          "Use binary data and a generator of 2–32 bits beginning and ending in 1.",
        );
      const padded = input + "0".repeat(gen.length - 1),
        remainder = crcRemainder(padded, gen),
        code = input + remainder;
      $("#error-results").innerHTML = /* HTML */ `<label>CRC remainder</label>
        <div class="lab-result-code mono">${remainder}</div>
        <p>
          Append ${gen.length - 1} zero bits, divide by
          <span class="mono">${gen}</span> using XOR, and keep the final
          ${gen.length - 1} bits.
        </p>
        <div class="result-grid">
          <div>
            <label>Transmitted codeword</label
            ><strong class="mono">${code}</strong>
          </div>
          <div>
            <label>Receiver remainder</label
            ><strong class="mono">${crcRemainder(code, gen)}</strong>
          </div>
        </div>
        <p>
          A zero remainder means this division found no error; some error
          patterns can remain undetected.
        </p>`;
    } else if (method === "checksum") {
      const checksum = internetChecksum($("#error-input").value),
        length = new TextEncoder().encode($("#error-input").value).length;
      $("#error-results").innerHTML = /* HTML */ `<label
          >16-bit Internet checksum</label
        >
        <div class="lab-result-code mono">
          0x${checksum.toString(16).toUpperCase().padStart(4, "0")}
        </div>
        <p>
          Sum the ${length} UTF-8 bytes as 16-bit words in network byte order,
          fold end-around carries, then take the one's complement. An odd final
          byte is padded with zero.
        </p>
        <p>
          This calculation uses your text only, without a TCP/UDP pseudo-header.
        </p>`;
    } else {
      if (!/^[01]{4}$/.test(input))
        throw Error("Hamming (7,4) requires exactly four data bits.");
      hammingCode = hamming(input);
      receivedCode = [...hammingCode];
      renderHamming();
    }
  } catch (e) {
    $("#error-results").innerHTML = /* HTML */ `<div class="inline-message">
      ${esc(e.message)}
    </div>`;
  }
}

// OSI reference text used in the CN tools tab.
const osi = [
  [
    7,
    "Application",
    "Services & application protocols",
    "HTTP and DNS sit at the application layer. This project decodes DNS when Scapy identifies it and labels common ports as service hints. HTTPS contents remain encrypted.",
    "DNS · HTTP · HTTPS",
  ],
  [
    6,
    "Presentation",
    "Representation & encryption",
    "Encoding, compression, and encryption are presentation concerns in the OSI model. The flow database contains metadata; it does not decrypt TLS payloads.",
    "Encoding · serialization · encryption",
  ],
  [
    5,
    "Session",
    "Managing logical sessions",
    "Session concepts describe establishing, coordinating, and ending a dialog. They are a conceptual view here; an AegisNet directional flow is not an OSI session implementation.",
    "Dialog control · checkpoints",
  ],
  [
    4,
    "Transport",
    "Ports, flags & conversations",
    "TCP and UDP ports identify transport endpoints. Inspect SYN, ACK, FIN, and RST flags in a TCP flow. A five-tuple contains source IP, destination IP, source port, destination port, and transport protocol.",
    "TCP · UDP · five-tuple",
  ],
  [
    3,
    "Network",
    "Addresses & packet delivery",
    "IPv4 and IPv6 addresses identify network-layer endpoints. ICMP carries control and diagnostic information. Use the subnet calculator to explore address ranges; this app does not run routing protocols.",
    "IPv4 · IPv6 · ICMP",
  ],
  [
    2,
    "Data link",
    "Frames & local delivery",
    "Ethernet frames carry IP packets. ARP maps IPv4 addresses to link-layer addresses on a local link. Frame sizes contribute to captured-byte totals. Ethernet FCS is usually unavailable to this flow collector.",
    "Ethernet · ARP · frame size",
  ],
  [
    1,
    "Physical",
    "Bits on a medium",
    "The physical layer transmits bits over a wired or wireless medium. A software packet capture does not directly measure electrical signals, radio quality, or the full capacity of a link.",
    "Bits · cables · radio",
  ],
];
function selectLayer(n) {
  const layer = osi.find((x) => x[0] === n);
  $("#osi-stack").innerHTML = osi
    .map(
      (l) =>
        /* HTML */ `<button
          class="osi-layer ${l[0] === n ? "active" : ""}"
          data-layer="${l[0]}"
        >
          <span>L${l[0]}</span>${l[1]}
        </button>`,
    )
    .join("");
  $("#osi-explanation").innerHTML = /* HTML */ `<span class="overline"
      >LAYER ${n} · ${esc(layer[1].toUpperCase())}</span
    >
    <h3>${esc(layer[2])}</h3>
    <p>${esc(layer[3])}</p>
    ${badge(layer[4], "info")}<br /><a href="#traffic" class="button"
      >View traffic records ${icon("arrow")}</a
    >`;
}

// Connect the controls to the functions above.

icons();
$("#menu-button").onclick = () =>
  setNavigationOpen(!document.body.classList.contains("navigation-open"));
$("#nav-overlay").onclick = () => {
  setNavigationOpen(false);
  $("#menu-button").focus();
};
$("#close-navigation").onclick = $("#nav-overlay").onclick;
document.addEventListener("keydown", (event) => {
  if (!document.body.classList.contains("navigation-open")) return;
  if (event.key === "Escape") {
    setNavigationOpen(false);
    $("#menu-button").focus();
  }
  if (event.key === "Tab") {
    const controls = [...$("#sidebar").querySelectorAll("a, button")];
    const first = controls[0],
      last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    }
    if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
});
window.addEventListener("hashchange", () => {
  if (location.hash !== "#main") navigate();
});
document.addEventListener("click", (e) => {
  if (
    e.target.closest(".nav-link") &&
    document.body.classList.contains("navigation-open")
  ) {
    setNavigationOpen(false);
    $("#main").focus({ preventScroll: true });
  }
  const flow = e.target.closest("[data-flow]");
  if (flow) {
    inspectFlow(flow.dataset.flow);
    return;
  }
  const source = e.target.closest("[data-source]");
  if (source) {
    state.query = source.dataset.source;
    state.pageNumber = 1;
    $("#flow-search").value = state.query;
    location.hash = "traffic";
    if (state.page === "traffic") loadFlows();
    return;
  }
  if (e.target.closest("[data-open-capture]")) openCapture();
  const close = e.target.closest("[data-close-dialog]");
  if (close) document.getElementById(close.dataset.closeDialog).close();
  const layer = e.target.closest("[data-layer]");
  if (layer) selectLayer(+layer.dataset.layer);
  const bit = e.target.closest("[data-bit]");
  if (bit) {
    receivedCode[+bit.dataset.bit] ^= 1;
    renderHamming();
  }
});
document.addEventListener("keydown", (e) => {
  if (
    e.key === "/" &&
    !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName) &&
    !$("dialog[open]")
  ) {
    e.preventDefault();
    location.hash = "traffic";
    navigate();
    $("#flow-search").focus();
  }
  const row = e.target.closest('[role="button"][data-flow]');
  if (row && (e.key === "Enter" || e.key === " ")) {
    e.preventDefault();
    inspectFlow(row.dataset.flow);
  }
});
$("#range-select").onchange = (e) => {
  state.range = e.target.value;
  state.pageNumber = 1;
  loadDashboard();
};
$("#pause-button").onclick = () => {
  state.paused = !state.paused;
  $("#pause-label").textContent = state.paused
    ? "Resume updates"
    : "Pause updates";
  $("#pause-button [data-icon]").innerHTML = icon(
    state.paused ? "play" : "pause",
  );
  $("#updated-label").textContent = state.paused
    ? "Dashboard updates paused"
    : "Refreshing…";
  if (!state.paused) loadDashboard();
};
$("#refresh-button").onclick = loadDashboard;
$$("[data-chart]").forEach(
  (b) =>
    (b.onclick = () => {
      state.chart = b.dataset.chart;
      $$("[data-chart]").forEach((x) => x.classList.toggle("active", x === b));
      if (state.data) renderTrafficChart();
    }),
);
$("#flow-search").oninput = (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.query = e.target.value;
    state.pageNumber = 1;
    loadFlows();
  }, 250);
};
for (const [id, key] of [
  ["protocol-filter", "protocol"],
  ["kind-filter", "kind"],
  ["sort-filter", "sort"],
])
  $("#" + id).onchange = (e) => {
    state[key] = e.target.value;
    state.pageNumber = 1;
    loadFlows();
  };
$("#prev-page").onclick = () => {
  if (state.pageNumber > 1) {
    state.pageNumber--;
    loadFlows();
  }
};
$("#next-page").onclick = () => {
  if (state.pageNumber < state.pages) {
    state.pageNumber++;
    loadFlows();
  }
};
$("#export-csv").onclick = () => {
  window.location.assign(`/api/export.csv?${flowParams()}`);
  toast("Exporting all matching flow records as CSV…");
};
$("#export-report").onclick = () => {
  window.location.assign(`/api/report.json?range=${state.range}`);
  toast("Exporting the selected range as a JSON report…");
};
$("#inspect-flagged").onclick = () => {
  state.kind = "flagged";
  state.query = "";
  state.protocol = "all";
  state.pageNumber = 1;
  $("#kind-filter").value = "flagged";
  $("#flow-search").value = "";
  $("#protocol-filter").value = "all";
  location.hash = "traffic";
};
$("#start-capture").onclick = () => captureAction("start");
$("#stop-capture").onclick = () => captureAction("stop");
$("#subnet-form").onsubmit = (e) => {
  e.preventDefault();
  calculateSubnet();
};
$("#calculate-error").onclick = calculateError;
$("#error-method").onchange = () => {
  const m = $("#error-method").value;
  $("#generator-field").hidden = m !== "crc";
  $("#error-input-label").textContent =
    m === "checksum"
      ? "Text (UTF-8)"
      : m === "hamming"
        ? "Four data bits"
        : "Data bits";
  $("#error-input").value =
    m === "checksum" ? "AegisNet" : m === "hamming" ? "1011" : "1101011011";
  $("#error-results").innerHTML = "";
  calculateError();
};
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (state.data) {
      renderTrafficChart();
      renderSecondary();
    }
  }, 120);
});
selectLayer(4);
navigate();
loadDashboard();
setInterval(() => {
  if (!state.paused && !document.hidden) loadDashboard();
}, 5000);

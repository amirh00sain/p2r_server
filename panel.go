package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// panelJSON is served at /api/stats for the dashboard's poller.
type panelJSON struct {
	Status        string           `json:"status"`
	Token         string           `json:"token"`
	Clients       int              `json:"clients"`
	Sessions      int              `json:"sessions"`
	RxBytes       uint64           `json:"rx_bytes"`
	TxBytes       uint64           `json:"tx_bytes"`
	Version       string           `json:"version"`
	UptimeSeconds int64            `json:"uptime_seconds"`
	ClientsList   []ClientSnapshot `json:"clients_list"`
	SessionsList  []SessionInfo    `json:"sessions_list"`
	Logs          []LogEntry       `json:"logs"`
	TokenPath     string           `json:"token_path"`
	RailwayPort   string           `json:"port"`
}

func (s *Server) snapshot() panelJSON {
	return panelJSON{
		Status:        "ONLINE",
		Token:         s.users.Primary(),
		Clients:       s.ActiveClients(),
		Sessions:      s.ActiveSessions(),
		RxBytes:       s.stats.RxBytes.Load(),
		TxBytes:       s.stats.TxBytes.Load(),
		Version:       s.cfg.Version,
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		ClientsList:   s.clientsSnapshot(),
		SessionsList:  s.sessionsSnapshot(),
		Logs:          s.log.History(),
		TokenPath:     s.users.Path(),
		RailwayPort:   s.cfg.Port,
	}
}

func (s *Server) sessionsSnapshot() []SessionInfo {
	s.clientsMu.RLock()
	conns := make([]*ClientConn, 0, len(s.clients))
	for c := range s.clients {
		conns = append(conns, c)
	}
	s.clientsMu.RUnlock()

	var out []SessionInfo
	for _, c := range conns {
		out = append(out, c.sessions.Snapshot()...)
	}
	return out
}

var startTime = time.Now()

// panelAuth wraps a dashboard handler with HTTP Basic auth (user "admin",
// password from PANEL_PASSWORD). An explicitly empty PANEL_PASSWORD disables
// the check — useful only on a trusted network.
func (s *Server) panelAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.CheckPanel(w, r) {
			return
		}
		next(w, r)
	}
}

// servePanel renders the dashboard HTML.
func (s *Server) servePanel(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(panelHTML))
}

// serveStats returns the JSON payload the panel polls every 2s.
func (s *Server) serveStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.snapshot())
}

// serveLogs streams live log entries over Server-Sent Events.
func (s *Server) serveLogs(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")

	// Seed the stream with recent history so a fresh browser has context.
	for _, e := range s.log.History() {
		writeSSE(w, e)
	}
	flusher.Flush()

	ch, unsub := s.log.Subscribe()
	defer unsub()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			writeSSE(w, e)
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = fmt.Fprintf(w, ": keep-alive\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, e LogEntry) {
	buf, err := json.Marshal(e)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(w, "data: %s\n\n", buf)
}

// serveRotate rotates the primary token from the panel (POST /api/rotate).
func (s *Server) serveRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Spider-Token") != s.users.Primary() && ExtractToken(r) != s.users.Primary() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	token, err := s.users.Rotate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Infof("token rotated; connected clients must reconnect with the new token")
	writeJSON(w, map[string]any{"ok": true, "token": token})
}

// serveToken exposes just the primary token for the panel's copy button.
func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"token": s.users.Primary()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// ----------------------------------------------------------------------------
// Dashboard HTML (no external framework, plain CSS + vanilla JS)
// ----------------------------------------------------------------------------

const panelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spider WSS Tunnel</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #121821; --line: #1e2733; --txt: #d7e1ec;
    --dim: #7f8ea3; --accent: #4dd08f; --warn: #f2b04c; --bad: #ef6a6a;
    --blue: #5aa9ff;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
    font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { display:flex; align-items:center; justify-content:space-between;
    gap:16px; padding:18px 24px; border-bottom:1px solid var(--line);
    background:linear-gradient(180deg,#121a24,#0d131b); flex-wrap:wrap; }
  h1 { margin:0; font-size:18px; letter-spacing:.5px; }
  h1 span { color:var(--accent); }
  .status { display:inline-flex; align-items:center; gap:8px; padding:4px 12px;
    border:1px solid var(--line); border-radius:999px; background:#0e141c; }
  .dot { width:9px; height:9px; border-radius:50%; background:var(--accent);
    box-shadow:0 0 10px var(--accent); animation:pulse 2s infinite; }
  .dot.off { background:var(--bad); box-shadow:0 0 10px var(--bad); animation:none; }
  @keyframes pulse { 50% { opacity:.45; } }
  main { padding:24px; max-width:1180px; margin:0 auto; display:grid;
    grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:18px; }
  .card { background:var(--panel); border:1px solid var(--line);
    border-radius:10px; padding:18px; }
  .card h2 { margin:0 0 14px; font-size:12px; letter-spacing:1.4px;
    text-transform:uppercase; color:var(--dim); font-weight:600; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:14px; }
  .metric .k { color:var(--dim); font-size:11px; text-transform:uppercase; letter-spacing:1px; }
  .metric .v { font-size:22px; margin-top:4px; }
  .token { display:flex; gap:8px; align-items:center; }
  .token code { flex:1; background:#0d131b; border:1px solid var(--line);
    padding:9px 11px; border-radius:6px; overflow:auto; white-space:nowrap;
    color:var(--blue); }
  button { background:#182231; color:var(--txt); border:1px solid var(--line);
    padding:9px 14px; border-radius:6px; cursor:pointer; font:inherit; }
  button:hover { background:#1f2c3f; border-color:var(--blue); }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th { text-align:left; color:var(--dim); font-weight:600; font-size:11px;
    text-transform:uppercase; letter-spacing:1px; padding:6px 8px;
    border-bottom:1px solid var(--line); }
  td { padding:7px 8px; border-bottom:1px solid #171f2a; }
  td.r, th.r { text-align:right; }
  .empty { color:var(--dim); font-style:italic; padding:8px 0; }
  .logs { background:#0a0e13; border:1px solid var(--line); border-radius:8px;
    height:300px; overflow:auto; padding:10px 12px; font-size:12.5px; }
  .logline { white-space:pre-wrap; word-break:break-word; margin:1px 0; }
  .t { color:var(--dim); } .lvl-INFO { color:#8fb8e8; }
  .lvl-WARN { color:var(--warn); } .lvl-ERROR { color:var(--bad); }
  .lvl-DEBUG { color:#66788c; }
  footer { text-align:center; color:var(--dim); padding:18px; font-size:12px; }
  .span2 { grid-column:1 / -1; }
  .hint { color:var(--dim); font-size:12px; margin-top:8px; }
</style>
</head>
<body>
<header>
  <h1><span>&#128375;</span> Spider WSS Tunnel</h1>
  <div class="status"><span class="dot" id="dot"></span><span id="status">CONNECTING…</span></div>
</header>
<main>
  <div class="card">
    <h2>Server token</h2>
    <div class="token"><code id="token">…</code><button id="copy">Copy</button></div>
    <div class="hint">Client config: <b>"token": "…"</b> &mdash; WSS URL ends with <code>/ws?token=…</code></div>
  </div>

  <div class="card">
    <h2>Overview</h2>
    <div class="grid">
      <div class="metric"><div class="k">Connected clients</div><div class="v" id="clients">0</div></div>
      <div class="metric"><div class="k">Active sessions</div><div class="v" id="sessions">0</div></div>
      <div class="metric"><div class="k">RX</div><div class="v" id="rx">0 B</div></div>
      <div class="metric"><div class="k">TX</div><div class="v" id="tx">0 B</div></div>
      <div class="metric"><div class="k">Uptime</div><div class="v" id="uptime">0m</div></div>
      <div class="metric"><div class="k">Version</div><div class="v" id="version">–</div></div>
    </div>
  </div>

  <div class="card span2">
    <h2>Live sessions</h2>
    <table>
      <thead><tr><th>Session</th><th>Target</th><th>State</th>
        <th class="r">Up</th><th class="r">Down</th><th class="r">Age</th></tr></thead>
      <tbody id="sessbody"><tr><td colspan="6" class="empty">no active sessions</td></tr></tbody>
    </table>
  </div>

  <div class="card span2">
    <h2>Live logs</h2>
    <div class="logs" id="logs"></div>
  </div>
</main>
<footer id="foot">Spider WSS Tunnel</footer>
<script>
const $ = id => document.getElementById(id);
function human(n) {
  const u = ["B","KB","MB","GB","TB"]; let i = 0; let v = +n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(2)) + " " + u[i];
}
function uptime(sec) {
  const d = Math.floor(sec/86400), h = Math.floor(sec%86400/3600),
        m = Math.floor(sec%3600/60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  return m + "m";
}
let offline = false;
function render(d) {
  $("token").textContent = d.token || "–";
  $("clients").textContent = d.clients;
  $("sessions").textContent = d.sessions;
  $("rx").textContent = human(d.rx_bytes);
  $("tx").textContent = human(d.tx_bytes);
  $("uptime").textContent = uptime(d.uptime_seconds || 0);
  $("version").textContent = d.version || "–";
  $("status").textContent = (d.status || "ONLINE");
  $("dot").classList.toggle("off", d.status !== "ONLINE");

  const sb = $("sessbody");
  if (!d.sessions_list || !d.sessions_list.length) {
    sb.innerHTML = '<tr><td colspan="6" class="empty">no active sessions</td></tr>';
  } else {
    sb.innerHTML = d.sessions_list.map(s => {
      const up = s.udp ? "udp" : "tcp";
      return '<tr><td>#' + s.id + ' <span class="t">(' + up + ')</span></td>' +
        '<td>' + esc(s.target) + '</td><td>' + s.state + '</td>' +
        '<td class="r">' + human(s.bytes_up) + '</td>' +
        '<td class="r">' + human(s.bytes_down) + '</td>' +
        '<td class="r">' + (s.age_ms/1000).toFixed(0) + 's</td></tr>';
    }).join("");
  }
  $("foot").textContent = "Spider WSS Tunnel v" + (d.version || "?") +
    " · port " + (d.port || "?") + " · poll " + new Date().toLocaleTimeString();
}
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

async function poll() {
  try {
    const r = await fetch("/api/stats", {cache:"no-store"});
    if (!r.ok) throw new Error(r.status);
    render(await r.json());
    offline = false;
  } catch (e) {
    offline = true;
    $("status").textContent = "OFFLINE";
    $("dot").classList.add("off");
  }
}
poll();
setInterval(poll, 2000);

function appendLog(e) {
  const el = document.createElement("div");
  el.className = "logline";
  el.innerHTML = '<span class="t">[' + esc(e.time) + ']</span> ' +
    '<span class="lvl-' + esc(e.level) + '">' + esc(e.level) + '</span> ' + esc(e.message);
  const box = $("logs");
  box.appendChild(el);
  while (box.childNodes.length > 500) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}
try {
  const es = new EventSource("/api/logs");
  es.onmessage = ev => { try { appendLog(JSON.parse(ev.data)); } catch (_) {} };
} catch (_) {}

$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("token").textContent);
    $("copy").textContent = "Copied";
    setTimeout(() => $("copy").textContent = "Copy", 1200);
  } catch (_) {}
});
</script>
</body>
</html>
`

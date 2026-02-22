// Package api provides an HTTP REST + SSE dashboard alongside the TUI.
// Enable with --api flag. Available at http://localhost:<port>
package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/meetsoni15/deadair/internal/target"
)

// Server is the HTTP dashboard server.
type Server struct {
	Table  *target.Table
	Iface  string
	Port   int
	start  time.Time
	events chan string // SSE broadcast channel
}

// NewServer creates an API server (not yet started).
func NewServer(tbl *target.Table, iface string, port int) *Server {
	return &Server{
		Table:  tbl,
		Iface:  iface,
		Port:   port,
		start:  time.Now(),
		events: make(chan string, 64),
	}
}

// Start launches the HTTP server in a background goroutine.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/targets", s.handleTargets)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/events", s.handleSSE)

	go func() {
		addr := fmt.Sprintf(":%d", s.Port)
		_ = http.ListenAndServe(addr, mux)
	}()
}

// Broadcast sends a message to all connected SSE clients.
func (s *Server) Broadcast(msg string) {
	select {
	case s.events <- msg:
	default:
	}
}

// --- Handlers ---

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, indexHTML)
}

func (s *Server) handleTargets(w http.ResponseWriter, _ *http.Request) {
	type apJSON struct {
		BSSID   string   `json:"bssid"`
		SSID    string   `json:"ssid"`
		Channel int      `json:"channel"`
		RSSI    int8     `json:"rssi_dbm"`
		Signal  string   `json:"signal"`
		Clients []string `json:"clients"`
		Deauths int      `json:"deauths"`
	}
	aps := s.Table.All()
	out := make([]apJSON, len(aps))
	for i, ap := range aps {
		clients := make([]string, len(ap.Clients))
		for j, c := range ap.Clients {
			clients[j] = c.String()
		}
		out[i] = apJSON{
			BSSID:   ap.BSSID.String(),
			SSID:    ap.SSID,
			Channel: ap.Channel,
			RSSI:    ap.RSSI,
			Signal:  ap.SignalBar(),
			Clients: clients,
			Deauths: ap.Deauths,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	uptime := time.Since(s.start).Round(time.Second)
	stats := map[string]interface{}{
		"iface":         s.Iface,
		"ap_count":      s.Table.Count(),
		"total_deauths": s.Table.TotalDeauths(),
		"uptime_sec":    int(uptime.Seconds()),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send current state immediately
	s.writeTargetsSSE(w, flusher)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			s.writeTargetsSSE(w, flusher)
		case msg := <-s.events:
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) writeTargetsSSE(w http.ResponseWriter, flusher http.Flusher) {
	type row struct {
		BSSID   string `json:"bssid"`
		SSID    string `json:"ssid"`
		Signal  string `json:"signal"`
		Clients int    `json:"clients"`
		Deauths int    `json:"deauths"`
	}
	aps := s.Table.All()
	rows := make([]row, len(aps))
	for i, ap := range aps {
		rows[i] = row{
			BSSID:   ap.BSSID.String(),
			SSID:    ap.SSID,
			Signal:  ap.SignalBar(),
			Clients: len(ap.Clients),
			Deauths: ap.Deauths,
		}
	}
	data, _ := json.Marshal(rows)
	fmt.Fprintf(w, "event: targets\ndata: %s\n\n", data)
	flusher.Flush()
}

// Dummy net import use
var _ = net.ParseMAC

const indexHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>deadair dashboard</title>
<style>
body { background:#111; color:#eee; font-family:monospace; padding:1rem; }
h1 { color:#4DD9FF; }
table { border-collapse:collapse; width:100%; }
th { color:#999; text-align:left; padding:4px 8px; border-bottom:1px solid #333; }
td { padding:4px 8px; }
tr:nth-child(even) { background:#1a1a1a; }
.signal { color:#B04DFF; }
.deauths { color:#FF4D4D; font-weight:bold; }
#log { color:#555; font-size:0.85em; margin-top:1rem; max-height:200px; overflow:auto; }
</style>
</head>
<body>
<h1>⚡ deadair</h1>
<div id="stats"></div>
<table id="tbl">
<thead><tr><th>BSSID</th><th>SSID</th><th>Signal</th><th>Clients</th><th>Deauths</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<div id="log"><b>Event log:</b><br></div>
<script>
const es = new EventSource('/events');
es.addEventListener('targets', e => {
  const data = JSON.parse(e.data);
  const rows = document.getElementById('rows');
  rows.innerHTML = data.map(r =>
    '<tr><td>'+r.bssid+'</td><td>'+r.ssid+'</td><td class="signal">'+r.signal+'</td><td>'+r.clients+'</td><td class="deauths">'+r.deauths+'</td></tr>'
  ).join('');
});
es.addEventListener('log', e => {
  const log = document.getElementById('log');
  log.innerHTML += e.data + '<br>';
  log.scrollTop = log.scrollHeight;
});
fetch('/api/stats').then(r=>r.json()).then(d=>{
  document.getElementById('stats').innerHTML =
    'Interface: <b>'+d.iface+'</b> | APs: <b>'+d.ap_count+'</b> | Deauths: <b>'+d.total_deauths+'</b>';
});
</script>
</body>
</html>`

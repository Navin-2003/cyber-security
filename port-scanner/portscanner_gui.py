#!/usr/bin/env python3
"""
Scanner GUI — Advanced Port Scanner with Web Interface
Run:  python3 portscanner_gui.py
Then open: http://localhost:7331
"""

import sys, os, socket, time, json, threading, re, csv, io
from queue import Queue, Empty
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import webbrowser, uuid
from typing import Dict, List, Optional

# ─── Port DB ──────────────────────────────────────────────────────────────────
PORT_DB: Dict[int, tuple] = {
    20:("FTP-DATA","File Transfer – Data"),21:("FTP","File Transfer Protocol"),
    22:("SSH","Secure Shell"),23:("TELNET","Telnet – UNENCRYPTED"),
    25:("SMTP","Simple Mail Transfer"),53:("DNS","Domain Name System"),
    67:("DHCP","DHCP Server"),68:("DHCP","DHCP Client"),
    69:("TFTP","Trivial File Transfer"),80:("HTTP","HyperText Transfer Protocol"),
    110:("POP3","Post Office Protocol v3"),111:("RPC","Remote Procedure Call"),
    123:("NTP","Network Time Protocol"),135:("MSRPC","Microsoft RPC"),
    137:("NETBIOS-NS","NetBIOS Name Service"),138:("NETBIOS-DGM","NetBIOS Datagram"),
    139:("NETBIOS-SSN","NetBIOS Session"),143:("IMAP","Internet Message Access"),
    161:("SNMP","Network Management"),194:("IRC","Internet Relay Chat"),
    389:("LDAP","Lightweight Directory Access"),443:("HTTPS","HTTP over TLS/SSL"),
    445:("SMB","Server Message Block"),465:("SMTPS","SMTP over TLS"),
    500:("ISAKMP","IPsec IKE / VPN"),514:("SYSLOG","Syslog Protocol"),
    587:("SUBMISSION","Mail Submission"),636:("LDAPS","LDAP over TLS"),
    873:("RSYNC","rsync File Sync"),902:("VMWARE","VMware ESXi"),
    993:("IMAPS","IMAP over TLS"),995:("POP3S","POP3 over TLS"),
    1080:("SOCKS","SOCKS Proxy"),1194:("OPENVPN","OpenVPN"),
    1433:("MSSQL","Microsoft SQL Server"),1521:("ORACLE","Oracle Database"),
    1723:("PPTP","Point-to-Point Tunneling"),1900:("UPNP","Universal Plug and Play"),
    2049:("NFS","Network File System"),2181:("ZOOKEEPER","Apache ZooKeeper"),
    2375:("DOCKER","Docker Daemon – UNAUTHENTICATED"),2376:("DOCKER-TLS","Docker TLS"),
    3000:("DEV-HTTP","Dev HTTP (Node/React)"),3306:("MYSQL","MySQL Database"),
    3389:("RDP","Remote Desktop Protocol"),3690:("SVN","Subversion"),
    4444:("METERPRETER","Metasploit / backdoor"),4848:("GLASSFISH","GlassFish Admin"),
    5000:("DEV-HTTP","Dev HTTP (Flask)"),5432:("POSTGRESQL","PostgreSQL"),
    5672:("AMQP","RabbitMQ AMQP"),5900:("VNC","Virtual Network Computing"),
    5984:("COUCHDB","Apache CouchDB"),6379:("REDIS","Redis – often NO AUTH"),
    6443:("K8S-API","Kubernetes API"),7001:("WEBLOGIC","Oracle WebLogic"),
    7474:("NEO4J","Neo4j Graph Database"),8000:("HTTP-ALT","HTTP Alternative"),
    8080:("HTTP-PROXY","HTTP Proxy / Dev"),8086:("INFLUXDB","InfluxDB HTTP"),
    8161:("ACTIVEMQ","ActiveMQ Console"),8443:("HTTPS-ALT","HTTPS Alternative"),
    8500:("CONSUL","HashiCorp Consul"),8888:("JUPYTER","Jupyter Notebook"),
    9000:("PHP-FPM","PHP-FPM / SonarQube"),9090:("PROMETHEUS","Prometheus"),
    9092:("KAFKA","Apache Kafka"),9200:("ELASTICSEARCH","Elasticsearch HTTP"),
    9300:("ELASTICSEARCH","ES Transport"),9418:("GIT","Git Protocol"),
    10250:("KUBELET","Kubernetes Kubelet"),11211:("MEMCACHED","Memcached – NO AUTH"),
    15672:("RABBITMQ-WEB","RabbitMQ Management"),
    27017:("MONGODB","MongoDB – often NO AUTH"),27018:("MONGODB","MongoDB Shard"),
    28017:("MONGODB-HTTP","MongoDB HTTP"),
}
HIGH_RISK   = {21,23,135,137,138,139,445,1433,2375,3389,4444,5900,6379,11211,27017,9200}
MEDIUM_RISK = {22,25,53,80,110,143,161,3306,5432,8080,8161,8888,9090}
PRESET_RANGES: Dict[str, List[int]] = {
    "top-100":  sorted(PORT_DB.keys()),
    "top-1000": list(range(1,1025)),
    "web":      [80,443,8000,8008,8080,8088,8443,8888,3000,4000,5000,9000],
    "database": [1433,1521,3306,5432,6379,7474,9200,9300,11211,27017,27018,5984],
    "infra":    [22,23,25,53,67,111,123,135,161,389,445,514,636,873,2049],
    "full":     list(range(1,65536)),
}

# ─── Scanner core ─────────────────────────────────────────────────────────────
def resolve_host(h):
    try: return socket.gethostbyname(h)
    except: return None

def reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return ip

def tcp_connect(ip, port, timeout):
    t0=time.perf_counter()
    try:
        with socket.create_connection((ip,port),timeout=timeout): pass
        return True,(time.perf_counter()-t0)*1000
    except: return False,(time.perf_counter()-t0)*1000

def grab_banner(ip, port, timeout=2.0):
    for probe in [b"HEAD / HTTP/1.0\r\n\r\n",b"\r\n",b""]:
        try:
            with socket.create_connection((ip,port),timeout=timeout) as s:
                if probe: s.sendall(probe)
                data=s.recv(512)
                text=data.decode("utf-8",errors="replace").strip()
                line=next((l.strip() for l in text.splitlines() if l.strip()),"")
                return line[:80] if line else ""
        except: continue
    return ""

def parse_port_spec(spec):
    ports=set()
    for part in spec.split(","):
        part=part.strip()
        if "-" in part:
            a,b=part.split("-",1); ports.update(range(int(a),int(b)+1))
        else:
            try: ports.add(int(part))
            except: pass
    return sorted(p for p in ports if 1<=p<=65535)

# ─── Scan session state ───────────────────────────────────────────────────────
scans: Dict[str, dict] = {}

def run_scan(scan_id: str):
    s = scans[scan_id]
    ip       = s["ip"]
    ports    = s["ports"]
    timeout  = s["timeout"]
    workers  = s["workers"]
    do_ban   = s["banners"]

    q: Queue = Queue()
    for p in ports: q.put(p)
    s["total"]   = len(ports)
    s["done"]    = 0
    s["open"]    = []
    s["status"]  = "running"
    s["start"]   = time.time()

    lock = threading.Lock()

    def worker():
        while True:
            try: port = q.get_nowait()
            except Empty: break
            open_, lat = tcp_connect(ip, port, timeout)
            if open_:
                svc, desc = PORT_DB.get(port, ("UNKNOWN","—"))
                banner = grab_banner(ip, port, timeout) if do_ban else ""
                risk = "HIGH" if port in HIGH_RISK else ("MED" if port in MEDIUM_RISK else "LOW")
                entry = {"port":port,"service":svc,"description":desc,
                         "risk":risk,"banner":banner,"latency":round(lat,1)}
                with lock:
                    s["open"].append(entry)
                    s["events"].append(("port", entry))
            with lock:
                s["done"] += 1
                pct = s["done"] / s["total"] * 100
                s["events"].append(("progress", {"done":s["done"],"total":s["total"],"pct":round(pct,1)}))

    threads=[threading.Thread(target=worker,daemon=True)
             for _ in range(min(workers, len(ports)))]
    for t in threads: t.start()
    for t in threads: t.join()

    s["end"]    = time.time()
    s["status"] = "done"
    s["events"].append(("done", {"open": len(s["open"]), "duration": round(s["end"]-s["start"],2)}))

# ─── HTML Frontend ────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scanner — Advanced Port Scanner</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;600;700&display=swap');

:root{
  --bg:#080c14;--bg2:#0d1320;--bg3:#111827;
  --teal:#00f5d4;--pink:#f15bb5;--yellow:#fee440;--cyan:#00bbf9;
  --red:#ff006e;--green:#57ff64;--white:#e6e6ff;--gray:#646496;--lgray:#a0a0c8;
  --card:#111827;--border:#1e2d45;
}
*{margin:0;padding:0;box-sizing:border-box;}
html,body{height:100%;background:var(--bg);color:var(--white);font-family:'Rajdhani',sans-serif;overflow-x:hidden;}

/* Scanline overlay */
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,245,212,.015) 2px,rgba(0,245,212,.015) 4px);pointer-events:none;z-index:999;}

/* Grid noise background */
body::after{content:'';position:fixed;inset:0;background-image:radial-gradient(circle at 20% 50%,rgba(0,245,212,.05) 0%,transparent 50%),radial-gradient(circle at 80% 20%,rgba(241,91,181,.05) 0%,transparent 40%);pointer-events:none;}

/* ── Layout ── */
.shell{display:grid;grid-template-rows:auto 1fr;min-height:100vh;}

header{
  padding:20px 32px 16px;
  border-bottom:1px solid var(--border);
  background:rgba(8,12,20,.9);
  backdrop-filter:blur(12px);
  display:flex;align-items:center;gap:24px;
  position:sticky;top:0;z-index:100;
}
.logo{
  font-family:'Share Tech Mono',monospace;
  font-size:1.25rem;color:var(--teal);letter-spacing:.15em;
  text-shadow:0 0 20px rgba(0,245,212,.5);
}
.logo span{color:var(--pink);}
.tagline{font-size:.85rem;color:var(--gray);letter-spacing:.1em;margin-left:auto;}

main{display:grid;grid-template-columns:360px 1fr;gap:0;overflow:hidden;}

/* ── Sidebar ── */
aside{
  background:var(--bg2);
  border-right:1px solid var(--border);
  padding:24px 20px;
  overflow-y:auto;
  display:flex;flex-direction:column;gap:20px;
}
.section-label{
  font-size:.7rem;letter-spacing:.18em;color:var(--teal);
  text-transform:uppercase;margin-bottom:10px;
  display:flex;align-items:center;gap:8px;
}
.section-label::after{content:'';flex:1;height:1px;background:var(--border);}

label{display:block;font-size:.8rem;color:var(--lgray);letter-spacing:.08em;margin-bottom:5px;}
input[type=text],input[type=number],select{
  width:100%;background:var(--bg3);border:1px solid var(--border);
  color:var(--white);padding:9px 12px;border-radius:4px;
  font-family:'Share Tech Mono',monospace;font-size:.85rem;
  outline:none;transition:border-color .2s,box-shadow .2s;
}
input:focus,select:focus{border-color:var(--teal);box-shadow:0 0 0 2px rgba(0,245,212,.15);}
select option{background:var(--bg3);}

.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}

.toggle-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;}
.toggle-label{font-size:.85rem;color:var(--lgray);}
.toggle{position:relative;width:40px;height:22px;cursor:pointer;}
.toggle input{opacity:0;width:0;height:0;}
.slider{position:absolute;inset:0;background:#1e2d45;border-radius:22px;transition:.3s;}
.slider::before{content:'';position:absolute;height:16px;width:16px;left:3px;bottom:3px;background:var(--gray);border-radius:50%;transition:.3s;}
.toggle input:checked+.slider{background:rgba(0,245,212,.2);border:1px solid var(--teal);}
.toggle input:checked+.slider::before{transform:translateX(18px);background:var(--teal);}

.btn{
  width:100%;padding:12px;border:none;border-radius:4px;cursor:pointer;
  font-family:'Rajdhani',sans-serif;font-size:1rem;font-weight:700;
  letter-spacing:.12em;text-transform:uppercase;transition:all .2s;
}
.btn-scan{
  background:linear-gradient(135deg,var(--teal),#00c4aa);
  color:var(--bg);
  box-shadow:0 4px 20px rgba(0,245,212,.25);
}
.btn-scan:hover{box-shadow:0 4px 30px rgba(0,245,212,.45);transform:translateY(-1px);}
.btn-scan:active{transform:translateY(0);}
.btn-scan:disabled{opacity:.4;cursor:not-allowed;transform:none;}
.btn-stop{background:rgba(255,0,110,.15);color:var(--red);border:1px solid var(--red);}
.btn-stop:hover{background:rgba(255,0,110,.25);}

/* ── Main panel ── */
.panel{display:flex;flex-direction:column;overflow:hidden;}

/* Status bar */
.statusbar{
  padding:14px 24px;
  background:var(--bg2);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:20px;flex-wrap:wrap;
}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--gray);flex-shrink:0;}
.status-dot.running{background:var(--teal);box-shadow:0 0 8px var(--teal);animation:pulse 1s infinite;}
.status-dot.done{background:var(--green);box-shadow:0 0 8px var(--green);}
.status-dot.error{background:var(--red);}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:.4;}}
.status-text{font-size:.85rem;color:var(--lgray);font-family:'Share Tech Mono',monospace;}
.stat-chip{
  padding:3px 10px;border-radius:3px;
  font-size:.75rem;font-family:'Share Tech Mono',monospace;
  background:var(--bg3);border:1px solid var(--border);
}
.stat-chip b{color:var(--teal);}

/* Progress */
.progress-wrap{padding:12px 24px;background:var(--bg2);border-bottom:1px solid var(--border);}
.prog-bar{height:4px;background:var(--border);border-radius:2px;overflow:hidden;}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--teal),var(--cyan));border-radius:2px;transition:width .3s;width:0%;}
.prog-label{display:flex;justify-content:space-between;margin-top:5px;font-size:.75rem;color:var(--gray);font-family:'Share Tech Mono',monospace;}

/* Results */
.results-wrap{flex:1;overflow-y:auto;padding:0;}
.results-header{
  padding:12px 24px;
  display:flex;align-items:center;gap:12px;flex-wrap:wrap;
  border-bottom:1px solid var(--border);
  background:var(--bg);
  position:sticky;top:0;z-index:10;
}
.results-title{font-size:.9rem;font-weight:700;color:var(--yellow);letter-spacing:.1em;text-transform:uppercase;}
.filter-input{
  margin-left:auto;padding:5px 10px;width:180px;
  background:var(--bg3);border:1px solid var(--border);
  color:var(--white);font-family:'Share Tech Mono',monospace;font-size:.8rem;
  border-radius:4px;outline:none;
}
.filter-input:focus{border-color:var(--teal);}
.btn-sm{
  padding:5px 12px;font-size:.75rem;border-radius:3px;cursor:pointer;
  font-family:'Rajdhani',sans-serif;font-weight:700;letter-spacing:.1em;
  text-transform:uppercase;border:none;transition:all .2s;
}
.btn-json{background:rgba(0,187,249,.15);color:var(--cyan);border:1px solid var(--cyan);}
.btn-csv{background:rgba(254,228,64,.15);color:var(--yellow);border:1px solid var(--yellow);}
.btn-txt{background:rgba(160,160,200,.1);color:var(--lgray);border:1px solid var(--gray);}
.btn-sm:hover{filter:brightness(1.3);}
.btn-sm:disabled{opacity:.3;cursor:not-allowed;}

/* Table */
table{width:100%;border-collapse:collapse;font-size:.85rem;}
thead{position:sticky;top:0;z-index:5;}
th{
  padding:10px 14px;text-align:left;
  font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;
  color:var(--gray);background:var(--bg2);border-bottom:1px solid var(--border);
  white-space:nowrap;
}
td{padding:10px 14px;border-bottom:1px solid rgba(30,45,69,.5);vertical-align:middle;}
tbody tr{transition:background .15s;}
tbody tr:hover{background:rgba(0,245,212,.04);}
tbody tr.high{background:rgba(255,0,110,.04);}
tbody tr.high:hover{background:rgba(255,0,110,.08);}

.port-num{font-family:'Share Tech Mono',monospace;color:var(--teal);font-weight:bold;font-size:.9rem;}
.svc{font-weight:700;color:var(--white);}
.svc.high{color:var(--red);}
.risk-badge{
  display:inline-block;padding:2px 8px;border-radius:3px;
  font-size:.72rem;font-family:'Share Tech Mono',monospace;font-weight:bold;letter-spacing:.08em;
}
.risk-HIGH{background:rgba(255,0,110,.15);color:var(--red);border:1px solid rgba(255,0,110,.3);}
.risk-MED{background:rgba(254,228,64,.12);color:var(--yellow);border:1px solid rgba(254,228,64,.3);}
.risk-LOW{background:rgba(0,187,249,.1);color:var(--cyan);border:1px solid rgba(0,187,249,.2);}
.lat{font-family:'Share Tech Mono',monospace;color:var(--gray);font-size:.8rem;}
.banner{color:var(--lgray);font-family:'Share Tech Mono',monospace;font-size:.78rem;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

/* Empty state */
.empty-state{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  height:100%;min-height:300px;color:var(--gray);gap:12px;
}
.empty-icon{font-size:3rem;opacity:.3;}
.empty-text{font-size:.9rem;letter-spacing:.1em;text-transform:uppercase;}
.empty-sub{font-size:.8rem;color:var(--border);}

/* Summary cards */
.summary-cards{
  display:grid;grid-template-columns:repeat(4,1fr);gap:1px;
  background:var(--border);border-top:1px solid var(--border);
}
.card{
  background:var(--bg2);padding:16px 20px;text-align:center;
}
.card-val{font-size:1.8rem;font-weight:700;font-family:'Share Tech Mono',monospace;line-height:1;}
.card-lbl{font-size:.7rem;letter-spacing:.12em;text-transform:uppercase;color:var(--gray);margin-top:4px;}
.card.open .card-val{color:var(--green);}
.card.high .card-val{color:var(--red);}
.card.time .card-val{color:var(--yellow);}
.card.rate .card-val{color:var(--cyan);}

/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
::-webkit-scrollbar-thumb:hover{background:var(--gray);}

/* Responsive */
@media(max-width:900px){
  main{grid-template-columns:1fr;}
  aside{border-right:none;border-bottom:1px solid var(--border);}
}
</style>
</head>
<body>
<div class="shell">

<header>
  <div class="logo">░ SCAN<span>NER</span></div>
  <div style="font-family:'Share Tech Mono',monospace;font-size:.75rem;color:var(--teal);opacity:.6;">v2.0</div>
  <div class="tagline">Advanced Network Port Scanner</div>
</header>

<main>
<!-- ── Sidebar ── -->
<aside>
  <div>
    <div class="section-label">Target</div>
    <label>Hostname or IP Address</label>
    <input type="text" id="target" placeholder="192.168.1.1 or example.com" spellcheck="false">
  </div>

  <div>
    <div class="section-label">Port Range</div>
    <label>Preset</label>
    <select id="preset" onchange="onPresetChange()">
      <option value="top-100">top-100 — Known services (fastest)</option>
      <option value="top-1000">top-1000 — IANA standard (1–1024)</option>
      <option value="web">web — HTTP/HTTPS + dev servers</option>
      <option value="database">database — SQL, NoSQL, caches</option>
      <option value="infra">infra — SSH, DNS, SNMP, LDAP…</option>
      <option value="full">full — All 65,535 ports (slow)</option>
      <option value="custom">custom — Enter ports manually</option>
    </select>
    <div id="custom-ports-wrap" style="margin-top:10px;display:none;">
      <label>Custom ports (e.g. 22,80,443,8000-9000)</label>
      <input type="text" id="custom-ports" placeholder="22,80,443,8000-9000">
    </div>
  </div>

  <div>
    <div class="section-label">Options</div>
    <div class="row2">
      <div>
        <label>Timeout (sec)</label>
        <input type="number" id="timeout" value="1.0" min="0.1" max="10" step="0.1">
      </div>
      <div>
        <label>Workers</label>
        <input type="number" id="workers" value="300" min="10" max="1000">
      </div>
    </div>
    <div class="toggle-row">
      <span class="toggle-label">Banner grabbing</span>
      <label class="toggle">
        <input type="checkbox" id="banners" checked>
        <span class="slider"></span>
      </label>
    </div>
  </div>

  <div style="margin-top:auto;display:flex;flex-direction:column;gap:8px;">
    <button class="btn btn-scan" id="btn-scan" onclick="startScan()">▶ Start Scan</button>
    <button class="btn btn-stop" id="btn-stop" style="display:none" onclick="stopScan()">■ Stop</button>
  </div>
</aside>

<!-- ── Main panel ── -->
<div class="panel">
  <div class="statusbar">
    <div class="status-dot" id="status-dot"></div>
    <span class="status-text" id="status-text">Ready — configure target and press Start Scan</span>
    <div id="stat-chips" style="display:flex;gap:8px;flex-wrap:wrap;margin-left:auto;"></div>
  </div>

  <div class="progress-wrap" id="progress-wrap" style="display:none;">
    <div class="prog-bar"><div class="prog-fill" id="prog-fill"></div></div>
    <div class="prog-label">
      <span id="prog-text">0 / 0</span>
      <span id="prog-pct">0%</span>
    </div>
  </div>

  <div class="results-header">
    <span class="results-title" id="results-title">Results</span>
    <input class="filter-input" id="filter" placeholder="Filter…" oninput="applyFilter()" style="display:none;">
    <div id="export-btns" style="display:flex;gap:6px;">
      <button class="btn-sm btn-json" id="btn-json" onclick="exportData('json')" disabled>JSON</button>
      <button class="btn-sm btn-csv"  id="btn-csv"  onclick="exportData('csv')"  disabled>CSV</button>
      <button class="btn-sm btn-txt"  id="btn-txt"  onclick="exportData('txt')"  disabled>TXT</button>
    </div>
  </div>

  <div style="flex:1;overflow-y:auto;" id="results-scroll">
    <div class="empty-state" id="empty-state">
      <div class="empty-icon">◈</div>
      <div class="empty-text">No scan running</div>
      <div class="empty-sub">Enter a target and press Start Scan</div>
    </div>
    <table id="results-table" style="display:none;">
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>Risk</th>
          <th>Latency</th>
          <th>Banner / Description</th>
        </tr>
      </thead>
      <tbody id="results-body"></tbody>
    </table>
  </div>

  <div class="summary-cards" id="summary-cards" style="display:none;">
    <div class="card open"><div class="card-val" id="s-open">0</div><div class="card-lbl">Open Ports</div></div>
    <div class="card high"><div class="card-val" id="s-high">0</div><div class="card-lbl">High Risk</div></div>
    <div class="card time"><div class="card-val" id="s-time">—</div><div class="card-lbl">Duration</div></div>
    <div class="card rate"><div class="card-val" id="s-rate">—</div><div class="card-lbl">Ports/sec</div></div>
  </div>
</div>
</main>

</div>

<script>
let currentScanId = null;
let es = null;
let allResults = [];
let scanMeta = {};
let scanning = false;
let stopped = false;

function onPresetChange(){
  const v = document.getElementById('preset').value;
  document.getElementById('custom-ports-wrap').style.display = v==='custom' ? 'block' : 'none';
}

function setStatus(msg, state='idle'){
  document.getElementById('status-text').textContent = msg;
  const dot = document.getElementById('status-dot');
  dot.className = 'status-dot' + (state ? ' '+state : '');
}

function setChips(chips){
  const el = document.getElementById('stat-chips');
  el.innerHTML = chips.map(([lbl,val]) =>
    `<span class="stat-chip">${lbl}: <b>${val}</b></span>`
  ).join('');
}

async function startScan(){
  const target  = document.getElementById('target').value.trim();
  const preset  = document.getElementById('preset').value;
  const timeout = parseFloat(document.getElementById('timeout').value) || 1.0;
  const workers = parseInt(document.getElementById('workers').value) || 300;
  const banners = document.getElementById('banners').checked;
  const custom  = document.getElementById('custom-ports').value.trim();

  if(!target){ alert('Please enter a target.'); return; }

  // Reset UI
  allResults = []; scanMeta = {}; stopped = false;
  document.getElementById('results-body').innerHTML = '';
  document.getElementById('results-table').style.display = 'none';
  document.getElementById('empty-state').style.display = 'none';
  document.getElementById('summary-cards').style.display = 'none';
  document.getElementById('filter').style.display = 'none';
  document.getElementById('filter').value = '';
  document.getElementById('btn-json').disabled = true;
  document.getElementById('btn-csv').disabled  = true;
  document.getElementById('btn-txt').disabled  = true;
  document.getElementById('prog-fill').style.width = '0%';
  document.getElementById('prog-text').textContent = '0 / 0';
  document.getElementById('prog-pct').textContent  = '0%';

  setStatus('Resolving target…', 'running');
  document.getElementById('progress-wrap').style.display = 'block';
  document.getElementById('btn-scan').disabled = true;
  document.getElementById('btn-stop').style.display = 'block';
  scanning = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({target, preset, timeout, workers, banners,
                            custom: preset==='custom' ? custom : ''})
    });
    const data = await res.json();
    if(data.error){ setStatus('Error: '+data.error, 'error'); resetUI(); return; }
    currentScanId = data.scan_id;
    scanMeta = {target: data.target, ip: data.ip, total: data.total, startTime: Date.now()};

    setChips([['IP', data.ip], ['Ports', data.total.toLocaleString()], ['Workers', workers]]);
    setStatus(`Scanning ${data.ip} — ${data.total.toLocaleString()} ports`, 'running');
    document.getElementById('results-title').textContent = `Live Results — ${data.ip}`;

    // Stream events
    if(es) es.close();
    es = new EventSource(`/api/stream/${currentScanId}`);
    es.onmessage = handleEvent;
    es.onerror   = () => { if(scanning && !stopped) setStatus('Stream error', 'error'); };
  } catch(e){
    setStatus('Connection error: '+e.message, 'error');
    resetUI();
  }
}

function handleEvent(e){
  const msg = JSON.parse(e.data);
  if(msg.type === 'progress'){
    const d = msg.data;
    const pct = d.pct;
    document.getElementById('prog-fill').style.width = pct+'%';
    document.getElementById('prog-text').textContent  = `${d.done.toLocaleString()} / ${d.total.toLocaleString()}`;
    document.getElementById('prog-pct').textContent   = pct.toFixed(1)+'%';
  }
  else if(msg.type === 'port'){
    const p = msg.data;
    allResults.push(p);
    addRow(p);
    document.getElementById('results-table').style.display = 'table';
    document.getElementById('s-open').textContent = allResults.length;
    document.getElementById('s-high').textContent = allResults.filter(r=>r.risk==='HIGH').length;
    document.getElementById('summary-cards').style.display = 'grid';
    document.getElementById('filter').style.display = 'block';
  }
  else if(msg.type === 'done'){
    const d = msg.data;
    const dur = (d.duration).toFixed(2);
    const rate = Math.round((scanMeta.total||0) / (d.duration||1));
    document.getElementById('s-time').textContent = dur+'s';
    document.getElementById('s-rate').textContent = rate.toLocaleString()+'/s';
    setStatus(`Scan complete — ${d.open} open ports found in ${dur}s`, 'done');
    document.getElementById('prog-fill').style.width = '100%';
    document.getElementById('prog-text').textContent = `${scanMeta.total?.toLocaleString()} / ${scanMeta.total?.toLocaleString()}`;
    document.getElementById('prog-pct').textContent = '100%';
    if(allResults.length === 0){
      document.getElementById('empty-state').style.display = 'flex';
      document.getElementById('empty-state').querySelector('.empty-text').textContent = 'No open ports found';
      document.getElementById('empty-state').querySelector('.empty-sub').textContent = 'All scanned ports are closed or filtered';
    }
    document.getElementById('btn-json').disabled = false;
    document.getElementById('btn-csv').disabled  = false;
    document.getElementById('btn-txt').disabled  = false;
    es.close(); resetUI();
  }
}

function addRow(p){
  const tbody = document.getElementById('results-body');
  const tr = document.createElement('tr');
  tr.className = p.risk==='HIGH' ? 'high' : '';
  tr.dataset.port    = p.port;
  tr.dataset.service = p.service.toLowerCase();
  tr.dataset.banner  = (p.banner||p.description).toLowerCase();
  const svcClass = p.risk==='HIGH' ? 'svc high' : 'svc';
  const info = p.banner || `(${p.description})`;
  tr.innerHTML = `
    <td><span class="port-num">${p.port}</span></td>
    <td><span class="${svcClass}">${p.service}</span></td>
    <td><span class="risk-badge risk-${p.risk}">${p.risk==='MED'?'◆ MED':p.risk==='HIGH'?'▲ HIGH':'● LOW'}</span></td>
    <td><span class="lat">${p.latency}ms</span></td>
    <td><span class="banner" title="${escHtml(p.banner)}">${escHtml(info)}</span></td>`;
  tbody.insertBefore(tr, tbody.firstChild);
}

function applyFilter(){
  const q = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('#results-body tr').forEach(tr => {
    const match = !q || tr.dataset.port?.includes(q) || tr.dataset.service?.includes(q) || tr.dataset.banner?.includes(q);
    tr.style.display = match ? '' : 'none';
  });
}

function stopScan(){
  stopped = true;
  if(es) es.close();
  if(currentScanId) fetch(`/api/stop/${currentScanId}`, {method:'POST'});
  setStatus('Scan stopped by user', 'error');
  resetUI();
}

function resetUI(){
  scanning = false;
  document.getElementById('btn-scan').disabled = false;
  document.getElementById('btn-stop').style.display = 'none';
}

function escHtml(s){ return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

async function exportData(fmt){
  if(!currentScanId) return;
  const res = await fetch(`/api/export/${currentScanId}?fmt=${fmt}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const fn = res.headers.get('X-Filename') || `scan.${fmt}`;
  a.href=url; a.download=fn; a.click();
  URL.revokeObjectURL(url);
}
</script>
</body>
</html>
"""

# ─── HTTP Handler ─────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass   # silence logs

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path == "/":
            self._html(HTML)

        elif path.startswith("/api/stream/"):
            scan_id = path.split("/")[-1]
            self._sse_stream(scan_id)

        elif path.startswith("/api/export/"):
            scan_id = path.split("/")[-1]
            fmt = parse_qs(parsed.query).get("fmt", ["json"])[0]
            self._export(scan_id, fmt)

        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body   = json.loads(self.rfile.read(length))
            self._start_scan(body)

        elif path.startswith("/api/stop/"):
            scan_id = path.split("/")[-1]
            if scan_id in scans:
                scans[scan_id]["stopped"] = True
            self._json({"ok": True})

        else:
            self._json({"error": "not found"}, 404)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _html(self, content):
        b = content.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(b))
        self.end_headers()
        self.wfile.write(b)

    def _json(self, data, code=200):
        b = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(b))
        self.end_headers()
        self.wfile.write(b)

    def _start_scan(self, body):
        target  = body.get("target","").strip()
        preset  = body.get("preset","top-100")
        timeout = float(body.get("timeout",1.0))
        workers = int(body.get("workers",300))
        banners = bool(body.get("banners",True))
        custom  = body.get("custom","")

        ip = resolve_host(target)
        if not ip:
            self._json({"error": f"Cannot resolve '{target}'"}, 400); return

        hostname = reverse_dns(ip)
        if custom:
            ports = parse_port_spec(custom)
        else:
            ports = PRESET_RANGES.get(preset, PRESET_RANGES["top-100"])

        scan_id = str(uuid.uuid4())
        scans[scan_id] = {
            "target": target, "ip": ip, "hostname": hostname,
            "ports": ports, "timeout": timeout, "workers": workers,
            "banners": banners, "total": len(ports), "done": 0,
            "open": [], "events": [], "status": "pending", "stopped": False,
            "start": 0.0, "end": 0.0,
        }
        threading.Thread(target=run_scan, args=(scan_id,), daemon=True).start()
        self._json({"scan_id": scan_id, "ip": ip, "total": len(ports), "target": target})

    def _sse_stream(self, scan_id):
        if scan_id not in scans:
            self._json({"error":"not found"},404); return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        s     = scans[scan_id]
        sent  = 0
        while True:
            if s.get("stopped"):
                break
            events = s["events"]
            while sent < len(events):
                etype, edata = events[sent]
                msg = json.dumps({"type": etype, "data": edata})
                try:
                    self.wfile.write(f"data: {msg}\n\n".encode())
                    self.wfile.flush()
                except Exception:
                    return
                sent += 1
            if s["status"] == "done" and sent >= len(s["events"]):
                break
            time.sleep(0.05)

    def _export(self, scan_id, fmt):
        if scan_id not in scans:
            self._json({"error":"not found"},404); return
        s = scans[scan_id]
        open_ports = s.get("open", [])
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"scan_{s['ip']}_{ts}.{fmt}"

        if fmt == "json":
            data = {
                "target": s["target"], "ip": s["ip"], "hostname": s["hostname"],
                "scan_time": datetime.fromtimestamp(s["start"]).isoformat() if s["start"] else "",
                "duration_sec": round(s["end"]-s["start"],3) if s["end"] else 0,
                "total_ports": s["total"], "open_ports": open_ports,
            }
            content = json.dumps(data, indent=2).encode()
            ct = "application/json"
        elif fmt == "csv":
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=["port","service","description","risk","banner","latency"])
            w.writeheader()
            for r in sorted(open_ports, key=lambda x: x["port"]):
                w.writerow(r)
            content = buf.getvalue().encode()
            ct = "text/csv"
        else:
            lines = [f"Scanner v2.0  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                     f"Target: {s['target']}  ({s['ip']})", "─"*80,
                     f"{'PORT':>6}  {'SERVICE':<16}  {'RISK':<6}  BANNER / DESCRIPTION", "─"*80]
            for r in sorted(open_ports, key=lambda x: x["port"]):
                info = r.get("banner") or r.get("description","")
                lines.append(f"{r['port']:>6}/tcp  {r['service']:<16}  {r['risk']:<6}  {info}")
            content = "\n".join(lines).encode()
            ct = "text/plain"

        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", len(content))
        self.send_header("X-Filename", fname)
        self.end_headers()
        self.wfile.write(content)


# ─── Entry ────────────────────────────────────────────────────────────────────
def main():
    PORT = 7331
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    url = f"http://localhost:{PORT}"

    print(f"""
\033[38;2;0;245;212m\033[1m
  ╔═══════════════════════════════════════════╗
  ║  ░  SCANNER GUI  ─  Web Interface  ░     ║
  ╠═══════════════════════════════════════════╣
  ║\033[0m\033[38;2;254;228;64m  Server →  {url:<32}\033[38;2;0;245;212m\033[1m║
  ║\033[0m\033[38;2;160;160;200m  Opening browser automatically…          \033[38;2;0;245;212m\033[1m║
  ║\033[0m\033[38;2;100;100;140m  Press Ctrl+C to stop the server          \033[38;2;0;245;212m\033[1m║
  ╚═══════════════════════════════════════════╝\033[0m
""")
    threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[38;2;100;100;140m  Server stopped.\033[0m\n")
        server.shutdown()

if __name__ == "__main__":
    main()

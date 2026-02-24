#!/usr/bin/env python3
"""
┌────────────────────────────────────────────────────────────────────┐
│  ░░░ SCANNER  ░░   Advanced Network Port Scanner   v2.0            │
│  Zero-dependency · Fast · Beautiful · Feature-rich                 │
└────────────────────────────────────────────────────────────────────┘

Usage:
    python3 portscanner.py                          # interactive TUI
    python3 portscanner.py 192.168.1.1             # quick scan (top-100)
    python3 portscanner.py example.com --preset web
    python3 portscanner.py 10.0.0.1 --ports 22,80,443,8000-9000
    python3 portscanner.py target.io --preset full --workers 600 --export json

Requirements: Python 3.8+  (stdlib only — no pip install needed)
"""

import sys, os, socket, time, json, csv, threading, argparse, shutil, re
from queue import Queue, Empty
from datetime import datetime
from typing import Optional, List, Dict


# ─── ANSI Color Palette ───────────────────────────────────────────────────────
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    TEAL  = "\033[38;2;0;245;212m";  PINK   = "\033[38;2;241;91;181m"
    YELLOW= "\033[38;2;254;228;64m"; CYAN   = "\033[38;2;0;187;249m"
    RED   = "\033[38;2;255;0;110m";  WHITE  = "\033[38;2;230;230;255m"
    GRAY  = "\033[38;2;100;100;140m";LGRAY  = "\033[38;2;160;160;200m"
    ORANGE= "\033[38;2;255;140;0m";  GREEN  = "\033[38;2;57;255;100m"

def strip_ansi(s: str) -> str:
    return re.sub(r'\033\[[^m]*m', '', s)

def trunc(s: str, n: int) -> str:
    return (s[:n-1] + '…') if len(s) > n else s

def term_width() -> int:
    return shutil.get_terminal_size((100, 40)).columns

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# ─── Port/Service Database ────────────────────────────────────────────────────
PORT_DB: Dict[int, tuple] = {
    20:("FTP-DATA","File Transfer – Data"),21:("FTP","File Transfer Protocol"),
    22:("SSH","Secure Shell"),23:("TELNET","Telnet – UNENCRYPTED"),
    25:("SMTP","Simple Mail Transfer"),53:("DNS","Domain Name System"),
    67:("DHCP","DHCP Server"),68:("DHCP","DHCP Client"),
    69:("TFTP","Trivial File Transfer"),80:("HTTP","HyperText Transfer Protocol"),
    110:("POP3","Post Office Protocol v3"),111:("RPC","Remote Procedure Call"),
    119:("NNTP","Network News Transfer"),123:("NTP","Network Time Protocol"),
    135:("MSRPC","Microsoft RPC"),137:("NETBIOS-NS","NetBIOS Name Service"),
    138:("NETBIOS-DGM","NetBIOS Datagram"),139:("NETBIOS-SSN","NetBIOS Session"),
    143:("IMAP","Internet Message Access"),161:("SNMP","Network Management"),
    194:("IRC","Internet Relay Chat"),389:("LDAP","Lightweight Directory Access"),
    443:("HTTPS","HTTP over TLS/SSL"),445:("SMB","Server Message Block"),
    465:("SMTPS","SMTP over TLS"),500:("ISAKMP","IPsec IKE / VPN"),
    514:("SYSLOG","Syslog Protocol"),587:("SUBMISSION","Mail Submission Agent"),
    636:("LDAPS","LDAP over TLS"),873:("RSYNC","rsync File Sync"),
    902:("VMWARE","VMware ESXi"),993:("IMAPS","IMAP over TLS"),
    995:("POP3S","POP3 over TLS"),1080:("SOCKS","SOCKS Proxy"),
    1194:("OPENVPN","OpenVPN"),1433:("MSSQL","Microsoft SQL Server"),
    1521:("ORACLE","Oracle Database"),1723:("PPTP","Point-to-Point Tunneling"),
    1900:("UPNP","Universal Plug and Play"),2049:("NFS","Network File System"),
    2181:("ZOOKEEPER","Apache ZooKeeper"),
    2375:("DOCKER","Docker Daemon – UNAUTHENTICATED"),
    2376:("DOCKER-TLS","Docker Daemon TLS"),3000:("DEV-HTTP","Dev HTTP (Node/React)"),
    3306:("MYSQL","MySQL Database"),3389:("RDP","Remote Desktop Protocol"),
    3690:("SVN","Subversion"),4444:("METERPRETER","Metasploit/backdoor listener"),
    4848:("GLASSFISH","GlassFish Admin"),5000:("DEV-HTTP","Dev HTTP (Flask)"),
    5432:("POSTGRESQL","PostgreSQL Database"),5672:("AMQP","RabbitMQ AMQP"),
    5900:("VNC","Virtual Network Computing"),5984:("COUCHDB","Apache CouchDB"),
    6379:("REDIS","Redis – often NO AUTH"),6443:("K8S-API","Kubernetes API"),
    7001:("WEBLOGIC","Oracle WebLogic"),7474:("NEO4J","Neo4j Graph Database"),
    8000:("HTTP-ALT","HTTP Alternative"),8080:("HTTP-PROXY","HTTP Proxy/Dev"),
    8086:("INFLUXDB","InfluxDB HTTP API"),8161:("ACTIVEMQ","ActiveMQ Console"),
    8443:("HTTPS-ALT","HTTPS Alternative"),8500:("CONSUL","HashiCorp Consul"),
    8888:("JUPYTER","Jupyter Notebook"),9000:("PHP-FPM","PHP-FPM/SonarQube"),
    9090:("PROMETHEUS","Prometheus Metrics"),9092:("KAFKA","Apache Kafka"),
    9200:("ELASTICSEARCH","Elasticsearch HTTP"),9300:("ELASTICSEARCH","ES Transport"),
    9418:("GIT","Git Protocol"),10250:("KUBELET","Kubernetes Kubelet API"),
    11211:("MEMCACHED","Memcached – often NO AUTH"),
    15672:("RABBITMQ-WEB","RabbitMQ Management"),
    27017:("MONGODB","MongoDB – often NO AUTH"),27018:("MONGODB","MongoDB Shard"),
    28017:("MONGODB-HTTP","MongoDB HTTP Interface"),
}

HIGH_RISK   = {21,23,135,137,138,139,445,1433,2375,3389,4444,5900,6379,11211,27017,9200}
MEDIUM_RISK = {22,25,53,80,110,143,161,3306,5432,8080,8161,8888,9090}

PRESET_RANGES: Dict[str, List[int]] = {
    "top-100":  sorted(PORT_DB.keys()),
    "top-1000": list(range(1, 1025)),
    "web":      [80,443,8000,8008,8080,8088,8443,8888,3000,4000,5000,9000],
    "database": [1433,1521,3306,5432,6379,7474,9200,9300,11211,27017,27018,5984],
    "infra":    [22,23,25,53,67,111,123,135,161,389,445,514,636,873,2049],
    "full":     list(range(1, 65536)),
}

PRESET_DESC = {
    "top-100":"Known services + databases","top-1000":"IANA port space (1–1024)",
    "web":"HTTP/HTTPS + dev servers","database":"SQL, NoSQL, caches",
    "infra":"SSH, DNS, SNMP, LDAP, NFS…","full":"All 65,535 ports (slow!)",
}

# ─── Scan result ──────────────────────────────────────────────────────────────
class ScanResult:
    __slots__ = ("port","state","service","description","banner","risk","latency_ms")
    def __init__(self, port: int, state: str, latency_ms: float=0.0):
        self.port=port; self.state=state; self.latency_ms=latency_ms
        self.service, self.description = PORT_DB.get(port, ("UNKNOWN","—"))
        self.banner=""
        self.risk = "HIGH" if port in HIGH_RISK else ("MED" if port in MEDIUM_RISK else "LOW")

RISK_COLOR = {"HIGH": C.RED+C.BOLD, "MED": C.YELLOW+C.BOLD, "LOW": C.CYAN+C.BOLD}
RISK_BADGE = {"HIGH": "▲ HIGH", "MED": "◆ MED ", "LOW": "● LOW "}

def risk_badge(r: str) -> str:
    return RISK_COLOR.get(r,"") + RISK_BADGE.get(r,r) + C.RESET

# ─── Networking ───────────────────────────────────────────────────────────────
def resolve_host(host: str) -> Optional[str]:
    try: return socket.gethostbyname(host)
    except socket.gaierror: return None

def reverse_dns(ip: str) -> str:
    try: return socket.gethostbyaddr(ip)[0]
    except: return ip

def tcp_connect(ip: str, port: int, timeout: float):
    t0=time.perf_counter()
    try:
        with socket.create_connection((ip,port),timeout=timeout): pass
        return True, (time.perf_counter()-t0)*1000
    except: return False, (time.perf_counter()-t0)*1000

def grab_banner(ip: str, port: int, timeout: float=2.0) -> str:
    for probe in [b"HEAD / HTTP/1.0\r\n\r\n", b"\r\n", b""]:
        try:
            with socket.create_connection((ip,port),timeout=timeout) as s:
                if probe: s.sendall(probe)
                data=s.recv(512)
                text=data.decode("utf-8",errors="replace").strip()
                line=next((l.strip() for l in text.splitlines() if l.strip()),"")
                return line[:70] if line else ""
        except: continue
    return ""

# ─── Progress bar ─────────────────────────────────────────────────────────────
class ProgressBar:
    def __init__(self, total: int, label: str="Scanning"):
        self.total=total; self.label=label
        self._done=0; self._lock=threading.Lock()
        self._start=time.time()

    def advance(self, n: int=1):
        with self._lock:
            self._done+=n; self._render()

    def _render(self):
        done=self._done; total=self.total
        pct=done/total if total else 0
        elapsed=time.time()-self._start
        rate=done/elapsed if elapsed>0 else 0
        eta=(total-done)/rate if rate>0 and done<total else 0
        w=min(term_width(),90); bar_w=w-54
        filled=int(bar_w*pct)
        bar=(C.TEAL+C.BOLD+"█"*filled+C.RESET+C.GRAY+"░"*(bar_w-filled)+C.RESET)
        line=(f"  {C.TEAL}{C.BOLD}{self.label[:16]:<16}{C.RESET}  {bar}  "
              f"{C.YELLOW}{C.BOLD}{pct*100:5.1f}%{C.RESET}  "
              f"{C.GRAY}{done:>6,}/{total:,}  {rate:>7.0f}/s  ETA {eta:5.1f}s{C.RESET}")
        sys.stdout.write(f"\r{line}"); sys.stdout.flush()

    def finish(self):
        with self._lock: self._done=self.total; self._render()
        print()

# ─── Scanner ──────────────────────────────────────────────────────────────────
class Scanner:
    def __init__(self,target,ports,timeout=1.0,workers=300,grab_banners=True):
        self.target=target; self.ports=ports; self.timeout=timeout
        self.workers=workers; self.grab_banners=grab_banners
        self.ip=""; self.hostname=""
        self.results: List[ScanResult]=[]
        self.start_time=0.0; self.end_time=0.0

    def run(self) -> List[ScanResult]:
        self.start_time=time.time()
        pb=ProgressBar(len(self.ports), self.target)
        q: Queue=Queue()
        for p in self.ports: q.put(p)
        out=[]; lock=threading.Lock()

        def worker():
            while True:
                try: port=q.get_nowait()
                except Empty: break
                open_,lat=tcp_connect(self.ip,port,self.timeout)
                r=ScanResult(port,"open" if open_ else "closed",lat)
                if open_ and self.grab_banners: r.banner=grab_banner(self.ip,port,self.timeout)
                with lock: out.append(r)
                pb.advance()

        threads=[threading.Thread(target=worker,daemon=True) for _ in range(min(self.workers,len(self.ports)))]
        for t in threads: t.start()
        for t in threads: t.join()
        pb.finish()
        self.results=sorted(out,key=lambda r:r.port)
        self.end_time=time.time()
        return [r for r in self.results if r.state=="open"]

# ─── UI ───────────────────────────────────────────────────────────────────────
LOGO = f"""{C.TEAL}{C.BOLD}
  ╔════════════════════════════════════════════════════════════════════╗
  ║  ░   ░                                                         ░  ║
  ║     ███████   ██████  █████  ███  ██  ███  ██  ███████  ██████    ║
  ║     ██        ██      ██  ██ ████ ██  ████ ██  ██       ██  ██    ║
  ║     ███████   ██      ███████ ██ ████  ██ ████  █████    ██████   ║
  ║          ██   ██      ██  ██  ██  ███  ██  ███  ██       ██ ██    ║
  ║     ███████   ██████  ██  ██  ██   ██  ██   ██  ███████  ██  ██   ║
  ║  ░   ░                                                         ░  ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║{C.RESET}{C.GRAY}   Advanced Network Port Scanner  ·  v2.0  ·  Python stdlib only  {C.TEAL}{C.BOLD}║
  ╚════════════════════════════════════════════════════════════════════╝
{C.RESET}"""

def print_target_box(scanner: Scanner):
    rows=[
        ("TARGET",    scanner.target),
        ("IP",        scanner.ip),
    ]
    if scanner.hostname and scanner.hostname != scanner.ip:
        rows.append(("HOSTNAME", scanner.hostname))
    rows += [
        ("PORTS",    f"{len(scanner.ports):,} ports queued"),
        ("WORKERS",  f"{scanner.workers} concurrent threads"),
        ("TIMEOUT",  f"{scanner.timeout}s per connection"),
        ("BANNERS",  "enabled" if scanner.grab_banners else "disabled"),
    ]
    w=min(term_width(),70)
    print(f"\n  {C.TEAL}┌{'─'*(w-4)}┐{C.RESET}")
    for label,val in rows:
        line=f"  {C.TEAL}│{C.RESET}  {C.YELLOW}{C.BOLD}{label:<10}{C.RESET}  {C.WHITE}{val}{C.RESET}"
        pad=w-4-12-len(strip_ansi(val))
        print(f"{line}{' '*max(0,pad)}  {C.TEAL}│{C.RESET}")
    print(f"  {C.TEAL}└{'─'*(w-4)}┘{C.RESET}\n")

def print_results_table(open_ports: List[ScanResult]):
    if not open_ports:
        print(f"\n  {C.GRAY}  No open ports discovered.{C.RESET}\n"); return

    w=min(term_width(),110)
    CP,CS,CR,CL,CB=7,17,9,9,max(30,w-7-17-9-9-16)

    def cell(text,width,color="",align="left"):
        plain=strip_ansi(text)
        if len(plain)>width: text=text[:width-1]+"…"; plain=plain[:width-1]+"…"
        pad=width-len(plain)
        return (" "*pad if align=="right" else "")+color+text+C.RESET+(" "*pad if align=="left" else "")

    hdr=(f"  {C.YELLOW}{C.BOLD}{'PORT':>{CP}}  {'SERVICE':<{CS}}{'RISK':<{CR}}{'LATENCY':>{CL}}  {'BANNER / DESCRIPTION':<{CB}}{C.RESET}")
    sep=f"  {C.GRAY}{'─'*CP}  {'─'*CS}{'─'*CR}{'─'*CL}  {'─'*CB}{C.RESET}"

    print(f"\n  {C.TEAL}┌─ OPEN PORTS ── {len(open_ports)} found {'─'*(w-26)}┐{C.RESET}")
    print(hdr); print(sep)

    for r in open_ports:
        banner=r.banner if r.banner else f"({r.description})"
        sc=C.WHITE+C.BOLD if r.risk=="HIGH" else C.WHITE
        badge=risk_badge(r.risk)
        # badge has extra invisible chars; pad manually
        badge_plain=strip_ansi(badge)
        badge_pad=" "*(CR-len(badge_plain))
        row=(f"  {cell(str(r.port),CP,C.TEAL+C.BOLD,'right')}  "
             f"{cell(r.service,CS,sc)}"
             f"{badge}{badge_pad}"
             f"{cell(f'{r.latency_ms:.1f}ms',CL,C.GRAY,'right')}  "
             f"{cell(trunc(banner,CB),CB,C.LGRAY)}")
        if r.risk=="HIGH":
            print(f"\033[48;2;35;0;10m{row}{C.RESET}")
        else:
            print(row)

    print(f"  {C.TEAL}└{'─'*(w-4)}┘{C.RESET}\n")

def print_summary(scanner: Scanner, open_ports: List[ScanResult]):
    dur=scanner.end_time-scanner.start_time
    total=len(scanner.ports); n=len(open_ports)
    rate=total/dur if dur>0 else 0
    hc=sum(1 for r in open_ports if r.risk=="HIGH")
    mc=sum(1 for r in open_ports if r.risk=="MED")
    lc=sum(1 for r in open_ports if r.risk=="LOW")
    w=min(term_width(),90)
    print(f"  {C.PINK}┌─ SUMMARY {'─'*(w-13)}┐{C.RESET}")
    print(f"  {C.PINK}│{C.RESET}  "
          f"{C.TEAL}{C.BOLD}SCANNED{C.RESET} {C.WHITE}{total:>7,}{C.RESET}   "
          f"{C.TEAL}{C.BOLD}OPEN{C.RESET} {C.GREEN}{C.BOLD}{n:>4}{C.RESET}   "
          f"{C.TEAL}{C.BOLD}CLOSED{C.RESET} {C.GRAY}{total-n:>7,}{C.RESET}   "
          f"{C.TEAL}{C.BOLD}TIME{C.RESET} {C.YELLOW}{dur:>6.2f}s{C.RESET}   "
          f"{C.TEAL}{C.BOLD}RATE{C.RESET} {C.CYAN}{rate:>7,.0f}/s{C.RESET}"
          +(" "*8)+f"  {C.PINK}│{C.RESET}")
    if n:
        print(f"  {C.PINK}│{C.RESET}  "
              f"{C.RED}{C.BOLD}▲ HIGH-RISK{C.RESET} {hc:>3}   "
              f"{C.YELLOW}{C.BOLD}◆ MEDIUM{C.RESET}    {mc:>3}   "
              f"{C.CYAN}{C.BOLD}● LOW{C.RESET}       {lc:>3}"
              +(" "*28)+f"  {C.PINK}│{C.RESET}")
    print(f"  {C.PINK}└{'─'*(w-4)}┘{C.RESET}\n")

# ─── Export ───────────────────────────────────────────────────────────────────
def export_results(scanner: Scanner, open_ports: List[ScanResult], fmt: str) -> str:
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    fname=f"scan_{scanner.ip}_{ts}.{fmt}"
    if fmt=="json":
        data={"target":scanner.target,"ip":scanner.ip,"hostname":scanner.hostname,
              "scan_time":datetime.fromtimestamp(scanner.start_time).isoformat(),
              "duration_sec":round(scanner.end_time-scanner.start_time,3),
              "total_ports":len(scanner.ports),
              "open_ports":[{"port":r.port,"service":r.service,"description":r.description,
                              "risk":r.risk,"banner":r.banner,"latency_ms":round(r.latency_ms,2)}
                             for r in open_ports]}
        with open(fname,"w") as f: json.dump(data,f,indent=2)
    elif fmt=="csv":
        with open(fname,"w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=["port","service","description","risk","banner","latency_ms"])
            w.writeheader()
            for r in open_ports:
                w.writerow({"port":r.port,"service":r.service,"description":r.description,
                             "risk":r.risk,"banner":r.banner,"latency_ms":round(r.latency_ms,2)})
    elif fmt=="txt":
        with open(fname,"w") as f:
            f.write(f"Scanner v2.0  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target : {scanner.target}  ({scanner.ip})\n")
            f.write(f"Scanned: {len(scanner.ports):,} ports | {len(open_ports)} open | {scanner.end_time-scanner.start_time:.2f}s\n")
            f.write("─"*80+"\n")
            f.write(f"{'PORT':>6}  {'SERVICE':<16}  {'RISK':<6}  BANNER / DESCRIPTION\n")
            f.write("─"*80+"\n")
            for r in open_ports:
                f.write(f"{r.port:>6}/tcp  {r.service:<16}  {r.risk:<6}  {r.banner or r.description}\n")
    return fname

# ─── Port spec parser ─────────────────────────────────────────────────────────
def parse_port_spec(spec: str) -> List[int]:
    ports=set()
    for part in spec.split(","):
        part=part.strip()
        if "-" in part:
            a,b=part.split("-",1); ports.update(range(int(a),int(b)+1))
        else: ports.add(int(part))
    return sorted(p for p in ports if 1<=p<=65535)

# ─── Interactive TUI ──────────────────────────────────────────────────────────
def iprompt(label: str, default: str="") -> str:
    hint=f" [{C.GRAY}{default}{C.RESET}]" if default else ""
    try:
        v=input(f"  {C.YELLOW}{C.BOLD}{label}{C.RESET}{hint}  › ").strip()
        return v if v else default
    except (EOFError,KeyboardInterrupt): print(); sys.exit(0)

def iconfirm(label: str, default: bool=True) -> bool:
    hint="Y/n" if default else "y/N"
    ans=iprompt(f"{label} [{hint}]","").lower()
    return default if not ans else ans.startswith("y")

def interactive():
    clear(); print(LOGO)

    # Target
    print(f"  {C.TEAL}─── TARGET ──────────────────────────────────────────────────{C.RESET}\n")
    target=iprompt("Hostname or IP")
    if not target: print(f"  {C.RED}No target. Exiting.{C.RESET}"); sys.exit(1)

    print(f"\n  {C.GRAY}Resolving {target}…{C.RESET}  ",end="",flush=True)
    ip=resolve_host(target)
    if not ip: print(f"\n  {C.RED}✗  Cannot resolve '{target}'{C.RESET}\n"); sys.exit(1)
    hostname=reverse_dns(ip)
    print(f"{C.GREEN}{C.BOLD}✓  {ip}{C.RESET}\n")

    # Port preset
    print(f"  {C.TEAL}─── PORT RANGE ──────────────────────────────────────────────{C.RESET}\n")
    presets=list(PRESET_RANGES.keys())
    maxl=max(len(k) for k in presets)
    for i,name in enumerate(presets,1):
        n=len(PRESET_RANGES[name])
        print(f"  {C.TEAL}{C.BOLD}{i:>2}{C.RESET}  {C.WHITE}{name:<{maxl}}{C.RESET}  {C.GRAY}{n:>6,} ports{C.RESET}  {C.LGRAY}{PRESET_DESC.get(name,'')}{C.RESET}")
    last=len(presets)+1
    print(f"  {C.TEAL}{C.BOLD}{last:>2}{C.RESET}  {C.WHITE}{'custom':<{maxl}}{C.RESET}  {C.GRAY}         {C.RESET}  {C.LGRAY}e.g. 22,80,443 or 1-1024{C.RESET}\n")

    try: choice=int(iprompt("Select preset","1"))
    except: choice=1

    if 1<=choice<=len(presets): ports=PRESET_RANGES[presets[choice-1]]
    else:
        raw=iprompt("Enter ports (e.g. 22,80,443,8000-9000)","80,443")
        ports=parse_port_spec(raw)

    # Options
    print(f"\n  {C.TEAL}─── OPTIONS ─────────────────────────────────────────────────{C.RESET}\n")
    try: timeout=float(iprompt("Timeout per port (seconds)","1.0"))
    except: timeout=1.0
    try: workers=int(iprompt("Concurrent workers","300"))
    except: workers=300
    do_banners=iconfirm("Grab service banners",default=True)

    scanner=Scanner(target,ports,timeout=timeout,workers=workers,grab_banners=do_banners)
    scanner.ip=ip; scanner.hostname=hostname

    print(); print_target_box(scanner)
    print(f"  {C.GRAY}Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}…{C.RESET}\n")
    open_ports=scanner.run()
    print()
    print_results_table(open_ports)
    print_summary(scanner,open_ports)

    if open_ports and iconfirm("Export results",default=False):
        fmt=iprompt("Format (json / csv / txt)","json").strip().lower()
        if fmt not in ("json","csv","txt"): fmt="json"
        fname=export_results(scanner,open_ports,fmt)
        print(f"\n  {C.GREEN}{C.BOLD}✓  Saved →{C.RESET}  {C.LGRAY}{fname}{C.RESET}\n")

# ─── CLI mode ─────────────────────────────────────────────────────────────────
def cli():
    parser=argparse.ArgumentParser(description="Advanced Port Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 portscanner.py 192.168.1.1
  python3 portscanner.py example.com --preset web --no-banners
  python3 portscanner.py 10.0.0.1 --ports 22,80,443,8080-8090 --workers 500
  python3 portscanner.py 172.16.0.1 --preset full --timeout 0.5 --export json""")
    parser.add_argument("target")
    parser.add_argument("--preset",choices=list(PRESET_RANGES.keys()),default="top-100")
    parser.add_argument("--ports",help="Port spec: 22,80,1000-2000")
    parser.add_argument("--timeout",type=float,default=1.0)
    parser.add_argument("--workers",type=int,default=300)
    parser.add_argument("--no-banners",action="store_true")
    parser.add_argument("--export",choices=["json","csv","txt"])
    args=parser.parse_args()
    print(LOGO)
    ip=resolve_host(args.target)
    if not ip: print(f"  {C.RED}✗  Cannot resolve {args.target}{C.RESET}\n"); sys.exit(1)
    hostname=reverse_dns(ip)
    ports=parse_port_spec(args.ports) if args.ports else PRESET_RANGES[args.preset]
    scanner=Scanner(args.target,ports,timeout=args.timeout,workers=args.workers,grab_banners=not args.no_banners)
    scanner.ip=ip; scanner.hostname=hostname
    print_target_box(scanner)
    print(f"  {C.GRAY}Starting scan…{C.RESET}\n")
    open_ports=scanner.run()
    print()
    print_results_table(open_ports)
    print_summary(scanner,open_ports)
    if args.export and open_ports:
        fname=export_results(scanner,open_ports,args.export)
        print(f"  {C.GREEN}{C.BOLD}✓  Saved →{C.RESET}  {C.LGRAY}{fname}{C.RESET}\n")

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__=="__main__":
    try:
        if len(sys.argv)==1: interactive()
        else: cli()
    except KeyboardInterrupt:
        print(f"\n\n  {C.GRAY}Scan interrupted.{C.RESET}\n"); sys.exit(0)

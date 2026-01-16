# Copyright 2026 R A Veeraragavan

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, 
# publish, distribute, sublicense, and/or sell copies of the Software, and to permit 
# persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import time
import json
import ipaddress
import logging
import re
import psutil
from collections import defaultdict, deque
from flask import request, abort, jsonify, Flask

# ===================== PACKET =====================
class Packet:
    def __init__(self, src, dst, proto, sport, dport, payload="", size=0):
        self.src = ipaddress.ip_address(src)
        self.dst = ipaddress.ip_address(dst)
        self.proto = proto.upper()
        self.sport = int(sport or 0)
        self.dport = int(dport or 0)
        self.payload = payload
        self.size = size or len(payload)

    def __repr__(self):
        return f"[{self.proto}] {self.src}:{self.sport} → {self.dst}:{self.dport}"

# ===================== RULE =====================
class Rule:
    def __init__(self, src="0.0.0.0/0", dst="0.0.0.0/0",
                 proto="ANY", dport="ANY", action="DROP", desc=""):
        self.src_net = ipaddress.ip_network(src)
        self.dst_net = ipaddress.ip_network(dst)
        self.proto = proto.upper()
        self.dport = dport
        self.action = action.upper()
        self.desc = desc
        self.hits = 0

    def matches(self, pkt: Packet):
        if pkt.src not in self.src_net: return False
        if pkt.dst not in self.dst_net: return False
        if self.proto != "ANY" and pkt.proto != self.proto: return False
        if self.dport != "ANY" and pkt.dport != int(self.dport): return False
        return True

# ===================== DPI ENGINE =====================
class DPIEngine:
    MALICIOUS_PATTERNS = [
        r"union\s+select",
        r"<script>",
        r"\.\./",
        r"cmd\.exe",
        r"/etc/passwd"
    ]

    def inspect(self, pkt: Packet):
        for sig in self.MALICIOUS_PATTERNS:
            if re.search(sig, pkt.payload, re.IGNORECASE):
                return f"DPI_SIGNATURE_MATCH: {sig}"
        return None

# ===================== THREAT INTEL =====================
class ThreatIntel:
    MALICIOUS_DOMAINS = {"malware.com", "badsite.net"}

    def check_url(self, payload):
        for domain in self.MALICIOUS_DOMAINS:
            if domain in payload:
                return domain
        return None

# ===================== METRICS =====================
class MetricsEngine:
    def __init__(self):
        self.bandwidth = defaultdict(int)
        self.sessions = set()
        self.packet_rate = deque(maxlen=100)

    def record(self, pkt: Packet):
        self.bandwidth[str(pkt.src)] += pkt.size
        self.sessions.add((pkt.src, pkt.dst, pkt.proto))
        self.packet_rate.append(time.time())

    def stats(self):
        now = time.time()
        pps = len([t for t in self.packet_rate if now - t < 1])
        return {
            "active_sessions": len(self.sessions),
            "bandwidth_per_ip": dict(self.bandwidth),
            "pps": pps,
            "cpu": psutil.cpu_percent(),
            "memory": psutil.virtual_memory().percent
        }

# ===================== FIREWALL =====================
class Firewall:
    def __init__(self, app: Flask):
        self.rules = []
        self.stats = {"allowed": 0, "dropped": 0, "alerts": 0}
        self.metrics = MetricsEngine()
        self.dpi = DPIEngine()
        self.threats = ThreatIntel()

        self.logger = logging.getLogger("SentinelFW")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler("sentinel_fw.log")
        fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        self.logger.addHandler(fh)

    # ---------- CORE ----------
    def process(self, pkt: Packet):
        self.metrics.record(pkt)

        # DPI
        dpi_hit = self.dpi.inspect(pkt)
        if dpi_hit:
            self.alert(f"DPI ALERT {dpi_hit}", pkt)
            return self.drop(pkt)

        # URL Filtering
        bad = self.threats.check_url(pkt.payload)
        if bad:
            self.alert(f"MALICIOUS DOMAIN {bad}", pkt)
            return self.drop(pkt)

        # Rules
        for rule in self.rules:
            if rule.matches(pkt):
                rule.hits += 1
                if rule.action == "ALLOW":
                    return self.allow(pkt)
                return self.drop(pkt)

        return self.drop(pkt)

    def allow(self, pkt):
        self.stats["allowed"] += 1
        self.logger.info(f"ALLOW {pkt}")
        return "ALLOW"

    def drop(self, pkt):
        self.stats["dropped"] += 1
        self.logger.warning(f"DROP {pkt}")
        return "DROP"

    def alert(self, msg, pkt):
        self.stats["alerts"] += 1
        self.logger.error(f"ALERT {msg} {pkt}")

    # ---------- FLASK DECORATOR ----------
    def protect(self, port=5000):
        def decorator(f):
            def wrapper(*args, **kwargs):
                pkt = Packet(
                    src=request.remote_addr,
                    dst="127.0.0.1",
                    proto="TCP",
                    sport=request.environ.get("REMOTE_PORT"),
                    dport=port,
                    payload=request.path
                )
                verdict = self.process(pkt)
                if verdict == "DROP":
                    abort(403)
                return f(*args, **kwargs)
            return wrapper
        return decorator

    # ---------- APIs ----------
    def api_stats(self):
        return jsonify({
            "firewall": self.stats,
            "metrics": self.metrics.stats(),
            "rules": [
                {"desc": r.desc, "hits": r.hits, "action": r.action}
                for r in self.rules
            ]
        })

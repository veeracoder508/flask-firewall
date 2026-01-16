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

import json
import time
import ipaddress
import logging
import re
from functools import wraps
from flask import request, abort, jsonify
from flask import Flask
import psutil
import os


# ---------------- ANSI STRIPPING LOGIC ----------------
# Regex to identify ANSI escape sequences (terminal colors/styles)
class StripAnsiFilter(logging.Filter):
    """Filter that removes ANSI color codes from log records."""
    def filter(self, record):
        ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        if isinstance(record.msg, str):
            record.msg = ANSI_ESCAPE.sub('', record.msg)
        return True

class Packet:
    """
    this object contains all the information about the natwork packet.

    Examples:
    >>> Packet("127.0.0.1", "8.8.8.8", "TCP", 5000, 80, "")
    """
    def __init__(self, src: ipaddress.IPv4Address | ipaddress.IPv6Address, dst: ipaddress.IPv4Address | ipaddress.IPv6Address, proto: str, sport: int, dport: int, payload: str=""):
        """
        :param src: The source IP address.
        :type src: ipaddress.IPv4Address | ipaddress.IPv6Address
        :param dst: The  IP address.
        :type dst: ipaddress.IPv4Address | ipaddress.IPv6Address
        :param proto: The protocol of the packet
        :type proto: str
        :param sport: the source port.
        :type sport: int
        :param dport: The destination port
        :type dport: int
        :param payload: The raw data of the packet.
        :type payload: str
        """
        self.src = ipaddress.ip_address(src)
        self.dst = ipaddress.ip_address(dst)
        self.proto = proto.upper()
        self.sport = int(sport) if sport else 0
        self.dport = int(dport) if dport else 0
        self.payload = payload

    def __repr__(self):
        """
        Return a string representation of the packet.

        :return: String representation in the format "[PROTO] src:sport -> dst:dport".
        :rtype: str
        """
        return f"[{self.proto}] {self.src}:{self.sport} -> {self.dst}:{self.dport}"

class Rule:
    """
    this object contains a rule for the fire wall.

    Example:
    -------
    >>> Rule("127.0.0.1/32", "8.8.8.8", proto="TCP", dport=80, action="ALLOW", desc="Description")
    """
    def __init__(self, src_cidr="ANY", dst_cidr="ANY", proto="ANY", dport="ANY", action="DROP", desc=""):
        """
        :param src_cidr: The source cidr. 
        :type src_cidr: str 
        :param dst_cidr: the destination cidr. 
        :type dst_cidr: str 
        :param proto: the protocol for the rule
        :type proto: str
        :param dport: the destination port
        :type dport: str
        :param action: ALLOW/DROP action for the rule.
        :type action: str
        :param desc: Description for the rule.
        :type desc: str
        """
        self.src_net = ipaddress.ip_network(src_cidr) if src_cidr != "ANY" else "ANY"
        self.dst_net = ipaddress.ip_network(dst_cidr) if dst_cidr != "ANY" else "ANY"
        self.proto = proto.upper()
        self.dport = dport 
        self.action = action.upper()
        self.desc = desc

    def matches(self, pkt: Packet) -> bool:
        """
        Dto check if the rule and the packet matches
        
        :param pkt: the packet
        :type pkt: Packet
        :return: if the rule and the packet matches
        :rtype: bool
        """
        if self.src_net != "ANY" and (pkt.src not in self.src_net): 
            return False
        if self.dst_net != "ANY" and (pkt.dst not in self.dst_net): 
            return False
        if self.proto != "ANY" and self.proto != pkt.proto: 
            return False
        if self.dport != "ANY" and int(self.dport) != pkt.dport: 
            return False
        return True
    
    def to_tuple(self, index):
        """
        returns the tuple form of the `Rule` object

        >>> Rule("127.0.0.1/32", "8.8.8.8", proto="TCP", dport=80, action="ALLOW", desc="Description")
        (1, "Description", "8.8.8.8", "127.0.0.1/32", "ALLOW")
        """
        return (index, self.desc, str(self.src_net), self.action)

class StatefulEngine:
    """
    A stateful firewall engine that tracks connections and allows return traffic.

    This engine maintains a dictionary of active connections with timeouts to support
    stateful inspection, allowing return packets for established connections.
    """
    def __init__(self):
        """
        Initialize the stateful engine with an empty connections dictionary.
        """
        self.connections = {}

    def track(self, pkt: Packet):
        """
        Track a new outbound connection for stateful inspection.

        :param pkt: The packet representing the outbound connection.
        :type pkt: Packet
        """
        reverse_key = (pkt.dst, pkt.src, pkt.dport, pkt.sport, pkt.proto)
        self.connections[reverse_key] = time.time() + 300

    def is_allowed_return(self, pkt: Packet):
        """
        Check if a packet is an allowed return packet for an established connection.

        :param pkt: The packet to check.
        :type pkt: Packet
        :return: True if the packet is allowed as return traffic, False otherwise.
        :rtype: bool
        """
        key = (pkt.src, pkt.dst, pkt.sport, pkt.dport, pkt.proto)
        if key in self.connections:
            if time.time() < self.connections[key]:
                return True
            del self.connections[key]
        return False

class RuleEngine:
    """
    A rule-based engine that evaluates packets against a list of firewall rules.

    Rules are evaluated in order, and the first matching rule determines the action.
    If no rules match, the default action is DROP.
    """
    def __init__(self):
        """
        Initialize the rule engine with an empty list of rules.
        """
        self.rules: list[Rule] = []

    def evaluate(self, pkt: Packet):
        """
        Evaluate a packet against the rules and return the action.

        :param pkt: The packet to evaluate.
        :type pkt: Packet
        :return: The action to take ("ALLOW" or "DROP").
        :rtype: str
        """
        for rule in self.rules:
            if rule.matches(pkt):
                return rule.action
        return "DROP"

class Firewall:
    """
    A Flask-based firewall that integrates packet filtering with web applications.

    This firewall supports both stateless ACL rules and stateful connection tracking,
    providing comprehensive network security for Flask applications.
    """
    ALLOW = "ALLOW"
    DROP = "DROP"
    TCP = "TCP"
    ANY = "ANY"
    
    def __init__(self, flask_instance: Flask):
        """
        Initialize the firewall with a Flask application instance.

        :param flask_instance: The Flask application to protect.
        :type flask_instance: Flask
        """
        self.flask_instance = flask_instance
        self.server_pid = os.getpid()
        self.engine = RuleEngine()
        self.state = StatefulEngine()
        self.stats = {"Allowed": 0, "Dropped": 0, "Stateful_Hits": 0}
        self.server_name = flask_instance.name
        
        # Setup dynamic logging based on server_name
        self.logger = logging.getLogger(f"Firewall_{self.server_name}")
        self.logger.setLevel(logging.INFO)
        
        # Clear existing handlers if any (prevents duplicate logs on reload)
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

        # Use the server name for the log file
        log_filename = f"{self.server_name}_firewall.log"
        file_handler = logging.FileHandler(log_filename)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(StripAnsiFilter())

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def process(self, pkt):
        """
        Process a packet through the firewall rules and stateful engine.

        :param pkt: The packet to process.
        :type pkt: Packet
        :return: The action taken ("ALLOW", "DROP", or "ALLOW (STATEFUL)").
        :rtype: str
        """
        if self.state.is_allowed_return(pkt):
            self.stats["Stateful_Hits"] += 1
            self.stats["Allowed"] += 1
            self.logger.info(f"STATEFUL ALLOW: {pkt}") # Use self.logger
            return "ALLOW (STATEFUL)"

        action = self.engine.evaluate(pkt)
        
        if action == "ALLOW":
            self.stats["Allowed"] += 1
            self.state.track(pkt)
            self.logger.info(f"ACL ALLOW: {pkt}") # Use self.logger
        else:
            self.stats["Dropped"] += 1
            self.logger.warning(f"ACL DROP: {pkt} - No matching allow rule.") # Use self.logger
            
        return action

    def firewall(self, port=5000):
        """
        Decorator to apply firewall protection to Flask routes.

        :param port: The port number for the destination (default 5000).
        :type port: int
        :return: A decorator function.
        :rtype: function
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    pkt = Packet(
                        src=request.remote_addr,
                        dst="127.0.0.1" if ":" not in request.remote_addr else "::1",
                        proto="TCP",
                        sport=request.environ.get('REMOTE_PORT', 0),
                        dport=port,
                        payload=request.path
                    )
                    verdict = self.process(pkt)
                    if "DROP" in verdict:
                        abort(403, description="Access denied by Firewall.")
                    return f(*args, **kwargs)
                except Exception as e:
                    self.logger.error(f"Firewall Processing Error: {e}")
                    abort(500)
            return decorated_function
        return decorator

    def get_stats_json(self):
        """
        Get firewall statistics as a JSON response.

        :return: JSON response containing firewall statistics.
        :rtype: flask.Response
        """
        return jsonify(self.stats)
    
def create_monitor(SentinelMonitor_instance):
    """
    Create a monitor script for the firewall instance.

    :param firewall_instance: The firewall instance to monitor.
    :type firewall_instance: Firewall
    """
    file_name = f"{SentinelMonitor_instance.fw.server_name}_monitor.py"
    print(file_name)
    with open(file_name, 'w', encoding='utf-8') as file:
        file.write(f"""# FlaskFirewall Monitor (FFWM)\nfrom {SentinelMonitor_instance.fw.server_name} import monitor\nmonitor.mainloop()""")

def get_stats(firewall_instance: Firewall):
    """
    Get system statistics for the process running the firewall.

    :param firewall_instance: The firewall instance.
    :type firewall_instance: Firewall
    :return: Dictionary containing app name, RAM usage in MB, and CPU percentage.
    :rtype: dict
    """
    # Use the PID captured when the Flask server started
    process = psutil.Process(firewall_instance.server_pid) 
    
    memory_info = process.memory_info().rss / (1024 * 1024)
    cpu_usage = process.cpu_percent(interval=0.1)
    
    return {
        "app_name": firewall_instance.flask_instance.name,
        "ram_mb": round(memory_info, 2),
        "cpu_percent": cpu_usage
    }

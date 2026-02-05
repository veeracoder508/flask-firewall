# Copyright 2026 R A Veeraragavan (refer __init__.py)
"""Flask-Firewall: A comprehensive firewall module for Flask applications.

This module provides stateless ACL (Access Control List) rules and stateful
connection tracking to protect Flask applications from unauthorized network access.
It includes packet filtering, rule evaluation, logging, and statistics monitoring.

Key Components:
    - RuleEngine: Evaluates packets against defined rules in order.
    - StatefulEngine: Tracks connections to allow return traffic for established sessions.
    - Logger: Dedicated logging for firewall events with ANSI stripping.
    - Firewall: Main Flask integration class that applies filtering to routes.
"""

import time
from flask_firewall.log import Logger
from functools import wraps
from flask import request, abort, jsonify
import os
import objs


class StatefulEngine:
    """
    A stateful firewall engine that tracks connections and allows return traffic.

    This engine maintains a dictionary of active connections with timeouts to support
    stateful inspection, allowing return packets for established connections.
    """
    def __init__(self) -> None:
        """
        Initialize the stateful engine with an empty connections dictionary.
        """
        self.connections = {}

    def track(self, pkt: objs.Packet) -> None:
        """
        Track a new outbound connection for stateful inspection.

        :param pkt: The packet representing the outbound connection.
        :type pkt: Packet
        """
        reverse_key = (pkt.dst, pkt.src, pkt.dport, pkt.sport, pkt.proto)
        self.connections[reverse_key] = time.time() + 300

    def is_allowed_return(self, pkt: objs.Packet) -> bool:
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
        self.rules: list[objs.Rule] = []

    def evaluate(self, pkt: objs.Packet) -> str:
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
    
    def __init__(self, flask_instance) -> None:
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
        
        self.logger = Logger(flask_instance.name)

    def process(self, pkt) -> str:
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
            self.logger.info(f"STATEFUL ALLOW: {pkt}")
            return "ALLOW (STATEFUL)"

        action = self.engine.evaluate(pkt)
        
        if action == "ALLOW":
            self.stats["Allowed"] += 1
            self.state.track(pkt)
            self.logger.log_allow(pkt)
        else:
            self.stats["Dropped"] += 1
            self.logger.log_drop({pkt})
            
        return action

    def firewall(self, port=5000):
        """Decorator to apply firewall protection to Flask route handlers.
        
        This decorator creates a Packet object from the incoming Flask request,
        processes it through the firewall rules, and aborts with a 403 Forbidden
        response if the packet is dropped. Any processing errors result in a 500 error.
        
        Usage:
            @app.route('/api/data')
            @firewall_instance.firewall(port=5000)
            def get_data():
                return jsonify({"data": "sensitive information"})
        
        :param port: The destination port number for the packet (default 5000).
        :type port: int
        :return: A decorator function that wraps Flask route handlers.
        :rtype: function
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    # Add defaults for remote_addr if it's None (e.g., during local testing)
                    src_ip = request.remote_addr or "127.0.0.1" 
                    pkt = objs.Packet(
                        src=src_ip,
                        dst="127.0.0.1", # Default local dst
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
                    self.logger.log_error(f"Firewall Processing Error: {e}")
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


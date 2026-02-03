# Copyright 2026 R A Veeraragavan (Refere firewall.py)
"""
"""


import ipaddress

class Packet:
    """Represents a network packet with source/destination IP addresses, protocol, and ports.
    
    This class encapsulates all information about a network packet for firewall filtering.
    It normalizes and validates IP addresses and ports, and provides a readable string representation.
    
    Examples:
        >>> pkt = Packet("127.0.0.1", "8.8.8.8", "TCP", 5000, 80)
        >>> print(pkt)
        [TCP] 127.0.0.1:5000 -> 8.8.8.8:80
    """
    def __init__(self, src: ipaddress.IPv4Address | ipaddress.IPv6Address, dst: ipaddress.IPv4Address | ipaddress.IPv6Address, proto: str, sport: int, dport: int, payload: str=""):
        """Initialize a Packet object with network flow information.
        
        :param src: The source IP address (IPv4 or IPv6).
        :type src: ipaddress.IPv4Address | ipaddress.IPv6Address
        :param dst: The destination IP address (IPv4 or IPv6).
        :type dst: ipaddress.IPv4Address | ipaddress.IPv6Address
        :param proto: The network protocol (e.g., 'TCP', 'UDP', 'ICMP').
        :type proto: str
        :param sport: The source port number.
        :type sport: int
        :param dport: The destination port number.
        :type dport: int
        :param payload: Optional raw data or path associated with the packet.
        :type payload: str
        """
        self.src = ipaddress.ip_address(src)
        self.dst = ipaddress.ip_address(dst)
        self.proto = proto.upper()
        self.sport = int(sport) if sport else 0
        self.dport = int(dport) if dport else 0
        self.payload = payload

    def __repr__(self):
        """Return a string representation of the packet in flow format.
        
        :return: String representation in the format "[PROTO] src:sport -> dst:dport".
        :rtype: str
        """
        return f"[{self.proto}] {self.src}:{self.sport} -> {self.dst}:{self.dport}"

class Rule:
    """Represents a firewall rule with CIDR matching and action definitions.
    
    Rules define allowed or denied traffic based on source/destination CIDR blocks,
    protocol type, and destination port. Rules are evaluated sequentially, with the
    first match determining the action.
    
    Examples:
        >>> allow_web = Rule("0.0.0.0/0", "0.0.0.0/0", proto="TCP", dport=80, action="ALLOW", desc="Allow HTTP")
        >>> deny_telnet = Rule("0.0.0.0/0", "0.0.0.0/0", proto="TCP", dport=23, action="DROP", desc="Block Telnet")
    """
    def __init__(self, src_cidr="ANY", dst_cidr="ANY", proto="ANY", dport="ANY", action="DROP", desc=""):
        """Initialize a firewall rule.
        
        :param src_cidr: Source CIDR block (e.g., '192.168.1.0/24') or 'ANY' for all sources.
        :type src_cidr: str 
        :param dst_cidr: Destination CIDR block (e.g., '10.0.0.0/8') or 'ANY' for all destinations.
        :type dst_cidr: str 
        :param proto: Protocol type ('TCP', 'UDP', 'ICMP') or 'ANY' for all protocols.
        :type proto: str
        :param dport: Destination port number or 'ANY' for all ports.
        :type dport: str
        :param action: Action to take when rule matches ('ALLOW' or 'DROP').
        :type action: str
        :param desc: Human-readable description of the rule's purpose.
        :type desc: str
        """
        self.src_net = ipaddress.ip_network(src_cidr) if src_cidr != "ANY" else "ANY"
        self.dst_net = ipaddress.ip_network(dst_cidr) if dst_cidr != "ANY" else "ANY"
        self.proto = proto.upper()
        self.dport = dport 
        self.action = action.upper()
        self.desc = desc

    def matches(self, pkt: Packet) -> bool:
        """Check if a packet matches this rule's criteria.
        
        All specified rule criteria must match the packet for this method to return True.
        A rule criterion set to 'ANY' matches any packet value for that criterion.
        
        :param pkt: The packet to evaluate against this rule.
        :type pkt: Packet
        :return: True if packet matches all rule criteria, False otherwise.
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
        """Convert the rule to a tuple format for display or serialization.
        
        Returns a tuple with index, description, source CIDR, and action.
        Useful for tabular display of rules.
        
        Example:
            >>> rule = Rule("127.0.0.1/32", "8.8.8.8", proto="TCP", dport=80, action="ALLOW", desc="Allow from local")
            >>> rule.to_tuple(1)
            (1, 'Allow from local', '127.0.0.1/32', 'ALLOW')
        
        :param index: The rule number for display purposes.
        :type index: int
        :return: Tuple containing (index, description, source_network, action).
        :rtype: tuple
        """
        return (index, self.desc, str(self.src_net), self.action)
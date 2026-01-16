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
from colorama import init, Fore, Style

# Initialize colorama for cross-platform support
init(autoreset=True)

# ---------------- COLORS ----------------
class Colors:
    """Color constants for console output."""
    HEADER = Fore.CYAN + Style.BRIGHT
    INFO = Fore.BLUE
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    FAIL = Fore.RED
    RESET = Style.RESET_ALL

# ---------------- LOGGER ----------------
class Logger:
    """Logger class for logging firewall events."""
    
    def __init__(self, file: str="firewall.log") -> None:
        """Initialize the Logger with a log file.
        
        Args:
            file (str): Path to the log file.
        """
        self.file = file

    def log(self, msg: str, level="INFO") -> None:
        """Log a message with a given level.
        
        Args:
            msg (str): The message to log.
            level (str): The log level (INFO, SUCCESS, etc.).
        """
        # Map levels to colors
        color_map = {
            "INFO": Colors.INFO,
            "SUCCESS": Colors.SUCCESS,
            "WARNING": Colors.WARNING,
            "FAIL": Colors.FAIL
        }
        color = color_map.get(level, "")
        
        timestamp = time.strftime('%H:%M:%S')
        clean_entry = f"[{timestamp}] {msg}"
        colored_entry = f"{Style.DIM}[{timestamp}]{Colors.RESET} {color}{msg}"
        
        print(colored_entry)
        try:
            with open(self.file, "a") as f:
                f.write(clean_entry + "\n")
        except IOError as e:
            print(f"{Colors.FAIL}Logging error: {e}")

# ---------------- PACKET ----------------
class Packet:
    """Represents a network packet."""
    
    def __init__(self, src: str, dst: str, proto: str, sport: int, dport: int) -> None:
        """Initialize a Packet.
        
        Args:
            src (str): Source IP.
            dst (str): Destination IP.
            proto (str): Protocol.
            sport (int): Source port.
            dport (int): Destination port.
        """
        self.src = src
        self.dst = dst
        self.proto = proto.upper()
        self.sport = int(sport)
        self.dport = int(dport)

    def __repr__(self) -> str:
        """String representation of the packet."""
        return f"{self.proto} {self.src}:{self.sport} -> {self.dst}:{self.dport}"

# ---------------- RULE ----------------
class Rule:
    """Represents a firewall rule."""
    
    def __init__(self, src: str="any", dst: str="any", proto: str="any", dport: str="any", action: str="DROP") -> None:
        """Initialize a Rule.
        
        Args:
            src (str): Source IP or 'any'.
            dst (str): Destination IP or 'any'.
            proto (str): Protocol or 'any'.
            dport (str): Destination port or 'any'.
            action (str): Action (ALLOW or DROP).
        """
        self.src = src
        self.dst = dst
        self.proto = proto.upper()
        self.dport = dport if dport == "any" else int(dport)
        self.action = action.upper()

    def match(self, pkt: Packet) -> bool:
        """Check if packet matches the rule.
        
        Args:
            pkt (Packet): The packet to check.
        
        Returns:
            bool: True if matches.
        """
        if self.src != "any" and pkt.src != self.src: return False
        if self.dst != "any" and pkt.dst != self.dst: return False
        if self.proto != "any" and pkt.proto != self.proto: return False
        if self.dport != "any" and pkt.dport != self.dport: return False
        return True

# ---------------- STATE TABLE ----------------
class StateTable:
    """Manages stateful connections."""
    
    def __init__(self) -> None:
        """Initialize with an empty set."""
        self.table = set()

    def is_known(self, pkt: Packet) -> bool:
        """Check if packet is from a known connection.
        
        Args:
            pkt (Packet): The packet.
        
        Returns:
            bool: True if known.
        """
        key = (pkt.src, pkt.dst, pkt.dport, pkt.proto)
        if key in self.table:
            return True
        self.table.add(key)
        return False

# ---------------- NAT ----------------
class NAT:
    """Network Address Translation handler."""
    
    def __init__(self, logger) -> None:
        """Initialize NAT with a logger.
        
        Args:
            logger (Logger): The logger instance.
        """
        self.table = {}
        self.logger = logger

    def add(self, internal_ip: str, external_ip: str) -> None:
        """Add a NAT mapping.
        
        Args:
            internal_ip (str): Internal IP.
            external_ip (str): External IP.
        """
        self.table[internal_ip] = external_ip

    def apply(self, pkt: Packet) -> None:
        """Apply NAT to the packet.
        
        Args:
            pkt (Packet): The packet to translate.
        """
        if pkt.src in self.table:
            old = pkt.src
            pkt.src = self.table[old]
            self.logger.log(f"[NAT] Translated {old} -> {pkt.src}", "INFO")

# ---------------- IDS ----------------
class IDS:
    """**Intrusion Detection System.**"""
    
    def __init__(self, logger: Logger) -> None:
        """Initialize IDS with logger and signatures.
        
        Args:
            logger (Logger): The logger instance.
        """
        self.logger = logger
        self.signatures = [
            {"proto": "TCP", "dport": 23, "alert": "TELNET ATTEMPT"},
            {"proto": "TCP", "dport": 4444, "alert": "BACKDOOR PORT"},
            {"proto": "UDP", "dport": 53, "alert": "DNS TRAFFIC"}
        ]

    def inspect(self, pkt: Packet) -> None:
        """Inspect packet for signatures.
        
        Args:
            pkt (Packet): The packet to inspect.
        """
        for sig in self.signatures:
            if pkt.proto == sig["proto"] and pkt.dport == sig["dport"]:
                self.logger.log(f"[IDS ALERT] {sig['alert']} from {pkt.src}", "WARNING")

# ---------------- RULE ENGINE ----------------
class RuleEngine:
    """Evaluates packets against rules."""
    
    def __init__(self, logger: Logger) -> None:
        """Initialize with logger and empty rules.
        
        Args:
            logger (Logger): The logger instance.
        """
        self.rules: list[Rule] = []
        self.logger = logger

    def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine.
        
        Args:
            rule (Rule): The rule to add.
        """
        self.rules.append(rule)

    def evaluate(self, pkt: Packet) -> str:
        """Evaluate packet against rules.
        
        Args:
            pkt (Packet): The packet.
        
        Returns:
            str: Action (ALLOW or DROP).
        """
        for rule in self.rules:
            if rule.match(pkt):
                return rule.action
        return "DROP"

# ---------------- FIREWALL ----------------
class Firewall:
    """Main Firewall class."""
    
    def __init__(self) -> None:
        """Initialize firewall with components."""
        self.logger = Logger()
        self.state = StateTable()
        self.nat = NAT(self.logger)
        self.ids = IDS(self.logger)
        self.engine = RuleEngine(self.logger)

    def process(self, pkt: Packet) -> str:
        """Process a packet.
        
        Args:
            pkt (Packet): The packet.
        
        Returns:
            str: Action.
        """
        self.ids.inspect(pkt)
        action = self.engine.evaluate(pkt)
        
        if action == "ALLOW":
            self.nat.apply(pkt)
            self.state.is_known(pkt)
            self.logger.log(f"ALLOWED: {pkt}", "SUCCESS")
        else:
            self.logger.log(f"DROPPED: {pkt}", "FAIL")
            
        return action

# ---------------- CLI ----------------
class FirewallCLI:
    """Command-line interface for the firewall."""
    
    def __init__(self) -> None:
        """Initialize CLI with firewall."""
        self.fw = Firewall()

    def start(self) -> None:
        """Start the CLI loop."""
        print(f"\n{Colors.HEADER}=== Python Firewall CLI ==={Colors.RESET}")
        print(f"Type '{Colors.INFO}help{Colors.RESET}' for commands (Ctrl+C to exit)\n")

        try:
            while True:
                try:
                    # Using Fore.CYAN for the prompt itself
                    user_input = input(f"{Fore.CYAN}fw>{Colors.RESET} ").strip().split()
                    if not user_input: continue
                    
                    cmd = user_input[0].lower()

                    if cmd == "exit":
                        break

                    elif cmd == "help":
                        print(f"\n{Colors.HEADER}Available Commands:{Colors.RESET}")
                        commands = {
                            "allow/drop <proto> <port>": "Add security rule",
                            "nat <in> <out>": "Map internal IP to external IP",
                            "packet": "Simulate an incoming packet",
                            "rules": "List current firewall rules",
                            "exit": "Shut down firewall"
                        }
                        for c, desc in commands.items():
                            print(f"  {Colors.INFO}{c:<30}{Colors.RESET} {desc}")
                        print()

                    elif cmd in ("allow", "drop"):
                        if len(user_input) < 3:
                            print(f"{Colors.FAIL}Usage: {cmd} <PROTO> <PORT>{Colors.RESET}")
                            continue
                        new_rule = Rule(proto=user_input[1], dport=user_input[2], action=cmd)
                        self.fw.engine.add_rule(new_rule)
                        print(f"{Colors.SUCCESS}Rule added: {cmd.upper()} {user_input[1]} on port {user_input[2]}")

                    elif cmd == "nat":
                        if len(user_input) < 3:
                            print(f"{Colors.FAIL}Usage: nat <Internal_IP> <External_IP>{Colors.RESET}")
                            continue
                        self.fw.nat.add(user_input[1], user_input[2])
                        print(f"{Colors.SUCCESS}NAT mapping added.{Colors.RESET}")

                    elif cmd == "packet":
                        try:
                            p = Packet(
                                input("Source IP: "),
                                input("Destination IP: "),
                                input("Protocol (TCP/UDP): "),
                                input("Source Port: "),
                                input("Destination Port: ")
                            )
                            self.fw.process(p)
                        except ValueError:
                            print(f"{Colors.FAIL}Error: Ports must be numbers.{Colors.RESET}")

                    elif cmd == "rules":
                        print(f"\n{Colors.HEADER}Current Rules:{Colors.RESET}")
                        if not self.fw.engine.rules:
                            print("  (No rules defined - Default: DROP)")
                        for i, r in enumerate(self.fw.engine.rules):
                            color = Colors.SUCCESS if r.action == "ALLOW" else Colors.FAIL
                            print(f"  [{i}] {color}{r.action:<6}{Colors.RESET} {r.proto:<5} port {r.dport}")
                        print()

                    else:
                        print(f"{Colors.FAIL}Unknown command. Type 'help' for options.{Colors.RESET}")

                except EOFError:
                    break
                except Exception as e:
                    print(f"{Colors.FAIL}Command Error: {e}{Colors.RESET}")

        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}[!] KeyboardInterrupt detected.")
        finally:
            self.fw.logger.log("FIREWALL SYSTEM SHUTDOWN", "WARNING")
            print(f"{Colors.HEADER}Goodbye!{Colors.RESET}")

if __name__ == "__main__":
    fwcli = FirewallCLI()
    fwcli.start()
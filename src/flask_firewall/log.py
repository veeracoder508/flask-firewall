import os
import logging
import re


class Logger:
    """
    Dedicated logging object for the Firewall.
    Handles ANSI stripping, file logging, and console output.
    """
    def __init__(self, server_name: str) -> None:
        """ 
        :param server_name: the name of the server instance
        :type server_name: str
        """
        self.server_name = server_name
        self.logger = logging.getLogger(f"Firewall_{self.server_name}")
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers if the firewall is re-initialized
        if self.logger.hasHandlers():
            self.logger.handlers.clear()

        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')

        # File Handler
        log_filename = f"{self.server_name}_firewall.log"
        self.log_file = log_filename
        file_handler = logging.FileHandler(log_filename)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(self._StripAnsiFilter())

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    class _StripAnsiFilter(logging.Filter):
        """Internal filter to remove ANSI color codes."""
        def filter(self, record) -> bool:
            """
            :param record: the log record
            :type record: LogRecord
            """
            ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            if isinstance(record.msg, str):
                record.msg = ANSI_ESCAPE.sub('', record.msg)
            return True

    def log_allow(self, pkt, stateful=False) -> None:
        """Log an allowed packet.
        
        :param pkt: The packet being allowed.
        :type pkt: Packet
        :param stateful: Whether the packet was allowed by stateful inspection or ACL rule.
        :type stateful: bool
        """
        tag = "STATEFUL ALLOW" if stateful else "ACL ALLOW"
        self.logger.info(f"{tag}: {pkt}")

    def log_drop(self, pkt) -> None:
        """Log a dropped packet.
        
        :param pkt: The packet being dropped.
        :type pkt: Packet
        """
        self.logger.warning(f"ACL DROP: {pkt} - No matching allow rule.")

    def log_error(self, message) -> None:
        """Log a firewall processing error.
        
        :param message: The error message to log.
        :type message: str
        """
        self.logger.error(message)

    def get_logs(self, limit=500) -> list:
        """Reads the log file and returns a list of formatted log entries."""
        if not os.path.exists(self.log_file):
            return []
        
        logs = []
        try:
            with open(self.log_file, 'r') as f:
                # Read the last 'limit' lines
                lines = f.readlines()[-limit:]
                for line in lines:
                    line = line.strip()
                    if not line: continue
                    
                    # Determine status for the UI badges in logs.html
                    status = "ALLOW" if "ALLOW" in line else "DROP" if "DROP" in line else "INFO"
                    logs.append({
                        "status": status,
                        "raw": line
                    })
        except Exception as e:
            print(f"Error reading logs: {e}")
        return logs
from flask_firewall.firewall import Firewall, Rule
from flask import Flask


app = Flask(__name__)

# Configure socket to allow immediate port reuse
app.config['ENV_RELOADER_TYPE'] = 'stat'

fw = Firewall(app)


fw.engine.rules = [
    # 1. Block the specific IP from port 5000 FIRST
    Rule(action=fw.DROP, proto=fw.TCP, dport=5000, src_cidr="192.168.29.83", dst_cidr=fw.ANY, desc="Block specific IP from accessing Flask app"),
    
    # 2. Existing rules
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=80, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTP"),
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=443, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTPS"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=23, src_cidr=fw.ANY, dst_cidr="10.0.0.0/24", desc="Blocks Telnet to a subnet"),
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=22, src_cidr="192.168.1.10", dst_cidr=fw.ANY, desc="Only allows SSH from one specific IP"),
    
    # 3. Allow port 5000 for everyone else (MUST be below the block rule)
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=5000, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Allow HTTP to Flask app on 5000"),
    
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=8000, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="allows the monitor"),
]

@app.route('/')
@fw.firewall(port=5000)
def index():
    return "VEERA"


if __name__ == "__main__":
    from flask_firewall.monitor.web_monitor import create_monitor # Changed from flask_firewall.web_monitor
    import time
    
    print("--- Starting Sentinel SOC Monitor on http://127.0.0.1:8000 ---")
    monitor_app, monitor_thread = create_monitor(fw, host='127.0.0.1', port=8000, run_server=True)
    
    # Give the monitor a second to warm up
    time.sleep(1)
    
    print("--- Starting Main Protected Application on http://127.0.0.1:5000 ---")
    # Disable debug mode and reloader to prevent socket binding issues
    app.run(host="0.0.0.0", port=5000, debug=False)
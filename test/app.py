from src.flask_firewall.firewall import Firewall, Rule, create_monitor
from src.flask_firewall.monitor import SentinelMonitor
from flask import Flask


app = Flask(__name__)
fw = Firewall(app)


fw.engine.rules = [
    Rule(action=fw.DROP, proto=fw.TCP, dport=80, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTP"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=443, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTPS"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=23, src_cidr=fw.ANY, dst_cidr="10.0.0.0/24", desc="Blocks Telnet to a subnet"),
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=22, src_cidr="192.168.1.10", dst_cidr=fw.ANY, desc="Only allows SSH from one specific IP"),
]

monitor = SentinelMonitor(fw)

@app.route('/')
@fw.firewall(port=5000)
def index():
    return "VEERA"


if __name__ == "__main__":
    create_monitor(monitor)
    app.run(host="0.0.0.0")
# Table Of Content
1. [_Introduction_ - flask-firewall v0.0.1](#flask-firewall-ffw-v001)

2. [_introduction to firewall_ - what is a firewall?](#what-is-a-firewall)
    - [How a firewall works](#how-a-firewall-works)
    - [Types of Firewalls](#types-of-firewalls)

3. [_Setting up_ - Setting up FFW](#setting-up-ffw)
    - [_getting started_](#geting-started)
    - [_Setting up the Firewall in flask_](#setting-up-the-firewall-in-flask)
    - [_the setup_](#the-setup)
        + [_explation of the setup_](#explanation-of-the-setup)
    - [_how to work with the logs?_](#how-to-work-with-the-logs)
    - [_how to create a monitor for the firewall?_](#how-to-create-a-monitor-for-the-firewall)

# flask-firewall (FFw) v0.0.1
It is a simple firewall for a flask application. You can use it in you flask application.

# What is a firewall?
First going into **FFw**, we first learn what is a firewall. A firewall is a network security system, either hardware or software, that monitors and controls incoming and outgoing network traffic, acting as a digital barrier between a trusted internal network and untrusted external networks like the internet, blocking or allowing data packets based on predefined security rules to prevent unauthorized access and malicious activity. It functions like a security guard, checking data (packets) against rules to decide if they can pass, protecting networks from hackers, viruses, and other threats. 
[for more details about firewall ⤴](firewall.md)

## How a firewall works
1. Inspects traffic: Firewalls examine data packets traveling between networks.
2. Applies rules: They compare packet information (like source/destination IP, port, protocol) against a set of security rules.
3. Blocks or allows: Based on the rules, they permit safe traffic and block harmful or unauthorized traffic. 

## Types of Firewalls
1. Hardware Firewalls: Physical devices, often built into home routers, protecting entire networks.
2. Software Firewalls: Programs installed on individual devices (like Windows Defender), protecting that specific host.
3. Next-Generation Firewalls (NGFW): Advanced firewalls with features like deep packet inspection, intrusion prevention, and application control.
4. Web Application Firewalls (WAFs): Protect specific web applications from web-based attacks like SQL injection. 

# Setting up FFw
## geting started
To install the firewall there are two ways of doing it.
method one is by downloading it from github by using git.
``` bash
# for all os
$ git clone https://github.com/veeracoder508/flask-firewall.git
```
method two is by using uv or pip
``` bash
# for windows
>>> pip install flask-firewall # using pip
>>> uv add flask-firewall # using uv

# for linux/mac
$ pip3 install flask-firewall
$ uv add flask-firewall
```

## Setting up the Firewall in flask
After installation we need to create a flask app.
``` python
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return "veera"

if __name__ == "__main__":
    app.run(host="0.0.0.0")
```

## the setup 
in this simple flask app we can import our flask-firewall module and initilize our firewall for the flask app.
``` python
from flask import Flask
from flask_firewall import Firewall, Rule

app = Flask(__name__)
fw = Firewall(app)

fw.engine.rules = [
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=80, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTP"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=443, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTPS"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=23, src_cidr=fw.ANY, dst_cidr="10.0.0.0/24", desc="Blocks Telnet to a subnet"),
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=22, src_cidr="192.168.1.10", dst_cidr=fw.ANY, desc="Only allows SSH from one specific IP"),
]

@app.route('/')
@fw.firewall(port=5000)
def index():
    return "veera"

if __name__ == "__main__":
    app.run(host=5000)
```

### explanation of the setup
in the above program we see that first we see that we are importing the `flask_firewall` module that we installed. secondly we are initialising the firewall by using `fw = Firewall(app)`, we give a parameter `flask_instance` of type `Flask` whick is the flask application we are initialising the firewall for. Next we are setting up the rules for the firewall in `fw.engine.rules` which contain all the rules for the firewall. We use the `Rule()` object for a instance for a single rule. 

``` python
Rule(action=fw.DROP, proto=fw.TCP, dport=23, src_cidr=fw.ANY, dst_cidr="10.0.0.0/24", desc="Blocks Telnet to a subnet")
```

In the `Rule()` object there are 6 attributes
- `action`: what should do if the packet and the rule matches(ALLOW/DROP)
- `proto`: The portocol of the packet for the rule can be 'ANY'
- `dport`: the destination port for the rule
- `src_cidr`: the source cidr for the rule can be 'ANY'
- `dst_cidr`: the destination cidr for the rule can be 'ANY'
- `desc`: the description for the rule for readability

## how to work with the logs?
After youn run the application, a log file will nbe created `<name of flask app>_firewall.log`. In the log file you can see all the requests and how it is processed by the firewall.\
If no matching allow rule.
``` log
2026-01-11 10:52:46,996 [WARNING] ACL DROP: [TCP] 192.168.29.83:62075 -> 127.0.0.1:5000 - No matching allow rule. 
2026-01-11 10:52:46,997 [ERROR] Firewall Processing Error: 403 Forbidden: Access denied by Firewall.
```
In the following logs we see that the conection is denied by the firewall, and the server sends a 403 code.\
If matching allow rule.
``` log
2026-01-11 11:07:39,364 [INFO] ACL ALLOW: [TCP] 127.0.0.1:62286 -> 127.0.0.1:5000
```
In this log the firewall allows the conection.

## how to create a monitor for the firewall?
You can create a monitor to monitor the logs and the rules and automate stuff.
you can do it by tweaking the last code to have a monitor.
``` python
from flask import Flask
from flask_firewall import Firewall, Rule
from flask_firewall.monitor import SentinelMonitor

app = Flask(__name__)
fw = Firewall(app)

fw.engine.rules = [
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=80, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTP"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=443, src_cidr=fw.ANY, dst_cidr=fw.ANY, desc="Permits HTTPS"),
    Rule(action=fw.DROP, proto=fw.TCP, dport=23, src_cidr=fw.ANY, dst_cidr="10.0.0.0/24", desc="Blocks Telnet to a subnet"),
    Rule(action=fw.ALLOW, proto=fw.TCP, dport=22, src_cidr="192.168.1.10", dst_cidr=fw.ANY, desc="Only allows SSH from one specific IP"),
]

monitor = SentinelMonitor(fw)

@app.route('/')
@fw.firewall(port=5000)
def index():
    return "veera"

if __name__ == "__main__":
    create_monitor(monitor)
    app.run(host=5000)
```
> [!IMPORTANT]
> the instance for the `SentinelMonitor` must be `monitor` for the monitor to work properly.

after running the application with the updated code, it should create a flie `<name of flask app>_monitor.py` in the same folder as the flask app.
``` python 
# FlaskFirewall Monitor (FFWM)
from {name of flask app} import monitor
monitor.mainloop()
```
You can run the file to open the monitor
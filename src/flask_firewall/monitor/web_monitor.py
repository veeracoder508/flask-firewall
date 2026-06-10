from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import os
import time
from ..firewall import get_stats

def create_monitor(fw, host='127.0.0.1', port=8000, run_server=False):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    template_folder = os.path.join(base_dir, 'template')
    
    app = Flask(f"{fw.flask_instance.name}_web_monitor", template_folder=template_folder)

    app.logger.disabled = True # Disableing the logging for the monitor
    
    # Initialize SocketIO with a broader async_mode if needed
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

    @app.route('/')
    def index():
        return render_template('dashboard.html', server_name=fw.flask_instance.name)

    @app.route('/api/rules')
    def get_rules():
        rules_list = []
        for i, rule in enumerate(fw.engine.rules):
            rules_list.append({
                "id": i + 1,
                "desc": rule.desc,
                "src": str(rule.src_net),
                "action": rule.action
            })
        return jsonify(rules_list)

    @app.route('/api/logs')
    def get_logs_api():
        """Returns logs as JSON for the dashboard AJAX calls."""
        try:
            # Returns raw strings for the dashboard.html logic
            raw_logs = [log['raw'] for log in fw.logger.get_logs(limit=20)]
            return jsonify(raw_logs)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/min/firewall-logs')
    def full_logs_page():
        """Renders the detailed logs page."""
        try:
            # Pass the structured list to logs.html
            return render_template('logs.html', 
                                 server_name=fw.flask_instance.name, 
                                 logs=fw.logger.get_logs(limit=500))
        except Exception as e:
            return str(e), 500
            
    @app.route('/min/policies')
    def policies_page():
        # Ensure this is also present if you want to access policies.html
        rules_list = []
        for i, rule in enumerate(fw.engine.rules):
            rules_list.append({
                "id": i + 1,
                "desc": rule.desc,
                "action": rule.action,
                "proto": rule.proto,
                "src": str(rule.src_net),
                "dst": str(rule.dst_net),
                "dport": rule.dport
            })
        return render_template('policies.html', 
                             server_name=fw.flask_instance.name, 
                             rules=rules_list)

    def push_stats():
        """Background task for pushing stats via WebSocket."""
        while True:
            try:
                perf = get_stats(fw)
                data = {
                    'allowed': int(fw.stats.get('Allowed', 0)),
                    'dropped': int(fw.stats.get('Dropped', 0)),
                    'stateful_hits': int(fw.stats.get('Stateful_Hits', 0)),
                    'cpu': f"{perf.get('cpu_usage', 0)}%", 
                    'memory': f"{perf.get('memory_info', 0):.2f} MB"
                }
                # Use the socketio instance directly to emit
                socketio.emit('stats_update', data)
            except Exception as e:
                print(f"Stats Error: {e}")
            socketio.sleep(2) # Use socketio.sleep instead of time.sleep

    monitor_thread = None
    if run_server:
        # Define the runner inside the conditional
        def start_server():
            try:
                # Start the background task within the SocketIO context
                socketio.start_background_task(push_stats)
                socketio.run(app, host=host, port=port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
            except Exception as e:
                print(f"[!] Web Monitor Failed: {e}")

        import threading
        monitor_thread = threading.Thread(target=start_server, daemon=True)
        monitor_thread.start()

    return app, monitor_thread
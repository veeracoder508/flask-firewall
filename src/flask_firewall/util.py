from firewall import Firewall
import psutil

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

import pandas as pd
import requests
import os
from datetime import datetime

# Get the project root directory (parent of scripts/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_c2_domains(file_path=os.path.join(PROJECT_ROOT, "configs", "c2_domains.txt")):
    """Load C2 domains from a file."""
    c2_domains = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith("#"):
                    c2_domains.append(domain)
        return c2_domains
    except FileNotFoundError:
        print(f"Error: {file_path} not found, using default C2 list")
        return ["malicious-c2-domain.com", "ransomware-site.net"]

def fetch_c2_list(url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"):
    """Fetch a C2 domain list from a public threat intel feed."""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        # Parse hosts file for domains (simple example)
        domains = [line.split()[1] for line in response.text.splitlines() if line and not line.startswith("#") and len(line.split()) > 1]
        return domains
    except requests.RequestException as e:
        print(f"Error fetching C2 list: {e}")
        return load_c2_domains()

def parse_dns_logs(log_file=os.path.join(PROJECT_ROOT, "data", "sample_dns.log")):
    """Parse DNS logs and check for C2 domains."""
    c2_domains = load_c2_domains()
    alerts = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 8 or parts[4] != "query:":  # Check log format
                    print(f"Skipping malformed DNS log line: {line.strip()}")
                    continue
                timestamp = " ".join(parts[0:2])
                client_ip = parts[3].split("#")[0]
                domain = parts[5]
                if domain in c2_domains:
                    alerts.append({
                        "timestamp": timestamp,
                        "client_ip": client_ip,
                        "domain": domain,
                        "alert_type": "C2 Domain Match",
                        "severity": "High"
                    })
    except FileNotFoundError:
        print(f"Error: {log_file} not found")
    return alerts

def parse_proxy_logs(log_file=os.path.join(PROJECT_ROOT, "data", "sample_proxy.log")):
    """Parse proxy/firewall logs for large file transfers (possible encryption)."""
    alerts = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                # Debug: Print parts to inspect
                print(f"Debug: Proxy log parts: {parts}")
                # Check for minimum fields
                if len(parts) < 9:
                    print(f"Skipping malformed proxy log line: {line.strip()}")
                    continue
                # Verify bytes_transferred is numeric
                try:
                    bytes_transferred = int(parts[8])
                except ValueError:
                    print(f"Skipping proxy log line with invalid bytes: {line.strip()}")
                    continue
                timestamp = " ".join(parts[0:2])
                client_ip = parts[2].split(":")[0]
                # Extract destination domain safely
                dest_field = parts[6]
                if dest_field.startswith("http://"):
                    # Remove protocol and get domain
                    dest_domain = dest_field.split("/")[2]
                elif "/" in dest_field:
                    # Handle cases like ransomware-site.net/data
                    dest_domain = dest_field.split("/")[0]
                else:
                    # Handle plain domains
                    dest_domain = dest_field
                # Flag large transfers (>5MB) as potential encryption
                if bytes_transferred > 5_000_000:
                    alerts.append({
                        "timestamp": timestamp,
                        "client_ip": client_ip,
                        "destination": dest_domain,
                        "bytes_transferred": bytes_transferred,
                        "alert_type": "Large File Transfer",
                        "severity": "Medium"
                    })
    except FileNotFoundError:
        print(f"Error: {log_file} not found")
    return alerts

def main():
    print(f"Ransomware Traffic Detector - Started at {datetime.now()}")
    
    # Parse logs and collect alerts
    dns_alerts = parse_dns_logs()
    proxy_alerts = parse_proxy_logs()
    all_alerts = dns_alerts + proxy_alerts

    # Print alerts (later integrate with SIEM)
    if all_alerts:
        print("\nDetected Potential Ransomware Indicators:")
        for alert in all_alerts:
            print(f"[{alert['severity']}] {alert['alert_type']} at {alert['timestamp']}: "
                  f"Client {alert['client_ip']} -> {alert.get('domain', alert.get('destination', 'N/A'))}")
    else:
        print("No ransomware indicators detected.")

    # Save alerts to a file for SIEM simulation
    alerts_df = pd.DataFrame(all_alerts)
    alerts_df.to_csv(os.path.join(PROJECT_ROOT, "data", "alerts.csv"), index=False)
    print(f"Alerts saved to {os.path.join(PROJECT_ROOT, 'data', 'alerts.csv')}")

if __name__ == "__main__":
    main()

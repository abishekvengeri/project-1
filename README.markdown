# Project1: Ransomware Traffic Detector

## Project Overview
This Python-based **Ransomware Traffic Detector** showcases SOC analyst skills by analyzing DNS and proxy/firewall logs to detect ransomware activity. It identifies connections to known command-and-control (C2) domains and large file transfers (>5MB) indicative of encryption or exfiltration, generating alerts for a simulated SIEM environment. Built on Zorin OS, it demonstrates expertise in log analysis, threat detection, Python scripting, data visualization, and incident reporting.

## Skills Demonstrated
- **Log Parsing and Analysis**: Processes DNS and proxy/firewall logs to extract threat indicators.
- **Threat Detection**: Matches traffic against a configurable C2 domain list.
- **Python Scripting**: Implements log analysis and alert generation.
- **SIEM Integration**: Outputs structured alerts to CSV for SIEM compatibility.
- **Data Visualization**: Generates bar charts of alerts by severity using `matplotlib`.
- **Incident Reporting**: Provides detailed analysis and mitigation steps.

## Project Structure
```
project1/
├── configs/
│   └── c2_domains.txt     # List of known C2 domains
├── data/
│   ├── alerts.csv         # Output alerts
│   ├── sample_dns.log     # Sample DNS logs
│   └── sample_proxy.log   # Sample proxy/firewall logs
├── docs/
│   └── report.md          # Incident response writeup
├── screenshots/
│   └── alerts_plot.png    # Alert visualization
├── scripts/
│   ├── detector.py        # Main detection script
│   └── visualize.py       # Alert visualization script
├── venv/                  # Python virtual environment
├── LICENSE                # MIT License
├── requirements.txt       # Python dependencies
└── README.md              # Project documentation
```

## Prerequisites
- **Operating System**: Zorin OS (or any Linux distribution)
- **Python**: 3.12 or higher
- **Dependencies** (listed in `requirements.txt`):
  - `scapy==2.5.0` (for potential packet analysis, unused in current version)
  - `pandas==2.2.3` (for log data processing)
  - `requests==2.32.3` (for fetching C2 threat intel)
  - `matplotlib==3.9.2` (for alert visualization)
- **System Package**: `libpcap-dev` (required for `scapy`)
- **Internet Access**: For installing dependencies
- **Basic Knowledge**: Familiarity with Linux terminal and Python

## Setup Instructions
1. **Clone the Repository** (once pushed to GitHub):
   ```bash
   git clone https://github.com/abishekvengeri/project1.git
   cd project1
   ```
2. **Set Up the Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   sudo apt update
   sudo apt install libpcap-dev
   ```
3. **Run the Detection Script**:
   ```bash
   python3 scripts/detector.py
   ```
   - Analyzes `data/sample_dns.log` and `data/sample_proxy.log`, detects C2 domains and large file transfers, and saves alerts to `data/alerts.csv`.
4. **Generate Alert Visualization**:
   ```bash
   python3 scripts/visualize.py
   ```
   - Creates a bar chart of alerts by severity, saved as `screenshots/alerts_plot.png`.
5. **View Incident Report**:
   - See `docs/report.md` for a detailed incident response writeup.

## Sample Output
- **Console Output** (`detector.py`):
  ```
  Ransomware Traffic Detector - Started at 2025-10-24 20:27:00
  Debug: Proxy log parts: ['2025-10-23', '10:00:01', '192.168.1.100:54321', '->', '203.0.113.10:80', 'GET', 'http://example.com', '200', '1024', 'bytes']
  Debug: Proxy log parts: ['2025-10-23', '10:00:02', '192.168.1.100:54322', '->', '198.51.100.5:443', 'CONNECT', 'malicious-c2-domain.com', '200', '5242880', 'bytes']
  Debug: Proxy log parts: ['2025-10-23', '10:00:03', '192.168.1.101:54323', '->', '192.0.2.7:445', 'POST', 'ransomware-site.net/data', '200', '10485760', 'bytes']
  Debug: Proxy log parts: ['2025-10-23', '10:00:04', '192.168.1.100:54324', '->', '203.0.113.11:80', 'GET', 'http://legit-site.org', '200', '2048', 'bytes']
  Detected Potential Ransomware Indicators:
  [High] C2 Domain Match at 2025-10-23 10:00:03: Client 192.168.1.100 -> malicious-c2-domain.com
  [High] C2 Domain Match at 2025-10-23 10:00:04: Client 192.168.1.101 -> ransomware-site.net
  [Medium] Large File Transfer at 2025-10-23 10:00:02: Client 192.168.1.100 -> malicious-c2-domain.com
  [Medium] Large File Transfer at 2025-10-23 10:00:03: Client 192.168.1.101 -> ransomware-site.net
  Alerts saved to /home/clairvoyant/project1/data/alerts.csv
  ```
- **CSV Output** (`data/alerts.csv`):
  ```
  timestamp,client_ip,domain,alert_type,severity,destination,bytes_transferred
  2025-10-23 10:00:03,192.168.1.100,malicious-c2-domain.com,C2 Domain Match,High,,
  2025-10-23 10:00:04,192.168.1.101,ransomware-site.net,C2 Domain Match,High,,
  2025-10-23 10:00:02,192.168.1.100,,,Large File Transfer,Medium,malicious-c2-domain.com,5242880
  2025-10-23 10:00:03,192.168.1.101,,,Large File Transfer,Medium,ransomware-site.net,10485760
  ```
- **Visualization** (`screenshots/alerts_plot.png`): A bar chart showing 2 High and 2 Medium severity alerts.
- **Incident Report**: See `docs/report.md` for a detailed analysis of detected threats and mitigation steps.

## Results and Analysis
The detector identified two C2 domain connections and two large file transfers, indicating potential ransomware activity. See `docs/report.md` for a detailed incident response writeup, including mitigation steps and recommendations.

## Future Enhancements
- Add real-time DNS packet monitoring using `scapy`.
- Integrate live threat intelligence feeds via `requests`.
- Support additional log formats (e.g., Syslog, PCAP).
- Enhance visualization with interactive dashboards (e.g., Plotly).

## License
MIT License - see `LICENSE` file.

## Contact
Abishekv - [LinkedIn](https://www.linkedin.com/in/abishekvengeri/) for questions or feedback.
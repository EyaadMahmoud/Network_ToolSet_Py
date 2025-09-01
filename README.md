# Network_ToolSet_Py
A Python-based network toolkit for ARP scanning, TCP/UDP port scanning, and packet sniffing with a simple GUI interface.

---

## Features

- **Auto Network Scan:** Detects all devices in your local subnet and displays their IP and MAC addresses.  
- **Custom Network Scan:** Scan a subnet of your choice.  
- **TCP + UDP Port Scan:** Checks common ports (21, 22, 23, 80, 443, 8080) for open/closed status.  
- **Packet Sniffer:** Monitors network traffic on a chosen interface in real-time.  
- **User-friendly GUI:** Built with Tkinter and displays results in a scrollable window.
- clean line by line comments explaining each line of code
---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/Network_ToolSet_Py.git
cd Network_ToolSet_Py
```

2. Install dependencies (only required if running from source):
```markdown
pip install scapy tabulate
```

## Running the Application
Run the main script directly:
python main.py

### Optional: Using a Virtual Environment

It is recommended to use a Python virtual environment (`venv`) to isolate dependencies:
reason: to prevents conflicts with system-wide Python packages, ensures consistent dependencies, and makes it easier to manage and deploy the project safely.

```bash
python -m venv venv
source venv/bin/activate   # On Windows use `venv\Scripts\activate`
pip install scapy tabulate
```

## Executable:
  Make sure you have PyInstaller installed:
pip install pyinstaller

Navigate to the project folder containing main.py and run:
```bash
pyinstaller --onefile --windowed main.py
```
This generates an executable in the dist folder. Run the .exe directly without Python installed.


## Usage
 1. Launch the GUI.

2. Select one of the buttons: Auto Network Scan, Custom Network Scan, TCP + UDP Port Scan, or Packet Sniffer.

3. Enter requested information such as subnet, target IP, or network interface.

4. View results in the scrollable output area.


## Notes

Running the ARP scan, port scan, or packet sniffer may require administrative privileges on some systems.

Ensure network interfaces are correctly specified (e.g., eth0 for Ethernet, wlan0 for Wi-Fi on Linux, or the correct interface name on Windows).

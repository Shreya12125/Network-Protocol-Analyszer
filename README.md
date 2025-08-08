# 📡 Network Protocol Analyzer

A **web-based tool** for analyzing network traffic from `.pcap` files using **Flask** and **Scapy**.  
It identifies protocols, extracts network details, and presents results in a simple and clean web interface.  
Ideal for network monitoring, troubleshooting, and basic security analysis.

---

## 📜 Table of Contents
- [Features](#-features)
- [Technologies Used](#-technologies-used)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Performance & Limitations](#-performance--limitations)
- [Future Enhancements](#-future-enhancements)
- [License](#-license)

---

## Features
- **Protocol Identification**  
  Detects Ethernet, IP, TCP, UDP, ICMP, ARP, and IEEE protocols.
  
- **Unique MAC/IP Address Detection**  
  Displays unique source and destination MAC & IP addresses.
  
- **Port & Flag Analysis**  
  Counts unique TCP/UDP ports, SYN/FIN flags, and fragmented packets.
  
- **Packet Statistics**  
  Shows the total number of packets processed along with protocol breakdown.

---

## Technologies Used
- **Backend**: [Flask](https://flask.palletsprojects.com/) (Python)
- **Packet Processing**: [Scapy](https://scapy.net/)
- **Frontend**: HTML, CSS
- **Language**: Python 3.x

---
## Project Structure
static/ # CSS & static resources
templates/ # HTML templates for UI
uploads/ # Uploaded PCAP files
app.py # Main Flask application
.DS_Store # System file (can be ignored in Git)


---

## ⚙ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/network-protocol-analyzer.git
   cd network-protocol-analyzer
   ```
2. Create a virtual environment (optional but recommended)
   python -m venv venv
   source venv/bin/activate   # On macOS/Linux
   venv\Scripts\activate      # On Windows
3. Install Dependencies
   pip install -r requirements.txt
4. Ensure Scapy is installed
   pip install scapy

## Usage
1. Run the flask App
   python app.py
2. Open your browser and go to:
   http://127.0.0.1:5000
3. Upload a .pcap file and view:
  Detected protocols
  Unique MAC/IP addresses
  Port usage statistics
  TCP flag counts (SYN/FIN)
  Fragmented packet count
## Performance & Limitations
Best for small to medium .pcap files (under ~50MB for smooth performance).
### Limitations:
Does not perform real-time capture (static file analysis only).
Only supports common protocols.
Large files may process slowly.

## Future Enhancements
Real-time packet capture and analysis.
Support for more network protocols.
Graphical data visualization (charts & graphs).
Advanced filtering (by IP range, protocol type, time window).



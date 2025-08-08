from flask import Flask, render_template, request, send_from_directory
import os
import logging
from scapy.all import rdpcap, Ether, IP, TCP, UDP, ICMP

app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Setup logging configuration
logging.basicConfig(level=logging.WARNING, format='%(message)s')

class ResultsC:
    def __init__(self, displayMacs=False, displayIPv4=False, displayUDP=False, displayTCP=False):
        self.ethernet = "Ethernet"
        self.IEEE = "IEEE"
        self.ARP = "ARP"
        self.IPv4 = "IPv4"
        self.IPv6 = "IPv6"
        self.otherNetwork = "OtherNetwork"
        self.TCP = "TCP"
        self.UDP = "UDP"
        self.ICMP = "ICMP"
        self.otherTransport = "OtherTransport"
        self.synCount = 0
        self.finCount = 0
        self.fragCount = 0
        self.totalPacketCount = 0
        self.displayMacs = displayMacs
        self.displayIPv4 = displayIPv4
        self.displayTCP = displayTCP
        self.displayUDP = displayUDP

        self.srcMacSet = set()
        self.dstMacSet = set()
        self.srcIPv4Set = set()
        self.dstIPv4Set = set()
        self.srcUDPSet = set()
        self.dstUDPSet = set()
        self.srcTCPSet = set()
        self.dstTCPSet = set()

    def increment_syn_count(self):
        self.synCount += 1

    def increment_fin_count(self):
        self.finCount += 1

    def increment_frag_count(self):
        self.fragCount += 1

    def increment_packet_count(self):
        self.totalPacketCount += 1

    def newSrcMac(self, mac):
        self.srcMacSet.add(mac)

    def newDstMac(self, mac):
        self.dstMacSet.add(mac)

    def newSrcIPv4(self, ip):
        self.srcIPv4Set.add(ip)

    def newDstIPv4(self, ip):
        self.dstIPv4Set.add(ip)

    def newSrcUDP(self, port):
        self.srcUDPSet.add(port)

    def newDstUDP(self, port):
        self.dstUDPSet.add(port)

    def newSrcTCP(self, port):
        self.srcTCPSet.add(port)

    def newDstTCP(self, port):
        self.dstTCPSet.add(port)

    def __str__(self):
        result = f"Counts:\n"
        result += f"\tUnique srcMac = {len(self.srcMacSet)}\n"
        result += f"\tUnique dstMac = {len(self.dstMacSet)}\n"
        result += f"\tUnique srcIPv4 = {len(self.srcIPv4Set)}\n"
        result += f"\tUnique dstIPv4 = {len(self.dstIPv4Set)}\n"
        result += f"\tUnique srcUDP = {len(self.srcUDPSet)}\n"
        result += f"\tUnique dstUDP = {len(self.dstUDPSet)}\n"
        result += f"\tUnique srcTCP = {len(self.srcTCPSet)}\n"
        result += f"\tUnique dstTCP = {len(self.dstTCPSet)}\n"
        result += f"\tsynCount = {self.synCount}\n"
        result += f"\tfinCount = {self.finCount}\n"
        result += f"\tfragCount = {self.fragCount}\n"
        result += f"\ttotalPacketCount = {self.totalPacketCount}\n"

        if self.displayMacs:
            result += "\nUnique Source MAC Addresses:\n"
            for mac in self.srcMacSet:
                result += f"\t{mac}\n"

            result += "\nUnique Destination MAC Addresses:\n"
            for mac in self.dstMacSet:
                result += f"\t{mac}\n"

        if self.displayIPv4:
            result += "\nUnique Source IPv4 Addresses:\n"
            for ip in self.srcIPv4Set:
                result += f"\t{ip}\n"

            result += "\nUnique Destination IPv4 Addresses:\n"
            for ip in self.dstIPv4Set:
                result += f"\t{ip}\n"

        if self.displayUDP:
            result += "\nUnique UDP Source Ports:\n"
            for port in self.srcUDPSet:
                result += f"\t{port}\n"

            result += "\nUnique UDP Destination Ports:\n"
            for port in self.dstUDPSet:
                result += f"\t{port}\n"

        if self.displayTCP:
            result += "\nUnique TCP Source Ports:\n"
            for port in self.srcTCPSet:
                result += f"\t{port}\n"

            result += "\nUnique TCP Destination Ports:\n"
            for port in self.dstTCPSet:
                result += f"\t{port}\n"

        return result

# Function to process pcap file and populate results
def process_pcap_file(filepath, displayMacs=False, displayIPv4=False, displayUDP=False, displayTCP=False):
    results = ResultsC(displayMacs, displayIPv4, displayUDP, displayTCP)

    # Read the pcap file
    packets = rdpcap(filepath)

    # Process each packet
    for packet in packets:
        results.increment_packet_count()
        if Ether in packet:
            results.newSrcMac(packet[Ether].src)
            results.newDstMac(packet[Ether].dst)

        if IP in packet:
            results.newSrcIPv4(packet[IP].src)
            results.newDstIPv4(packet[IP].dst)
            if packet[IP].flags == 'MF':  # Fragment flag
                results.increment_frag_count()

        if UDP in packet:
            results.newSrcUDP(packet[UDP].sport)
            results.newDstUDP(packet[UDP].dport)

        if TCP in packet:
            results.newSrcTCP(packet[TCP].sport)
            results.newDstTCP(packet[TCP].dport)
            if packet[TCP].flags.S:  # SYN flag
                results.increment_syn_count()
            if packet[TCP].flags.F:  # FIN flag
                results.increment_fin_count()

    return str(results)

@app.route('/')
def index():
    return render_template('main.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'fileInput' not in request.files:
        return "No file part", 400
    
    file = request.files['fileInput']
    
    if file.filename == '':
        return "No selected file", 400
    
    # Save the file to the upload folder
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)

    # Process the PCAP file and get results
    results = process_pcap_file(filepath, displayMacs=True, displayIPv4=True, displayUDP=True, displayTCP=True)
    
    # Render results in a separate result.html template
    return render_template('result.html', filename=os.path.basename(filepath), results=results)

if __name__ == '__main__':
    app.run(debug=True)
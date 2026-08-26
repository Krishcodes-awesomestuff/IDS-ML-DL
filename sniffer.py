import sys
import time
import random
import requests

# Try importing Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[WARNING] Scapy library is not installed. To run live sniffing, run: pip install scapy")
    print("[INFO] Running in simulated live packet parser mode (no raw network driver dependency).")

# API endpoint
API_URL = "http://127.0.0.1:5000/api/simulation/packet"

# Sliding window connection tracking
connection_history = []
start_time = time.time()

def calculate_metrics_and_post(packet_data):
    """
    Sends the parsed packet metrics to the Flask backend
    """
    try:
        res = requests.post(API_URL, json=packet_data, timeout=1.5)
        if res.status_code == 200:
            result = res.json()
            predictions = result.get('predictions', {})
            rf_pred = predictions.get('random_forest', 'Normal')
            dt_pred = predictions.get('decision_tree', 'Normal')
            
            # Print to local CLI console
            status = "BLOCKED" if (rf_pred == 'Attack' or dt_pred == 'Attack') else "CLEARED"
            print(f"[{result['timestamp']}] Protocol: {result['protocol'].upper()} | Service: {result['service']} | Data Rate: {result['data_rate']} MB/s | Latency: {result['latency']}ms -> RF: {rf_pred} | DT: {dt_pred} -> [{status}]")
    except requests.exceptions.ConnectionError:
        print("[ERROR] Flask backend server is not running on http://127.0.0.1:5000. Start it first!")
    except Exception as e:
        print(f"[ERROR] Failed to send packet: {e}")

def process_scapy_packet(pkt):
    """
    Parse a real scapy packet and translate to NSL-KDD-like features
    """
    global connection_history
    
    if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
        return
        
    ip = pkt[IP]
    proto = 'tcp' if pkt.haslayer(TCP) else 'udp'
    
    # Simple port mapping for service feature
    dport = pkt.sport if proto == 'tcp' else pkt.dport
    service_map = {
        80: 'http',
        443: 'http',  # map https to http for training compatibility
        21: 'ftp',
        20: 'ftp_data',
        25: 'smtp',
        53: 'domain_u',
        23: 'telnet',
    }
    service = service_map.get(dport, 'other')
    
    # TCP flag decoding
    flag = 'SF' # Default standard connection flag
    if proto == 'tcp':
        tcp_flags = pkt[TCP].flags
        if 'S' in tcp_flags and 'A' not in tcp_flags:
            flag = 'S0'  # SYN sent, no ACK (SYN Flood indicator)
        elif 'R' in tcp_flags:
            flag = 'REJ'  # Connection rejected
            
    # Byte sizes
    src_bytes = len(pkt)
    dst_bytes = 0  # relative mapping
    
    # Track connection timestamps for sliding window (2 seconds)
    current_time = time.time()
    connection_history.append((current_time, ip.dst, service, flag))
    # Keep only connections in the last 2 seconds
    connection_history = [c for c in connection_history if current_time - c[0] <= 2.0]
    
    # Count connections to the same destination host in the last 2 seconds
    same_host_connections = [c for c in connection_history if c[1] == ip.dst]
    count = len(same_host_connections)
    
    # Count connections to the same service
    same_service_connections = [c for c in connection_history if c[2] == service]
    srv_count = len(same_service_connections)
    
    # Error rate stats
    syn_errors = sum(1 for c in same_host_connections if c[3] == 'S0')
    rej_errors = sum(1 for c in same_host_connections if c[3] == 'REJ')
    
    serror_rate = syn_errors / count if count > 0 else 0.0
    rerror_rate = rej_errors / count if count > 0 else 0.0
    
    # Determine custom metrics for dashboard visuals
    latency = 8 if flag == 'SF' else (250 if flag == 'S0' else 120)
    # Calculate throughput (data rate) dynamically: total bytes in last 2 seconds / 2
    total_bytes = sum(len(pkt) for c in same_host_connections)
    data_rate = round((total_bytes / 1024.0 / 1024.0) / 2.0, 3) # MB/s
    if data_rate == 0.0:
        data_rate = 0.01
        
    active_connections = len(connection_history)
    
    # Classify traffic profile family
    profile = 'normal'
    if flag == 'S0' and count > 30:
        profile = 'dos'
    elif flag == 'REJ' and count > 15:
        profile = 'probe'
        
    packet_data = {
        'duration': 0.0,
        'protocol_type': proto,
        'service': service,
        'flag': flag,
        'src_bytes': src_bytes,
        'dst_bytes': dst_bytes,
        'land': 0.0,
        'wrong_fragment': 0.0,
        'urgent': 0.0,
        'hot': 0.0,
        'num_failed_logins': 0.0,
        'logged_in': 1.0 if (flag == 'SF' and proto == 'tcp') else 0.0,
        'num_compromised': 0.0,
        'root_shell': 0.0,
        'su_attempted': 0.0,
        'num_root': 0.0,
        'num_file_creations': 0.0,
        'num_shells': 0.0,
        'num_access_files': 0.0,
        'num_outbound_cmds': 0.0,
        'is_host_login': 0.0,
        'is_guest_login': 0.0,
        'count': count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'srv_serror_rate': serror_rate,
        'rerror_rate': rerror_rate,
        'srv_rerror_rate': rerror_rate,
        'same_srv_rate': 1.0 - (serror_rate + rerror_rate),
        'diff_srv_rate': 0.05 if count > 0 else 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 255.0,
        'dst_host_srv_count': min(srv_count, 255.0),
        'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 0.02,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': serror_rate,
        'dst_host_srv_serror_rate': serror_rate,
        'dst_host_rerror_rate': rerror_rate,
        'dst_host_srv_rerror_rate': rerror_rate,
        'src_ip': str(ip.src),
        'profile': profile,
        'latency': latency,
        'active_connections': active_connections,
        'data_rate': data_rate
    }
    
    calculate_metrics_and_post(packet_data)

def start_simulated_sniffer():
    """
    Fallback loop generating traffic profiles based on keyboard options
    allowing presentation triggers.
    """
    print("\n--------------------------------------------------------------")
    print("MOCK NET INTERFACE SNIFFER RUNNING")
    print("Controls - Press keys to simulate real-world actions:")
    print("N: Simulate normal HTTP connection activity")
    print("D: Simulate Neptune SYN Flood DoS Attack")
    print("P: Simulate Nmap Port Scan Probe Attack")
    print("R: Simulate FTP login password cracking (R2L)")
    print("U: Simulate Root privilege escalation attempt (U2R)")
    print("Q: Exit sniffer")
    print("--------------------------------------------------------------\n")
    
    while True:
        try:
            choice = input("Enter traffic injection trigger (N/D/P/R/U/Q): ").strip().lower()
            if choice == 'q':
                print("Disconnecting sniffer interface...")
                break
                
            profile = 'normal'
            if choice == 'n':
                profile = 'normal'
            elif choice == 'd':
                profile = 'dos'
            elif choice == 'p':
                profile = 'probe'
            elif choice == 'r':
                profile = 'r2l'
            elif choice == 'u':
                profile = 'u2r'
            else:
                print("Unknown command. Triggering normal background scan.")
                profile = 'normal'
                
            # Construct NSL-KDD values for the triggered option
            packet_data = {
                'protocol_type': 'tcp' if profile != 'normal' else random.choice(['tcp', 'udp']),
                'service': 'http' if profile == 'normal' else ('private' if profile == 'dos' else 'telnet'),
                'flag': 'SF' if profile in ['normal', 'u2r', 'r2l'] else ('S0' if profile == 'dos' else 'REJ'),
                'src_bytes': random.randint(100, 1000) if profile != 'dos' else 0,
                'dst_bytes': random.randint(500, 5000) if profile != 'dos' else 0,
                'count': random.randint(150, 450) if profile == 'dos' else (random.randint(50, 150) if profile == 'probe' else random.randint(1, 10)),
                'latency': random.randint(220, 580) if profile == 'dos' else (random.randint(80, 200) if profile == 'probe' else random.randint(8, 20)),
                'active_connections': random.randint(800, 2100) if profile == 'dos' else (random.randint(110, 240) if profile == 'probe' else random.randint(10, 35)),
                'data_rate': round(random.uniform(85.0, 290.0), 2) if profile == 'dos' else (round(random.uniform(0.02, 0.35), 2) if profile == 'probe' else round(random.uniform(1.5, 8.5), 2)),
                'profile': profile
            }
            
            calculate_metrics_and_post(packet_data)
            
        except KeyboardInterrupt:
            print("\nExiting sniffer...")
            break

if __name__ == "__main__":
    print("[NIDS SNIFFER GATEWAY]")
    
    # Try binding to raw capturing driver (WinPcap/Npcap on Windows)
    if SCAPY_AVAILABLE:
        try:
            print("Detecting default network interface and starting capture...")
            print("Capturing live traffic. Press Ctrl+C to stop.")
            sniff(prn=process_scapy_packet, filter="ip and (tcp or udp)", store=0)
        except Exception as e:
            print(f"\n[ERROR] Raw capture driver failed to bind: {e}")
            print("[INFO] Typically, this requires Npcap/WinPcap installed on Windows.")
            print("[INFO] Switching to interactive console injector mode for demo presentation.")
            start_simulated_sniffer()
    else:
        start_simulated_sniffer()

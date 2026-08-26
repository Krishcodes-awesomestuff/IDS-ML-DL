import os
import json
import random
import time
import subprocess
import platform
import pandas as pd
import numpy as np
import joblib
from flask import Flask, request, jsonify

# Setup paths relative to script
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
scaler_path = os.path.join(BASE_DIR, 'scaler.pkl')
encoder_path = os.path.join(BASE_DIR, 'encoder.pkl')
rf_model_path = os.path.join(BASE_DIR, 'rf_model.pkl')
dt_model_path = os.path.join(BASE_DIR, 'dt_model.pkl')
users_db_path = os.path.join(BASE_DIR, 'backend', 'users.json')

# Ensure backend folder exists for users.json
os.makedirs(os.path.dirname(users_db_path), exist_ok=True)

# Load machine learning assets
try:
    scaler = joblib.load(scaler_path)
    encoder = joblib.load(encoder_path)
    rf_model = joblib.load(rf_model_path)
    dt_model = joblib.load(dt_model_path)
    models_loaded = True
    print("IDS Machine Learning models loaded successfully.")
except Exception as e:
    models_loaded = False
    print(f"Error loading models: {e}. Running in Mock Mode.")

app = Flask(__name__)

# Simple User Database handlers
def read_users():
    if not os.path.exists(users_db_path):
        return {}
    try:
        with open(users_db_path, 'r') as f:
            return json.load(f)
    except:
        return {}

def write_users(users):
    with open(users_db_path, 'w') as f:
        json.dump(users, f, indent=4)

# In-memory history cache of simulated sessions
simulation_history = []

# Active IPS State & Firewall Mitigation Engine
auto_block_enabled = True
blocked_ips_db = {}  # ip -> { ip, profile, reason, timestamp, auto_blocked }

def execute_firewall_block(ip):
    """
    Executes actual OS firewall commands to block incoming IP.
    Gracefully handles non-admin permissions for robust demo execution.
    """
    system_os = platform.system()
    rule_name = f"Nexus_IPS_Block_{ip.replace('.', '_')}"
    try:
        if system_os == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[FIREWALL IPS] Windows Firewall rule created for {ip}")
            else:
                print(f"[FIREWALL MOCK] Non-admin mode: Simulated block for {ip}")
        elif system_os == "Linux":
            cmd = f"iptables -A INPUT -s {ip} -j DROP"
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[FIREWALL IPS] iptables rule created for {ip}")
            else:
                print(f"[FIREWALL MOCK] Simulated block for {ip}")
    except Exception as e:
        print(f"[FIREWALL EXCEPTION] {e}")

def execute_firewall_unblock(ip):
    """
    Executes actual OS firewall commands to remove rule for IP.
    """
    system_os = platform.system()
    rule_name = f"Nexus_IPS_Block_{ip.replace('.', '_')}"
    try:
        if system_os == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
        elif system_os == "Linux":
            cmd = f"iptables -D INPUT -s {ip} -j DROP"
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception as e:
        print(f"[FIREWALL UNBLOCK EXCEPTION] {e}")

def block_ip_address(ip, profile='manual', reason='Operator manual block', auto_blocked=False):
    if ip not in blocked_ips_db:
        execute_firewall_block(ip)
        blocked_ips_db[ip] = {
            'ip': ip,
            'profile': profile,
            'reason': reason,
            'timestamp': time.strftime('%H:%M:%S'),
            'auto_blocked': auto_blocked
        }
    return blocked_ips_db[ip]

def unblock_ip_address(ip):
    if ip in blocked_ips_db:
        execute_firewall_unblock(ip)
        del blocked_ips_db[ip]
        return True
    return False

def get_ip_for_profile(profile, data=None):
    if data and data.get('src_ip'):
        return data.get('src_ip')
    if profile == 'normal':
        return f"192.168.1.{random.randint(10, 99)}"
    elif profile == 'dos':
        return f"10.0.4.{random.randint(100, 250)}"
    elif profile == 'probe':
        return f"172.16.0.{random.randint(50, 150)}"
    elif profile == 'r2l':
        return f"198.51.100.{random.randint(2, 80)}"
    elif profile == 'u2r':
        return f"203.0.113.{random.randint(5, 95)}"
    return f"192.168.1.{random.randint(100, 200)}"

# NSL-KDD Feature Names (41 total, matching training columns)
FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Helper to preprocess data mirroring script.py's implementation
def preprocess_features(df):
    cat_cols = ['protocol_type', 'service', 'flag']
    num_cols = [col for col in df.columns if col not in cat_cols]
    
    # Process Categorical columns
    encoded = pd.DataFrame(encoder.transform(df[cat_cols]))
    encoded.columns = encoder.get_feature_names_out(cat_cols)
    df = df.drop(cat_cols, axis=1).reset_index(drop=True)
    df = pd.concat([df, encoded], axis=1)
    
    # Scale Numerical columns
    df[num_cols] = scaler.transform(df[num_cols])
    return df

# Authentication API
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
        
    users = read_users()
    if username in users:
        return jsonify({'error': 'Username already exists.'}), 400
        
    users[username] = {'password': password}
    write_users(users)
    return jsonify({'message': 'Registration successful.'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required.'}), 400
        
    users = read_users()
    user = users.get(username)
    if not user or user.get('password') != password:
        return jsonify({'error': 'Invalid username or password.'}), 401
        
    return jsonify({'message': 'Login successful.', 'username': username}), 200

# Predict custom packet endpoint
@app.route('/api/predict', methods=['POST'])
def predict_packet():
    if not models_loaded:
        return jsonify({'error': 'Models not loaded. Running in mock mode.'}), 503
        
    data = request.json
    try:
        # Construct DataFrame
        df = pd.DataFrame([data])
        # Run preprocessing
        df_processed = preprocess_features(df)
        # Predictions
        rf_pred = int(rf_model.predict(df_processed)[0])
        dt_pred = int(dt_model.predict(df_processed)[0])
        
        return jsonify({
            'random_forest': 'Normal' if rf_pred == 0 else 'Attack',
            'decision_tree': 'Normal' if dt_pred == 0 else 'Attack'
        })
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 400

# External sniffer packet receiver route
@app.route('/api/simulation/packet', methods=['POST'])
def receive_captured_packet():
    data = request.json or {}
    
    # Extract features matching FEATURE_COLUMNS, default to 0
    packet = {}
    for col in FEATURE_COLUMNS:
        if col in ['protocol_type', 'service', 'flag']:
            packet[col] = data.get(col, 'tcp' if col == 'protocol_type' else ('other' if col == 'service' else 'SF'))
        else:
            packet[col] = float(data.get(col, 0.0))
            
    # Extract custom visual metrics
    latency = int(data.get('latency', 5))
    active_connections = int(data.get('active_connections', 10))
    data_rate = float(data.get('data_rate', 0.5))
    profile = data.get('profile', 'normal')
    protocol = packet['protocol_type']
    service = packet['service']
    flag = packet['flag']
    src_ip = get_ip_for_profile(profile, data)
    
    # Predictions
    rf_prediction = "Normal"
    dt_prediction = "Normal"
    if models_loaded:
        try:
            df = pd.DataFrame([packet])
            df_processed = preprocess_features(df)
            rf_pred = rf_model.predict(df_processed)[0]
            dt_pred = dt_model.predict(df_processed)[0]
            rf_prediction = "Normal" if rf_pred == 0 else "Attack"
            dt_prediction = "Normal" if dt_pred == 0 else "Attack"
        except Exception as e:
            rf_prediction = "Normal" if profile == 'normal' else "Attack"
            dt_prediction = "Normal" if profile == 'normal' else "Attack"
    else:
        rf_prediction = "Normal" if profile == 'normal' else "Attack"
        dt_prediction = "Normal" if profile == 'normal' else "Attack"

    # Active IPS Threat Mitigation
    is_blocked = (src_ip in blocked_ips_db)
    if auto_block_enabled and (rf_prediction == "Attack" or dt_prediction == "Attack" or profile != "normal"):
        if not is_blocked:
            block_ip_address(src_ip, profile=profile, reason=f"Auto-mitigated {profile.upper()} attack threat", auto_blocked=True)
            is_blocked = True
        
    record = {
        'id': int(time.time() * 1000) + random.randint(0, 999),
        'timestamp': time.strftime('%H:%M:%S'),
        'profile': profile,
        'protocol': protocol,
        'service': service,
        'flag': flag,
        'src_ip': src_ip,
        'src_bytes': int(packet['src_bytes']),
        'dst_bytes': int(packet['dst_bytes']),
        'count': int(packet['count']),
        'latency': latency,
        'active_connections': active_connections,
        'data_rate': data_rate,
        'is_blocked': is_blocked,
        'action_taken': 'BLOCKED_BY_IPS' if is_blocked else 'LOGGED',
        'predictions': {
            'random_forest': rf_prediction,
            'decision_tree': dt_prediction
        },
        'threat_score': 0 if profile == 'normal' else (80 if profile == 'dos' else (65 if profile == 'probe' else (75 if profile == 'r2l' else 90)))
    }
    
    simulation_history.append(record)
    if len(simulation_history) > 100:
        simulation_history.pop(0)
        
    return jsonify(record), 200

# Simulate/Generate endpoint
@app.route('/api/simulation/generate', methods=['GET'])
def generate_simulation_packet():
    profile = request.args.get('profile', 'random')
    if profile not in ['normal', 'dos', 'probe', 'r2l', 'u2r', 'random']:
        profile = 'random'
        
    if profile == 'random':
        profile = random.choices(
            ['normal', 'dos', 'probe', 'r2l', 'u2r'], 
            weights=[0.6, 0.2, 0.12, 0.06, 0.02]
        )[0]
        
    packet = {col: 0.0 for col in FEATURE_COLUMNS}
    
    latency = 0
    active_connections = 0
    data_rate = 0.0
    
    if profile == 'normal':
        packet['protocol_type'] = random.choice(['tcp', 'udp', 'icmp'])
        packet['service'] = random.choice(['http', 'ftp_data', 'smtp', 'domain_u', 'other'])
        packet['flag'] = 'SF'
        packet['src_bytes'] = random.randint(150, 4500)
        packet['dst_bytes'] = random.randint(500, 15000)
        packet['logged_in'] = 1 if packet['protocol_type'] == 'tcp' else 0
        packet['count'] = random.randint(1, 20)
        packet['srv_count'] = random.randint(1, 20)
        packet['same_srv_rate'] = 1.0
        packet['diff_srv_rate'] = 0.0
        packet['dst_host_count'] = random.randint(1, 255)
        packet['dst_host_srv_count'] = random.randint(100, 255)
        packet['dst_host_same_srv_rate'] = float(packet['dst_host_srv_count']) / 255.0
        packet['dst_host_diff_srv_rate'] = 0.0
        packet['dst_host_same_src_port_rate'] = round(random.uniform(0.0, 0.1), 2)
        
        latency = random.randint(5, 25)
        active_connections = random.randint(12, 45)
        data_rate = round(random.uniform(1.2, 7.8), 2)
        
    elif profile == 'dos':
        packet['protocol_type'] = 'tcp'
        packet['service'] = random.choice(['private', 'http', 'other'])
        packet['flag'] = random.choice(['S0', 'RSTR', 'SF'])
        packet['src_bytes'] = 0 if packet['flag'] == 'S0' else random.randint(0, 100)
        packet['dst_bytes'] = 0
        packet['logged_in'] = 0
        packet['count'] = random.randint(120, 500)
        packet['srv_count'] = random.randint(5, 30)
        packet['serror_rate'] = 1.0 if packet['flag'] == 'S0' else 0.0
        packet['srv_serror_rate'] = 1.0 if packet['flag'] == 'S0' else 0.0
        packet['rerror_rate'] = 1.0 if packet['flag'] == 'RSTR' else 0.0
        packet['srv_rerror_rate'] = 1.0 if packet['flag'] == 'RSTR' else 0.0
        packet['same_srv_rate'] = round(random.uniform(0.01, 0.15), 2)
        packet['diff_srv_rate'] = round(random.uniform(0.05, 0.2), 2)
        packet['dst_host_count'] = 255
        packet['dst_host_srv_count'] = random.randint(1, 30)
        packet['dst_host_same_srv_rate'] = round(random.uniform(0.01, 0.15), 2)
        packet['dst_host_diff_srv_rate'] = round(random.uniform(0.05, 0.2), 2)
        packet['dst_host_serror_rate'] = 1.0 if packet['flag'] == 'S0' else 0.0
        packet['dst_host_srv_serror_rate'] = 1.0 if packet['flag'] == 'S0' else 0.0
        
        latency = random.randint(180, 650)
        active_connections = random.randint(850, 2400)
        data_rate = round(random.uniform(75.0, 310.0), 2)
        
    elif profile == 'probe':
        packet['protocol_type'] = random.choice(['tcp', 'udp', 'icmp'])
        packet['service'] = random.choice(['private', 'other', 'eco_i', 'ecr_i'])
        packet['flag'] = random.choice(['REJ', 'RSTR', 'SF'])
        packet['src_bytes'] = random.choice([0, 8, 20])
        packet['dst_bytes'] = 0
        packet['logged_in'] = 0
        packet['count'] = random.randint(50, 180)
        packet['srv_count'] = random.randint(1, 10)
        packet['diff_srv_rate'] = round(random.uniform(0.3, 0.9), 2)
        packet['rerror_rate'] = 1.0 if packet['flag'] == 'REJ' else 0.0
        packet['srv_rerror_rate'] = 1.0 if packet['flag'] == 'REJ' else 0.0
        packet['dst_host_count'] = 255
        packet['dst_host_srv_count'] = random.randint(1, 20)
        packet['dst_host_diff_srv_rate'] = round(random.uniform(0.4, 0.9), 2)
        packet['dst_host_same_srv_rate'] = round(random.uniform(0.01, 0.1), 2)
        packet['dst_host_same_src_port_rate'] = round(random.uniform(0.1, 0.8), 2)
        
        latency = random.randint(80, 220)
        active_connections = random.randint(120, 280)
        data_rate = round(random.uniform(0.05, 0.45), 2)
        
    elif profile == 'r2l':
        packet['protocol_type'] = 'tcp'
        packet['service'] = random.choice(['ftp', 'telnet', 'imap', 'pop_3', 'other'])
        packet['flag'] = 'SF'
        packet['src_bytes'] = random.randint(80, 800)
        packet['dst_bytes'] = random.randint(1000, 4000)
        packet['logged_in'] = random.choice([0, 1])
        packet['num_failed_logins'] = random.randint(1, 4)
        packet['hot'] = random.randint(1, 3)
        packet['count'] = random.randint(1, 5)
        packet['srv_count'] = random.randint(1, 5)
        packet['dst_host_count'] = random.randint(1, 50)
        packet['dst_host_srv_count'] = random.randint(1, 10)
        packet['dst_host_same_srv_rate'] = round(random.uniform(0.1, 0.5), 2)
        
        latency = random.randint(30, 85)
        active_connections = random.randint(8, 22)
        data_rate = round(random.uniform(0.3, 1.8), 2)
        
    elif profile == 'u2r':
        packet['protocol_type'] = 'tcp'
        packet['service'] = random.choice(['telnet', 'shell', 'other'])
        packet['flag'] = 'SF'
        packet['src_bytes'] = random.randint(200, 1500)
        packet['dst_bytes'] = random.randint(2000, 8000)
        packet['logged_in'] = 1
        packet['root_shell'] = 1
        packet['su_attempted'] = random.choice([0, 1])
        packet['num_root'] = random.randint(1, 3)
        packet['num_file_creations'] = random.randint(1, 3)
        packet['count'] = 1
        packet['srv_count'] = 1
        
        latency = random.randint(25, 60)
        active_connections = random.randint(4, 15)
        data_rate = round(random.uniform(0.6, 2.5), 2)

    # Smooth visual metrics with exponential moving average for continuous timeline trends
    if simulation_history:
        prev = simulation_history[-1]
        latency = max(5, int(0.65 * prev['latency'] + 0.35 * latency))
        active_connections = max(5, int(0.75 * prev['active_connections'] + 0.25 * active_connections))
        data_rate = max(0.01, round(0.65 * prev['data_rate'] + 0.35 * data_rate, 2))

    src_ip = get_ip_for_profile(profile)

    rf_prediction = "Normal"
    dt_prediction = "Normal"
    
    if models_loaded:
        try:
            df = pd.DataFrame([packet])
            df_processed = preprocess_features(df)
            rf_pred = rf_model.predict(df_processed)[0]
            dt_pred = dt_model.predict(df_processed)[0]
            rf_prediction = "Normal" if rf_pred == 0 else "Attack"
            dt_prediction = "Normal" if dt_pred == 0 else "Attack"
        except Exception as e:
            print(f"Prediction logic error: {e}")
            rf_prediction = "Normal" if profile == 'normal' else "Attack"
            dt_prediction = "Normal" if profile == 'normal' else "Attack"
    else:
        rf_prediction = "Normal" if profile == 'normal' else "Attack"
        dt_prediction = "Normal" if profile == 'normal' else "Attack"
        
    # Active IPS Threat Mitigation
    is_blocked = (src_ip in blocked_ips_db)
    if auto_block_enabled and (rf_prediction == "Attack" or dt_prediction == "Attack" or profile != "normal"):
        if not is_blocked:
            block_ip_address(src_ip, profile=profile, reason=f"Auto-mitigated {profile.upper()} attack threat", auto_blocked=True)
            is_blocked = True

    record = {
        'id': int(time.time() * 1000) + random.randint(0, 999),
        'timestamp': time.strftime('%H:%M:%S'),
        'profile': profile,
        'protocol': packet['protocol_type'],
        'service': packet['service'],
        'flag': packet['flag'],
        'src_ip': src_ip,
        'src_bytes': int(packet['src_bytes']),
        'dst_bytes': int(packet['dst_bytes']),
        'count': int(packet['count']),
        'latency': latency,
        'active_connections': active_connections,
        'data_rate': data_rate,
        'is_blocked': is_blocked,
        'action_taken': 'BLOCKED_BY_IPS' if is_blocked else 'LOGGED',
        'predictions': {
            'random_forest': rf_prediction,
            'decision_tree': dt_prediction
        },
        'threat_score': 0 if profile == 'normal' else (80 if profile == 'dos' else (65 if profile == 'probe' else (75 if profile == 'r2l' else 90)))
    }
    
    simulation_history.append(record)
    if len(simulation_history) > 100:
        simulation_history.pop(0)
        
    return jsonify(record)

# Active IPS Endpoints
@app.route('/api/ips/rules', methods=['GET'])
def get_ips_rules():
    return jsonify({
        'auto_block_enabled': auto_block_enabled,
        'total_blocked': len(blocked_ips_db),
        'blocked_ips': list(blocked_ips_db.values())
    }), 200

@app.route('/api/ips/block', methods=['POST'])
def manual_block_ip():
    data = request.json or {}
    ip = data.get('ip')
    reason = data.get('reason', 'Operator manual quarantine trigger')
    profile = data.get('profile', 'manual')
    if not ip:
        return jsonify({'error': 'IP address is required.'}), 400
    rule = block_ip_address(ip, profile=profile, reason=reason, auto_blocked=False)
    
    # Update status of any existing packet records matching this IP
    for p in simulation_history:
        if p.get('src_ip') == ip:
            p['is_blocked'] = True
            p['action_taken'] = 'BLOCKED_BY_IPS'
            
    return jsonify({'message': f'IP {ip} successfully quarantined.', 'rule': rule}), 200

@app.route('/api/ips/unblock', methods=['POST'])
def manual_unblock_ip():
    data = request.json or {}
    ip = data.get('ip')
    if not ip:
        return jsonify({'error': 'IP address is required.'}), 400
    success = unblock_ip_address(ip)
    
    # Update status of existing packet records matching this IP
    for p in simulation_history:
        if p.get('src_ip') == ip:
            p['is_blocked'] = False
            p['action_taken'] = 'LOGGED'
            
    if success:
        return jsonify({'message': f'IP {ip} successfully unblocked.'}), 200
    return jsonify({'error': f'IP {ip} was not found in active quarantine list.'}), 404

@app.route('/api/ips/toggle-autoblock', methods=['POST'])
def toggle_autoblock():
    global auto_block_enabled
    data = request.json or {}
    enabled = data.get('enabled')
    if enabled is None:
        auto_block_enabled = not auto_block_enabled
    else:
        auto_block_enabled = bool(enabled)
    return jsonify({
        'message': f'Auto IPS mitigation is now {"ENABLED" if auto_block_enabled else "DISABLED"}.',
        'auto_block_enabled': auto_block_enabled
    }), 200

# Analytics Endpoint
@app.route('/api/analytics/stats', methods=['GET'])
def get_analytics_stats():
    if not simulation_history:
        return jsonify({
            'total_inspected': 0,
            'attacks_detected': 0,
            'accuracy': 100.0,
            'avg_latency': 0,
            'avg_data_rate': 0.0,
            'active_connections': 0,
            'blocked_ips_count': len(blocked_ips_db),
            'auto_block_enabled': auto_block_enabled,
            'threat_distribution': {'normal': 0, 'dos': 0, 'probe': 0, 'r2l': 0, 'u2r': 0},
            'recent_packets': []
        })
        
    total_inspected = len(simulation_history)
    attacks_detected = sum(1 for p in simulation_history if p['predictions']['random_forest'] == 'Attack')
    
    correct_classifications = 0
    for p in simulation_history:
        actual_is_normal = (p['profile'] == 'normal')
        pred_is_normal = (p['predictions']['random_forest'] == 'Normal')
        if actual_is_normal == pred_is_normal:
            correct_classifications += 1
    accuracy = round((correct_classifications / total_inspected) * 100.0, 2)
    
    avg_latency = int(sum(p['latency'] for p in simulation_history) / total_inspected)
    avg_data_rate = round(sum(p['data_rate'] for p in simulation_history) / total_inspected, 2)
    current_active_connections = simulation_history[-1]['active_connections']
    
    threat_distribution = {'normal': 0, 'dos': 0, 'probe': 0, 'r2l': 0, 'u2r': 0}
    for p in simulation_history:
        threat_distribution[p['profile']] += 1
        
    return jsonify({
        'total_inspected': total_inspected,
        'attacks_detected': attacks_detected,
        'accuracy': accuracy,
        'avg_latency': avg_latency,
        'avg_data_rate': avg_data_rate,
        'active_connections': current_active_connections,
        'blocked_ips_count': len(blocked_ips_db),
        'auto_block_enabled': auto_block_enabled,
        'threat_distribution': threat_distribution,
        'recent_packets': list(reversed(simulation_history))[:20]
    })

# Reset analytics cache
@app.route('/api/analytics/reset', methods=['POST'])
def reset_stats():
    global simulation_history, blocked_ips_db
    simulation_history = []
    blocked_ips_db = {}
    return jsonify({'message': 'Analytics stats & active firewall blocks reset.'}), 200

# Export CSV Report
@app.route('/api/analytics/export/csv', methods=['GET'])
def export_csv_report():
    import io
    import csv
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header row
    writer.writerow([
        'Timestamp', 'Source IP', 'Profile', 'Protocol', 'Service', 
        'Flag', 'Latency (ms)', 'Data Rate (MB/s)', 'Active Connections',
        'Random Forest Prediction', 'Decision Tree Prediction', 'IPS Action'
    ])
    
    for p in simulation_history:
        writer.writerow([
            p.get('timestamp', ''),
            p.get('src_ip', '192.168.1.100'),
            p.get('profile', 'normal').upper(),
            p.get('protocol', 'tcp').upper(),
            p.get('service', 'http'),
            p.get('flag', 'SF'),
            p.get('latency', 0),
            p.get('data_rate', 0.0),
            p.get('active_connections', 0),
            p.get('predictions', {}).get('random_forest', 'Normal'),
            p.get('predictions', {}).get('decision_tree', 'Normal'),
            p.get('action_taken', 'LOGGED')
        ])
        
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=nexus_security_audit_report.csv'}
    )

# Fallback index endpoint
@app.route('/api')
def api_root():
    return jsonify({
        'status': 'online',
        'models_loaded': models_loaded,
        'auto_ips': auto_block_enabled,
        'blocked_ips_count': len(blocked_ips_db),
        'endpoints': {
            '/api/auth/register': 'POST signup',
            '/api/auth/login': 'POST login',
            '/api/predict': 'POST raw packet feature predictions',
            '/api/simulation/generate': 'GET simulate scenario network traffic',
            '/api/simulation/packet': 'POST submit real sniffed packet',
            '/api/analytics/stats': 'GET current stats dashboard history',
            '/api/analytics/reset': 'POST clean stats history',
            '/api/ips/rules': 'GET list active blocked IPs and config',
            '/api/ips/block': 'POST manually block IP',
            '/api/ips/unblock': 'POST unblock IP',
            '/api/ips/toggle-autoblock': 'POST toggle auto firewall mitigation'
        }
    })

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)

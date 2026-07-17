# 🛡️ Nexus: AI-Powered Network Intrusion Detection System (NIDS)

## 📌 Overview
Nexus is an enterprise-grade, real-time Network Intrusion Detection System (NIDS) powered by Machine Learning. Designed to transcend the limitations of traditional signature-based firewalls, Nexus leverages advanced behavioral analysis to detect, classify, and mitigate zero-day network threats with millisecond latency. 

Built with a scalable **microservices architecture**—comprising a high-performance Python/Flask ML inference engine, a lightweight real-time network sniffer, and a reactive React/TypeScript dashboard—Nexus provides actionable intelligence for modern Security Operations Centers (SOC).

## 🚀 Key Features
* **Behavioral Threat Detection**: Utilizes Machine Learning (Random Forest & Decision Trees) trained on the NSL-KDD dataset to classify traffic anomalies (DoS, Probe, U2R, R2L) rather than relying on static signatures.
* **Real-Time Packet Inspection**: A custom lightweight sensor (`sniffer.py`) powered by Scapy continuously analyzes TCP/UDP headers, calculates complex network statistics in sliding windows, and streams 41 distinct behavioral features.
* **Low-Latency Inference Engine**: A RESTful Flask backend acting as the central intelligence hub, capable of decoding categorical protocols and flags and running parallelized model inferences instantly.
* **Interactive Threat Dashboard**: A sleek, dark-mode SOC dashboard built in React & TypeScript. It features dynamic Chart.js visualizations for live network throughput, latency, connection spikes, and an automated threat terminal.
* **Nmap Simulation Integration**: Built-in capabilities to simulate real-world attacks (e.g., stealth SYN scans) on a loopback environment to demonstrate instant AI threat flagging.

## 🛠️ Technology Stack
* **Frontend**: React.js, TypeScript, Vite, Vanilla CSS (Glassmorphism UI), Chart.js
* **Backend**: Python, Flask, REST APIs
* **Machine Learning & Data Science**: Scikit-Learn (Random Forest, Decision Trees), Pandas, NumPy, RobustScaler
* **Network Interception**: Scapy, Npcap / WinPcap

## 🧠 System Architecture
1. **Network Sensor (`sniffer.py`)**: Attaches to the NIC, passively capturing frames. Extracts and aggregates feature states (error rates, connection counts, protocol states) over time without blocking the network thread.
2. **Inference API (`app.py`)**: Receives the telemetry. Applies `.pkl` encoded transformations, standardizes numerical data, and invokes the ML models to classify the packet state.
3. **SOC Dashboard (`frontend/`)**: Constantly polls to the inference engine to visualize metrics and issue warnings.

## ⚙️ Installation & Usage

### 1. Backend ML Engine
```bash
# Clone the repository
git clone https://github.com/Krishcodes-awesomestuff/IDS-ML-DL.git
cd IDS-ML-DL

# Install Python dependencies (ensure you have scikit-learn, pandas, flask, scapy installed)
# e.g., pip install flask pandas scikit-learn scapy flask-cors

# Start the Flask API server
cd backend
python app.py
```

### 2. Frontend SOC Dashboard
```bash
# Navigate to frontend directory
cd frontend

# Install Node dependencies
npm install

# Start the Vite development server
npm run dev
```

### 3. Network Sniffer
```bash
# Ensure the backend is running first
# Requires Npcap (Windows) or root privileges (Linux/macOS)
# Run the sniffer to begin feeding live traffic to the engine
python sniffer.py
```

## 📈 Machine Learning Pipeline
* **Dataset**: NSL-KDD (an improved iteration of KDD'99, eliminating redundant records).
* **Preprocessing**: 
  * Categorical features (`protocol_type`, `service`, `flag`) encoded via One-Hot Encoding (`handle_unknown='ignore'`).
  * Continuous features scaled using `RobustScaler` to minimize outlier distortion from extreme traffic spikes.
* **Models**: Evaluated Random Forest and Decision Tree classifiers for their speed and resistance to overfitting.

## 👨‍💻 Why This Matters (Engineering Focus)
* **Scale & Performance**: The split architecture allows the network sensor to be deployed on edge routers while the heavy ML inference occurs on a centralized scalable backend.
* **Resiliency**: The system handles unknown categorical features gracefully in production without crashing, ensuring 100% uptime in active network environments.
* **Extensibility**: The React + TSX frontend is entirely decoupled, paving the way for WebSocket integration, multiple SOC users, and OAuth integration in the future.
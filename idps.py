from flask import Flask, request, jsonify, render_template
import datetime
from collections import defaultdict

app = Flask(__name__)

# In-memory storage for intrusion logs
intrusion_logs = []

# Signature-based detection patterns
MALICIOUS_SIGNATURES = [
    "malware", "attack", "exploit", "virus", "trojan",
    "worm", "ransomware", "phishing", "brute force",
    "sql injection", "xss", "ddos"
]

# CSS for professional cybersecurity theme
CYBER_SECURITY_CSS = """
:root {
    --primary: #0a0a12;
    --secondary: #161622;
    --accent: #ff2a4d;
    --accent-dark: #cc1f3a;
    --text: #f0f0f5;
    --text-secondary: #a0a0b0;
    --danger: #ff2a4d;
    --warning: #ff9a3d;
    --success: #00d67c;
    --card-glow: 0 0 15px rgba(255, 42, 77, 0.3);
}

/* Main content */
.main-content {
    opacity: 1;
}

/* Result animations */
@keyframes slideIn {
    from { transform: translateY(20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}

.result-card {
    animation: slideIn 0.5s ease-out forwards;
}

/* Analyze button animation */
.btn-analyzing {
    position: relative;
    overflow: hidden;
}

.btn-analyzing::after {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
    animation: loading 1.5s infinite;
}

@keyframes loading {
    0% { left: -100%; }
    100% { left: 100%; }
}

body {
    font-family: 'Inter', 'Segoe UI', sans-serif;
    background-color: var(--primary);
    color: var(--text);
    margin: 0;
    padding: 0;
    line-height: 1.6;
}

.header {
    background: linear-gradient(135deg, #000 0%, #1a0a0e 100%);
    padding: 1.5rem 0;
    border-bottom: 1px solid var(--accent);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
}

.header-content {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.logo-icon {
    width: 40px;
    height: 40px;
    fill: var(--accent);
}

h1 {
    font-size: 1.8rem;
    font-weight: 600;
    margin: 0;
    background: linear-gradient(to right, var(--accent), #ff7e8a);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
}

.card {
    background: var(--secondary);
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
    box-shadow: var(--card-glow);
    border: 1px solid #252535;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 25px rgba(255, 42, 77, 0.4);
}

/* Form styles */
.form-group {
    margin-bottom: 1.5rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--accent);
    font-weight: 500;
    font-size: 0.95rem;
}

.form-control {
    width: 100%;
    padding: 0.8rem 1rem;
    background: #1e1e2e;
    border: 1px solid #303040;
    border-radius: 8px;
    color: var(--text);
    font-family: 'Roboto Mono', monospace;
    transition: border 0.3s ease;
}

.form-control:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 2px rgba(255, 42, 77, 0.2);
}

/* Button styles */
.btn {
    background: linear-gradient(135deg, var(--accent), var(--accent-dark));
    color: white;
    border: none;
    padding: 0.8rem 1.8rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 1rem;
    cursor: pointer;
    transition: all 0.3s ease;
    box-shadow: 0 4px 15px rgba(255, 42, 77, 0.3);
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
}

.btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(255, 42, 77, 0.4);
}

.btn:active {
    transform: translateY(0);
}

.btn-icon {
    width: 18px;
    height: 18px;
}

/* Result styles */
.result-card {
    padding: 1.5rem;
    border-radius: 10px;
    margin-top: 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    border-left: 4px solid;
    background: #1a1a2a;
    animation: fadeIn 0.5s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.result-normal {
    border-color: var(--success);
}

.result-malicious {
    border-color: var(--danger);
}

.result-anomalous {
    border-color: var(--warning);
}

.result-icon {
    flex-shrink: 0;
    width: 36px;
    height: 36px;
}

.result-content h3 {
    margin: 0 0 0.5rem 0;
    font-size: 1.2rem;
}

.result-content p {
    margin: 0;
    color: var(--text-secondary);
}

/* Table styles */
.intrusion-table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin-top: 1rem;
}

.intrusion-table th {
    background: #1e1e2e;
    color: var(--accent);
    padding: 0.8rem 1rem;
    text-align: left;
    font-weight: 600;
    border-bottom: 2px solid var(--accent);
}

.intrusion-table td {
    padding: 0.8rem 1rem;
    border-bottom: 1px solid #252535;
}

.intrusion-table tr:last-child td {
    border-bottom: none;
}

.status-badge {
    display: inline-block;
    padding: 0.25rem 0.6rem;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}

.badge-malicious {
    background: rgba(255, 42, 77, 0.15);
    color: var(--danger);
}

.badge-anomalous {
    background: rgba(255, 154, 61, 0.15);
    color: var(--warning);
}
"""

# HTML template for the UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Sniff & Shield IDPS</title>
    <style>{css}</style>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Roboto+Mono&display=swap" rel="stylesheet">
</head>
<body>
    <div class="header">
        <div class="container header-content">
            <svg class="logo-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" fill="currentColor"/>
            </svg>
            <h1 class="title-glitch">INTRUSION DETECTION</h1>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
    <div class="container">
        <div class="card">
            <h2>Network Event Analysis</h2>
            <form id="eventForm">
                <div class="form-group">
                    <label for="source_ip">Source IP</label>
                    <input type="text" class="form-control" id="source_ip" placeholder="192.168.1.1" required>
                </div>
                <div class="form-group">
                    <label for="dest_ip">Destination IP</label>
                    <input type="text" class="form-control" id="dest_ip" placeholder="10.0.0.1" required>
                </div>
                <div class="form-group">
                    <label for="protocol">Protocol</label>
                    <select class="form-control" id="protocol" required>
                        <option value="">Select protocol</option>
                        <option value="TCP">TCP</option>
                        <option value="UDP">UDP</option>
                        <option value="ICMP">ICMP</option>
                        <option value="HTTP">HTTP</option>
                        <option value="HTTPS">HTTPS</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="payload">Payload Content</label>
                    <textarea class="form-control" id="payload" rows="3" placeholder="Enter network payload..." required></textarea>
                </div>
                <div class="form-group">
                    <label for="packet_size">Packet Size (bytes)</label>
                    <input type="number" class="form-control" id="packet_size" placeholder="1500" required>
                </div>
                <button type="submit" class="btn">
                    <svg class="btn-icon" viewBox="0 0 24 24" fill="none">
                        <path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" fill="currentColor"/>
                    </svg>
                    Analyze Event
                </button>
            </form>
            <div id="result"></div>
        </div>
        
        <div class="card">
            <h2>Detection Log</h2>
            <div id="intrusions">
                <p>No intrusions detected yet.</p>
            </div>
        </div>
    </div>
    </div>
    
    <script>
        // Add glitch effect to title
        document.addEventListener('DOMContentLoaded', function() {
            const title = document.querySelector('.title-glitch');
            if (title) {
                title.addEventListener('mouseover', function() {
                    this.classList.add('glitch');
                    setTimeout(() => this.classList.remove('glitch'), 500);
                });
            }
        });
        
        // Icons for different result types
        const icons = {{
            normal: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" fill="#00d67c"/></svg>',
            malicious: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4 14.59L14.59 16 12 13.41 9.41 16 8 14.59 10.59 12 8 9.41 9.41 8 12 10.59 14.59 8 16 9.41 13.41 12 16 14.59z" fill="#ff2a4d"/></svg>',
            anomalous: '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" fill="#ff9a3d"/></svg>'
        }};

        document.getElementById('eventForm').addEventListener('submit', function(e) {{
            e.preventDefault();
            
            const event = {{
                source_ip: document.getElementById('source_ip').value,
                dest_ip: document.getElementById('dest_ip').value,
                protocol: document.getElementById('protocol').value,
                payload: document.getElementById('payload').value,
                packet_size: parseInt(document.getElementById('packet_size').value),
                timestamp: new Date().toISOString()
            }};
            
            const analyzeBtn = document.querySelector('button[type="submit"]');
            const originalBtnText = analyzeBtn.innerHTML;
            analyzeBtn.disabled = true;
            analyzeBtn.classList.add('btn-analyzing');
            analyzeBtn.innerHTML = '\\n                <svg class="btn-icon" viewBox="0 0 24 24" fill="none">\\n                    <path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46A7.93 7.93 0 0020 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74A7.93 7.93 0 004 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z" fill="currentColor"/>\\n                </svg>\\n                Analyzing...\\n            ';

            fetch('/analyze', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify(event)
            }})
            .then(response => response.json())
            .then(data => {{
                const resultDiv = document.getElementById('result');
                
                // Clear previous result with fade out
                resultDiv.style.opacity = '0';
                resultDiv.style.transition = 'opacity 0.3s';
                
                setTimeout(function() {
                    resultDiv.innerHTML = '';
                    resultDiv.style.opacity = '1';
                }, 300);
                
                // Create result card based on detection type
                const resultCard = document.createElement('div');
                resultCard.style.opacity = '0';
                resultCard.style.transform = 'translateY(20px)';
                resultCard.style.transition = 'all 0.5s ease-out';
                
                if (!data.is_intrusion) {{
                    resultCard.className = 'result-card result-normal';
                    resultCard.innerHTML = '<div class="result-icon">' + icons.normal + '</div>' +
                        '<div class="result-content">' +
                        '<h3>Normal Traffic</h3>' +
                        '<p>No suspicious activity detected.</p>' +
                        '</div>';
                }} else if (data.reason.includes('Malicious')) {{
                    resultCard.className = 'result-card result-malicious';
                    resultCard.innerHTML = '<div class="result-icon">' + icons.malicious + '</div>' +
                        '<div class="result-content">' +
                        '<h3>Malicious Content Detected!</h3>' +
                        '<p>' + data.reason + '</p>' +
                        '</div>';
                }} else {{
                    resultCard.className = 'result-card result-anomalous';
                    resultCard.innerHTML = '<div class="result-icon">' + icons.anomalous + '</div>' +
                        '<div class="result-content">' +
                        '<h3>Anomalous Activity Detected!</h3>' +
                        '<p>' + data.reason + '</p>' +
                        '</div>';
                }}
                
                resultDiv.appendChild(resultCard);
                // Trigger reflow
                void resultCard.offsetWidth;
                // Apply visible state
                resultCard.style.opacity = '1';
                resultCard.style.transform = 'translateY(0)';
                
                // Reset button state
                analyzeBtn.disabled = false;
                analyzeBtn.classList.remove('btn-analyzing');
                analyzeBtn.innerHTML = originalBtnText;
                refreshIntrusions();
            }});
        }});
        
        function refreshIntrusions() {{
            const intrusionsDiv = document.getElementById('intrusions');
            intrusionsDiv.innerHTML = '<div class="loading">Loading intrusions...</div>';
            
            fetch('/intrusions')
            .then(response => {{
                if (!response.ok) throw new Error('Network error');
                return response.json();
            }})
            .then(data => {{
                if (data.length === 0) {{
                    intrusionsDiv.innerHTML = '<p>No intrusions detected yet.</p>';
                    return;
                }}
                
                let html = '<table class="intrusion-table">';
                html += `
                    <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Type</th>
                        <th>Details</th>
                    </tr>
                `;
                
                data.forEach(function(intrusion) {{
                    const isMalicious = intrusion.reason.includes('signature');
                    html += '\n                        <tr>\n                            <td>' + new Date(intrusion.timestamp).toLocaleTimeString() + '</td>\n                            <td>' + intrusion.source_ip + '</td>\n                            <td>' + intrusion.dest_ip + '</td>\n                            <td>\n                                <span class="status-badge ' + (isMalicious ? 'badge-malicious' : 'badge-anomalous') + '">\n                                    ' + (isMalicious ? 'MALICIOUS' : 'ANOMALOUS') + '\n                                </span>\n                            </td>\n                            <td>' + intrusion.reason + '</td>\n                        </tr>\n                    ';
                }});
                
                html += '</table>';
                intrusionsDiv.innerHTML = html;
            }})
            .catch(error => {{
                console.error('Error:', error);
                intrusionsDiv.innerHTML = '<p class="error">Failed to load intrusions. ' + error.message + '</p>';
            }});
        }}
        
        // Load initial intrusion list
        refreshIntrusions();
    </script>
</body>
</html>
""".replace('{css}', CYBER_SECURITY_CSS.replace('\\', '\\\\').replace('"', '\\"'))

def detect_intrusion(event):
    """
    Analyze network event for potential intrusions using:
    1. Signature-based detection (malicious keywords in payload)
    2. Anomaly-based detection (unusual protocol or large packet size)
    """
    reasons = []
    
    # Signature-based detection
    payload_lower = event['payload'].lower()
    for signature in MALICIOUS_SIGNATURES:
        if signature in payload_lower:
            reasons.append(f"Malicious signature detected: '{signature}'")
    
    # Anomaly-based detection
    if event['packet_size'] > 1500:  # Large packet size
        reasons.append(f"Large packet size detected: {event['packet_size']} bytes")
    
    if event['protocol'] in ['ICMP', 'UDP']:  # Unusual protocols for certain contexts
        reasons.append(f"Unusual protocol detected: {event['protocol']}")
    
    if reasons:
        return True, ", ".join(reasons)
    return False, ""

@app.route('/')
def index():
    """Render the main UI"""
    return HTML_TEMPLATE

@app.route('/analyze', methods=['POST'])
def analyze_event():
    """
    Endpoint to analyze network events
    Accepts JSON with: source_ip, dest_ip, protocol, payload, packet_size, timestamp
    Returns JSON with is_intrusion (bool) and reason (str) if intrusion detected
    """
    event = request.get_json()
    
    # Add timestamp if not provided
    if 'timestamp' not in event:
        event['timestamp'] = datetime.datetime.now().isoformat()
    
    is_intrusion, reason = detect_intrusion(event)
    
    if is_intrusion:
        intrusion_log = {
            **event,
            'reason': reason,
            'detected_at': datetime.datetime.now().isoformat()
        }
        intrusion_logs.append(intrusion_log)
    
    return jsonify({
        'is_intrusion': is_intrusion,
        'reason': reason if is_intrusion else "No intrusion detected"
    })

@app.route('/intrusions', methods=['GET'])
def get_intrusions():
    """
    Endpoint to retrieve all detected intrusions
    Returns JSON array of intrusion logs
    """
    return jsonify(intrusion_logs)

if __name__ == '__main__':
    app.run(debug=True, port=5000)

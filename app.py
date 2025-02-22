import os
import re
import yara
import hashlib
import requests
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS

# Import our database and ScanLog model from models.py
from models import db, ScanLog

# --------------------
# 1. Basic Configuration
# --------------------
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

app.config['SECRET_KEY'] = 'your_secret_key_here'

# Set BASE_DIR to the directory where app.py resides
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define the default YARA rules file path (for default scanning and rule counting)
DEFAULT_RULES_PATH = os.path.join(BASE_DIR, 'rules', 'malware_rules.yar')

# Directory to store uploaded files
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'scan_logs.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database with the app
db.init_app(app)
with app.app_context():
    db.create_all()

# --------------------
# 2. Utility Functions and Constants
# --------------------
ALLOWED_EXTENSIONS = {'exe', 'yar', 'yara'}

def allowed_file(filename, exts):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in exts

def log_scan(filename, scan_type, result):
    log = ScanLog(filename=filename, scan_type=scan_type, result=result)
    db.session.add(log)
    db.session.commit()

def generate_yara_rule(rule_name, strings, condition_operator="and"):
    """
    Build a simple YARA rule from provided strings.
    """
    rule = f"rule {rule_name} {{\n"
    rule += "    strings:\n"
    for idx, s in enumerate(strings):
        rule += f"        $s{idx} = \"{s}\"\n"
    rule += "\n    condition:\n"
    rule += "        " + f" {condition_operator} ".join([f"$s{idx}" for idx in range(len(strings))]) + "\n"
    rule += "}"
    return rule

# --- External Integration: VirusTotal API ---
VIRUSTOTAL_API_KEY = os.getenv("API_KEY")   # Replace with your VirusTotal API key
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"
if not VIRUSTOTAL_API_KEY:
    raise ValueError("API Key not found. Please set API_KEY in .env file.")

print("API Key Loaded Successfully")
def get_virustotal_score(file_path):
    """
    Computes the SHA256 hash of the file and sends it to VirusTotal.
    Returns a threat score (0-100) based on the ratio of malicious detections.
    """
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        # For a real implementation, you might first check if this hash was already analyzed.
        files = {"file": file_bytes}
        response = requests.post(VIRUSTOTAL_URL, headers=headers, files={"file": f})
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            score = (malicious / total) * 100 if total > 0 else 0
            return round(score, 2)
        else:
            print(f"VirusTotal API error: {response.status_code} - {response.text}")
            return 0
    except Exception as e:
        print(f"Error querying VirusTotal: {e}")
        return 0

def count_yara_rules(yara_file_path):
    """
    Count the number of rule definitions in a YARA file using a regex.
    """
    try:
        with open(yara_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        # Matches lines starting with "rule" followed by a word and a '{'
        rules = re.findall(r'(?m)^\s*rule\s+\w+\s*\{', content)
        return len(rules) if len(rules) > 0 else 1
    except Exception as e:
        print("Error counting rules:", e)
        return 1

TOTAL_YARA_RULES = count_yara_rules(DEFAULT_RULES_PATH)

def calculate_vulnerability_score(yara_matches, vt_score):
    """
    Calculates an internal vulnerability score based on YARA matches.
    Each rule is weighted evenly over the total number of rules.
    Then combines the YARA score and VirusTotal score (simple average).
    """
    per_rule_weight = 100 / TOTAL_YARA_RULES
    yara_score = len(yara_matches) * per_rule_weight
    total_score = (yara_score + vt_score) / 2
    return round(total_score, 2)

# --------------------
# 3. API Endpoints
# --------------------

# A) Scan an uploaded .exe using default YARA rules (without external API)
@app.route('/api/scan_default', methods=['POST'])
def scan_default():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename, {'exe'}):
        return jsonify({'error': 'No selected file or invalid file type'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        print("Using YARA rules from:", DEFAULT_RULES_PATH)
        rules = yara.compile(filepath=DEFAULT_RULES_PATH)
        matches = rules.match(file_path)
        result_text = f"Matches: {[m.rule for m in matches]}" if matches else "No malicious patterns detected."
    except Exception as e:
        print("Exception during scan:", e)
        result_text = f"Error scanning file: {str(e)}"

    log_scan(filename, "default", result_text)
    return jsonify({'result': result_text})

# B) Scan using a custom YARA rule file
@app.route('/api/scan_custom', methods=['POST'])
def scan_custom():
    if 'exe_file' not in request.files or 'yara_file' not in request.files:
        return jsonify({'error': 'Missing file(s)'}), 400

    exe_file = request.files['exe_file']
    yara_file = request.files['yara_file']

    if exe_file.filename == '' or not allowed_file(exe_file.filename, {'exe'}):
        return jsonify({'error': 'Invalid executable file'}), 400
    if yara_file.filename == '' or not allowed_file(yara_file.filename, {'yar', 'yara'}):
        return jsonify({'error': 'Invalid YARA rule file'}), 400

    exe_filename = secure_filename(exe_file.filename)
    yara_filename = secure_filename(yara_file.filename)

    exe_path = os.path.join(app.config['UPLOAD_FOLDER'], exe_filename)
    yara_path = os.path.join(app.config['UPLOAD_FOLDER'], yara_filename)

    exe_file.save(exe_path)
    yara_file.save(yara_path)

    try:
        rules = yara.compile(filepath=yara_path)
        matches = rules.match(exe_path)
        result_text = f"Matches: {[m.rule for m in matches]}" if matches else "No malicious patterns detected with custom rules."
    except Exception as e:
        print("Exception during custom scan:", e)
        result_text = f"Error scanning file with custom rules: {str(e)}"

    log_scan(exe_filename, "custom", result_text)
    return jsonify({'result': result_text})

# C) YARA Rule Builder: Generate a rule from provided strings and operator
@app.route('/api/build_rule', methods=['POST'])
def build_rule():
    data = request.get_json()
    rule_name = data.get('rule_name', 'MyRule')
    strings_input = data.get('strings', '')
    if isinstance(strings_input, str):
        strings = [s.strip() for s in strings_input.split(',') if s.strip()]
    else:
        strings = strings_input
    operator = data.get('operator', 'and').lower()
    generated_rule = generate_yara_rule(rule_name, strings, operator)
    return jsonify({'generated_rule': generated_rule})

# D) Retrieve scan logs
@app.route('/api/logs', methods=['GET'])
def get_logs():
    logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).all()
    return jsonify([log.to_dict() for log in logs])

# E) Combined Scan: Use default YARA rules, then query VirusTotal and calculate a vulnerability rating
@app.route('/api/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Save the file into the uploads folder
    upload_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    filename = secure_filename(uploaded_file.filename)
    file_path = os.path.join(upload_dir, filename)
    uploaded_file.save(file_path)

    # Scan with default YARA rules
    yara_matches = []
    try:
        rules = yara.compile(filepath=DEFAULT_RULES_PATH)
        results = rules.match(file_path)
        yara_matches = [match.rule for match in results]
    except Exception as e:
        print("Error scanning with YARA:", e)

    # Query VirusTotal for an external threat score
    vt_score = get_virustotal_score(file_path)

    # Calculate final vulnerability score
    vulnerability_score = calculate_vulnerability_score(yara_matches, vt_score)

    result = {
        "file": filename,
        "yara_matches": yara_matches,
        "virustotal_score": vt_score,
        "vulnerability_score": vulnerability_score
    }
    return jsonify(result)

# --------------------
# 4. Run the App
# --------------------
if __name__ == '__main__':
    app.run(debug=True, port=5000)

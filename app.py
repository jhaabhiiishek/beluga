import os
import re
import yara
import hashlib
import requests
import time
import io
import json
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS

# Authentication imports
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)

# Import our database, User, and ScanLog models
from models import db, User, ScanLog

# --------------------
# 1. Basic Configuration
# --------------------
app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Limit uploads to 10MB

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES_PATH = os.path.join(BASE_DIR, 'rules', 'malware_rules.yar')
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'scan_logs.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
with app.app_context():
    db.create_all()

# Accept common file types plus rule files
jwt = JWTManager(app)
ALLOWED_EXTENSIONS = {'exe', 'pdf', 'docx', 'yar', 'yara'}

def allowed_file(filename, exts=ALLOWED_EXTENSIONS):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in exts

def log_scan(filename, scan_type, result, user_id=None):
    log = ScanLog(filename=filename, scan_type=scan_type, result=result, user_id=user_id)
    db.session.add(log)
    db.session.commit()

def generate_yara_rule(rule_name, strings, condition_operator="and"):
    rule = f"rule {rule_name} {{\n"
    rule += "    strings:\n"
    for idx, s in enumerate(strings):
        rule += f"        $s{idx} = \"{s}\"\n"
    rule += "\n    condition:\n"
    rule += "        " + f" {condition_operator} ".join([f"$s{idx}" for idx in range(len(strings))]) + "\n"
    rule += "}"
    return rule

# --- External Integration: VirusTotal API ---
DEFAULT_VT_API_KEY = os.getenv("API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"
print("Default API_KEY:", DEFAULT_VT_API_KEY)

def get_virustotal_score(file_path, provided_api_key=None):
    current_api_key = provided_api_key if provided_api_key else DEFAULT_VT_API_KEY
    headers = {"x-apikey": current_api_key}
    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        file_stream = io.BytesIO(file_bytes)
        response = requests.post(VIRUSTOTAL_URL, headers=headers, files={"file": file_stream})
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if not analysis_id:
                return {"score": 0, "stats": {}, "message": "No analysis ID returned."}
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(10):
                poll_response = requests.get(analysis_url, headers=headers)
                if poll_response.status_code == 200:
                    poll_data = poll_response.json()
                    status = poll_data.get("data", {}).get("attributes", {}).get("status", "")
                    if status == "completed":
                        print("completed")
                        stats = poll_data.get("data", {}).get("attributes", {}).get("stats", {})
                        malicious = stats.get("malicious", 0)
                        total = sum(stats.values()) if stats else 0
                        score = (malicious / total) * 100 if total > 0 else 0
                        return {"score": round(score, 2), "stats": stats, "message": "Analysis completed."}
                time.sleep(2)
            message = "Analysis did not complete in time. API usage may be maxed out. Please try again later."
            return {"score": 0, "stats": {}, "message": message}
        else:
            error_message = f"VirusTotal API error: {response.status_code} - {response.text}"
            return {"score": 0, "stats": {}, "message": error_message}
    except Exception as e:
        return {"score": 0, "stats": {}, "message": f"Error querying VirusTotal: {e}"}

def count_yara_rules(yara_file_path):
    try:
        with open(yara_file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        rules = re.findall(r'(?m)^\s*rule\s+\w+\s*\{', content)
        return len(rules) if len(rules) > 0 else 1
    except Exception as e:
        print("Error counting rules:", e)
        return 1

TOTAL_YARA_RULES = count_yara_rules(DEFAULT_RULES_PATH)

def calculate_vulnerability_score(yara_matches, vt_score):
    per_rule_weight = 100 / TOTAL_YARA_RULES
    yara_score = len(yara_matches) * per_rule_weight
    total_score = (yara_score + vt_score) / 2
    return round(total_score, 2)

def final_verdict(vulnerability_score, threshold=50):
    return "Malicious" if vulnerability_score >= threshold else "Clean"

# --------------------
# 4. Authentication Endpoints
# --------------------
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists."}), 400
    user = User(email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "User created successfully."}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required."}), 400
    user = User.query.filter_by(email=email).first()
    print("User:", user)
    if not user or not user.check_password(password):
        print("Invalid credentials.")
        return jsonify({"error": "Invalid credentials."}), 401
    access_token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": access_token}), 200

# --------------------
# 5. Protected API Endpoints (Require Authentication)
# --------------------
@app.route('/api/scan_default', methods=['POST'])
@jwt_required()
def scan_default():
    current_user = int(get_jwt_identity())
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename, {'exe', 'pdf', 'docx', 'yar', 'yara'}):
        return jsonify({'error': 'No selected file or invalid file type'}), 400
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    try:
        with open(DEFAULT_RULES_PATH, 'r', encoding='utf-8') as f:
            huge_rules_content = f.read()
    except Exception as e:
        return jsonify({"error": f"Could not read YARA rules file: {str(e)}"}), 500

    import re
    # Split huge YARA content into individual rule blocks
    rule_blocks = re.findall(r'(?s)(rule\s+\w+\s*\{.*?\})', huge_rules_content)
    total_rules = len(rule_blocks)
    processed_rules = 0
    yara_matches = []
    risk_factors = {}
    
    for block in rule_blocks:
        processed_rules += 1
        try:
            # Use the "source" keyword to compile the rule block
            compiled_rule = yara.compile(source=block)
            results = compiled_rule.match(file_path)
            if results:
                for match in results:
                    if match.rule not in yara_matches:
                        yara_matches.append(match.rule)
                    if hasattr(match, 'strings'):
                        if match.rule not in risk_factors:
                            risk_factors[match.rule] = []
                        for s in match.strings:
                            try:
                                risk_factors[match.rule].append(s.data)
                            except AttributeError:
                                try:
                                    risk_factors[match.rule].append(s[2])
                                except (TypeError, IndexError):
                                    risk_factors[match.rule].append(str(s))
        except Exception as e:
            print(f"Error processing rule: {e}")

    progress_str = f"{processed_rules}/{total_rules} rules scanned"
    
    # Compute a vulnerability score: percentage of matched rules relative to total rules
    vulnerability_score = (len(yara_matches) * 100) / total_rules if total_rules > 0 else 0
    verdict = "Malicious" if vulnerability_score >= 35 else "Safe ✅"
    
    result_text = (
        f"Matches: {yara_matches}\n"
        f"Risk Factors: {risk_factors}\n"
        f"Progress: {progress_str}\n"
        f"Verdict: {verdict} (Vulnerability Score: {vulnerability_score:.2f}%)"
    )
    
    log_scan(filename, "default", result_text, user_id=current_user)
    return jsonify({'result': result_text})

# B) Custom Scan using provided YARA rule file (for EXE only)
@app.route('/api/scan_custom', methods=['POST'])
@jwt_required()
def scan_custom():
    current_user = int(get_jwt_identity())
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
        results = rules.match(exe_path)
        matches = [match.rule for match in results]
        result_text = f"Matches: {matches}" if results else "No malicious patterns detected with custom rules."
    except Exception as e:
        print("Exception during custom scan:", e)
        result_text = f"Error scanning file with custom rules: {str(e)}"
    log_scan(exe_filename, "custom", result_text, user_id=current_user)
    return jsonify({'result': result_text})

# C) YARA Rule Builder
@app.route('/api/build_rule', methods=['POST'])
@jwt_required()
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

# D) Retrieve Scan Logs (only logs for current user)
@app.route('/api/logs', methods=['GET'])
@jwt_required()
def get_logs():
    current_user = int(get_jwt_identity())
    logs = ScanLog.query.filter_by(user_id=current_user).order_by(ScanLog.timestamp.desc()).all()
    return jsonify([log.to_dict() for log in logs])

# E) Combined Scan: Universal static analysis with risk factor report, verdict, etc.
# The client sends the API key in the form data field "api_key" (optional)
@app.route('/api/scan', methods=['POST'])
@jwt_required()
def scan_file():
    current_user = int(get_jwt_identity())
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    uploaded_file = request.files['file']
    if uploaded_file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    filename = secure_filename(uploaded_file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    uploaded_file.save(file_path)
    
    user_api_key = request.form.get("api_key")

    try:
        with open(DEFAULT_RULES_PATH, 'r', encoding='utf-8') as f:
            huge_rules_content = f.read()
    except Exception as e:
        return jsonify({"error": f"Could not read YARA rules file: {str(e)}"}), 500

    
    import re
    rule_blocks = re.findall(r'(?s)(rule\s+\w+\s*\{.*?\})', huge_rules_content)
    total_rules = len(rule_blocks)
    processed_rules = 0
    # Perform YARA scanning on all files
    yara_matches = []
    risk_factors = {}
    for block in rule_blocks:
        processed_rules += 1
        try:
            compiled_rule = yara.compile(source=block)
            results = compiled_rule.match(file_path)
            if results:
                for match in results:
                    if match.rule not in yara_matches:
                        yara_matches.append(match.rule)
                    # Gather risk factor details if available.
                    if hasattr(match, 'strings'):
                        if match.rule not in risk_factors:
                            risk_factors[match.rule] = []
                        for s in match.strings:
                            try:
                                risk_factors[match.rule].append(s.data)
                            except AttributeError:
                                try:
                                    risk_factors[match.rule].append(s[2])
                                except (TypeError, IndexError):
                                    risk_factors[match.rule].append(str(s))
        except Exception as e:
            # Log per-rule errors but continue scanning.
            print(f"Error processing rule: {e}")

    progress_str = f"{processed_rules}/{total_rules} rules scanned"
    
    vt_result = get_virustotal_score(file_path, provided_api_key=user_api_key)
    vt_score = vt_result["score"]
    vt_stats = vt_result["stats"]
    
    vulnerability_score = calculate_vulnerability_score(yara_matches, vt_score) if yara_matches else vt_score
    verdict = final_verdict(vulnerability_score)
    
    combined_result = {
        "file": filename,
        "file_type": filename.rsplit('.',1)[1].lower(),
        "yara_matches": yara_matches,
        "risk_factors": risk_factors,
        "virustotal_score": vt_score,
        "vt_stats": vt_stats,
        "vulnerability_score": vulnerability_score,
        "verdict": verdict,
        "progress": progress_str
    }
    
    log_scan(filename, "detailed", json.dumps(combined_result), user_id=current_user)
    return jsonify(combined_result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)

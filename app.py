import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from db import users_collection, scans_collection
from analyzer import analyze_header, extract_email_fields
from auth import generate_token, token_required
from feature_extractor import extract_features   # <-- NEW: Module 1 feature extractor

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)

# Turns a MongoDB scan document into something jsonify() can send back
# (ObjectId and datetime aren't JSON-serializable on their own).
def serialize_scan(scan):
    return {
        "id": str(scan["_id"]),
        "user_email": scan["user_email"],
        "header_text": scan["header_text"],
        "analysis_result": scan["analysis_result"],
        "risk_score": scan["risk_score"],
        "verdict": scan["verdict"],
        "timestamp": scan["timestamp"].isoformat() + "Z"
    }

# Route 1: Home page - just to check server is alive
@app.route('/')
def home():
    return "PhishShield AI backend is running!"

# Route 2: Analyze endpoint
@app.route('/analyze', methods=['POST'])
@token_required
def analyze():
    data = request.get_json()
    header_text = data.get('header_text', '')

    if not header_text.strip():
        return jsonify({"error": "No header text provided"}), 400

    result = analyze_header(header_text)

    # Save this scan to the user's history. request.current_user comes from
    # the verified JWT (set by @token_required) - never trust an email sent
    # by the client itself.
    user_email = request.current_user.get('email')
    scan_doc = {
        "user_email": user_email,
        "header_text": header_text,
        "analysis_result": result,
        "risk_score": result.get('riskScore'),
        "verdict": result.get('verdict'),
        "timestamp": datetime.datetime.utcnow()
    }
    try:
        scans_collection.insert_one(scan_doc)
    except Exception:
        # Don't fail the whole request just because saving history failed -
        # the user still gets their analysis result back.
        pass

    return jsonify(result), 200
# Route 3: Register - creates a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    confirm_password = data.get('confirmPassword', '')
    role = data.get('role', 'individual')

    if not name or not email or not password:
        return jsonify({"error": "Name, email, and password are required"}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    existing_user = users_collection.find_one({"email": email})
    if existing_user:
        return jsonify({"error": "Email is already registered"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = {
        "name": name,
        "email": email,
        "password": hashed_password,
        "role": role
    }
    users_collection.insert_one(new_user)

    return jsonify({"message": "Account created successfully"}), 201

# Route 4: Login - verifies user credentials, issues JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})

    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid email or password"}), 401

    token = generate_token(user)

    return jsonify({
        "message": "Login successful",
        "token": token,
        "user": {
            "name": user['name'],
            "email": user['email'],
            "role": user['role']
        }
    }), 200

# Route 5: Analyze-email - extracts basic fields (From, To, Subject, SPF, DKIM, DMARC)
@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    data = request.get_json(silent=True) or {}
    header_text = data.get('header_text', '')

    if not header_text.strip():
        return jsonify({"error": "No header text provided"}), 400

    fields = extract_email_fields(header_text)
    return jsonify(fields), 200

# Route 6: Extract-features - Module 1 - full ML-ready feature extraction
# Accepts EITHER:
#   - pasted text (JSON body: {"header_text": "..."})
#   - an uploaded .eml or .txt file (multipart/form-data, key "file")
# TEST-ONLY ROUTE FOR NOW. Not yet connected to the frontend.
@app.route('/extract-features', methods=['POST'])
def extract_features_route():
    header_text = ''

    # Case 1: A file was uploaded
    if 'file' in request.files:
        uploaded_file = request.files['file']

        if uploaded_file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        filename = uploaded_file.filename.lower()
        if not (filename.endswith('.eml') or filename.endswith('.txt')):
            return jsonify({"error": "Only .eml and .txt files are supported"}), 400

        try:
            raw_bytes = uploaded_file.read()
            # errors='ignore' means: if a weird/unreadable character shows up,
            # skip it instead of crashing the whole request.
            header_text = raw_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return jsonify({"error": "Could not read the uploaded file"}), 400

    # Case 2: No file - fall back to pasted text in JSON body (old behavior, unchanged)
    else:
        data = request.get_json(silent=True) or {}
        header_text = data.get('header_text', '')

    if not header_text.strip():
        return jsonify({"error": "No header text or file content provided"}), 400

    features = extract_features(header_text)
    return jsonify(features), 200

# Route 7: Scan history - returns the logged-in user's saved scans, newest first
@app.route('/api/scans/history', methods=['GET'])
@token_required
def scan_history():
    user_email = request.current_user.get('email')

    try:
        scans = list(
            scans_collection.find({"user_email": user_email}).sort("timestamp", -1)
        )
    except Exception:
        return jsonify({"error": "Could not fetch scan history"}), 500

    return jsonify({"scans": [serialize_scan(s) for s in scans]}), 200

# Route 8: Scan reports - real aggregated stats for the logged-in user only
@app.route('/api/scans/reports', methods=['GET'])
@token_required
def scan_reports():
    user_email = request.current_user.get('email')

    try:
        scans = list(scans_collection.find({"user_email": user_email}))
    except Exception:
        return jsonify({"error": "Could not fetch report data"}), 500

    total_scans = len(scans)

    if total_scans == 0:
        return jsonify({
            "totalScans": 0,
            "safeScans": 0,
            "phishingScans": 0,
            "riskPercentage": 0,
            "averageRiskScore": 0
        }), 200

    phishing_scans = sum(1 for s in scans if s.get('verdict') == 'phishing')
    safe_scans = total_scans - phishing_scans
    risk_percentage = round((phishing_scans / total_scans) * 100, 2)
    average_risk_score = round(
        sum(s.get('risk_score', 0) for s in scans) / total_scans, 2
    )

    return jsonify({
        "totalScans": total_scans,
        "safeScans": safe_scans,
        "phishingScans": phishing_scans,
        "riskPercentage": risk_percentage,
        "averageRiskScore": average_risk_score
    }), 200

# Route 9: Scan reports (monthly) - same stats as Route 8, grouped by month,
# for the logged-in user only.
@app.route('/api/scans/reports/monthly', methods=['GET'])
@token_required
def scan_reports_monthly():
    user_email = request.current_user.get('email')

    try:
        scans = list(scans_collection.find({"user_email": user_email}))
    except Exception:
        return jsonify({"error": "Could not fetch report data"}), 500

    # Group scans by (year, month) using the same fields the aggregate
    # report already relies on (verdict, risk_score, timestamp).
    buckets = {}
    for s in scans:
        ts = s.get('timestamp')
        if ts is None:
            continue
        key = (ts.year, ts.month)
        buckets.setdefault(key, []).append(s)

    months = []
    for (year, month), month_scans in sorted(buckets.items()):
        total = len(month_scans)
        phishing = sum(1 for s in month_scans if s.get('verdict') == 'phishing')
        safe = total - phishing
        safe_rate = round((safe / total) * 100, 2) if total else 0
        avg_risk_score = round(
            sum(s.get('risk_score', 0) for s in month_scans) / total, 2
        ) if total else 0

        months.append({
            "month": datetime.date(year, month, 1).strftime("%B"),
            "year": year,
            "totalScans": total,
            "safeScans": safe,
            "phishingScans": phishing,
            "safeRate": safe_rate,
            "averageRiskScore": avg_risk_score
        })

    return jsonify({"months": months}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
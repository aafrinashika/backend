from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from db import users_collection
from analyzer import analyze_header, extract_email_fields
from auth import generate_token, token_required
from feature_extractor import extract_features   # <-- NEW: Module 1 feature extractor

app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)

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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
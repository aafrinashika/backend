# PhishShield AI — Backend

Final-year project backend built with **Flask** + **MongoDB**, providing authentication, rule-based email phishing analysis, and ML-ready feature extraction for the PhishShield AI frontend (React/Vite).

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend framework | Flask 3.1.3 |
| Database | MongoDB (local, via `mongodb://localhost:27017`) |
| Password hashing | Flask-Bcrypt 1.0.1 (bcrypt 5.0.0) |
| Authentication | JWT (PyJWT 2.13.0) |
| CORS | flask-cors 6.0.5 |
| Config management | python-dotenv 1.2.3 |
| Mongo driver | pymongo 4.17.0 |

---

## Folder Structure

```
phishshield-backend/
├── venv/                  # Python virtual environment (not shared/committed)
├── .env                   # Secret config (MONGO_URI, DB_NAME, JWT_SECRET)
├── requirements.txt       # Pinned dependency versions
├── app.py                 # Main Flask app — all routes
├── db.py                  # MongoDB connection + collections
├── auth.py                # JWT token generation + verification (@token_required)
├── analyzer.py            # Email header parsing + rule-based phishing scoring
└── feature_extractor.py   # Module 1: ML-ready feature extraction (facts only, no verdict)
```

---

## Setup Instructions

1. Create and activate a virtual environment:
   ```
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project root:
   ```
   MONGO_URI=mongodb://localhost:27017
   DB_NAME=phishshield
   JWT_SECRET=phishshield_super_secret_key_change_this_later
   ```

4. Make sure MongoDB is running locally (verify via MongoDB Compass connecting to `localhost:27017`).

5. Run the server:
   ```
   python app.py
   ```
   Server runs at `http://127.0.0.1:5000` (debug mode on).

---

## Database

**Database name:** `phishshield`

**Collections:**
- `users` — registered accounts (`name`, `email`, `password` [hashed], `role`)
- `scans` — *(planned, not yet implemented)* saved analysis history per user

---

## API Routes — Current Status

### `GET /`
Health check. Returns plain text confirming the server is running.

---

### `POST /register`
Creates a new user account.

**Body:**
```json
{
  "name": "Test User",
  "email": "test@example.com",
  "password": "password123",
  "confirmPassword": "password123",
  "role": "individual"
}
```
- Validates required fields, password match, minimum password length (8 chars)
- Rejects duplicate emails
- Hashes password with bcrypt before saving to MongoDB

**Status:** ✅ Complete, tested, connected to frontend (`RegisterPage.jsx`)

---

### `POST /login`
Authenticates a user and issues a JWT token.

**Body:**
```json
{
  "email": "test@example.com",
  "password": "password123"
}
```

**Response (success):**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOi...",
  "user": { "name": "Test User", "email": "test@example.com", "role": "individual" }
}
```
- Verifies password against stored bcrypt hash
- Issues a JWT token (expires in 24 hours) containing `email` and `role`

**Status:** ✅ Complete, tested, connected to frontend (`LoginPage.jsx`, token stored in `localStorage`)

---

### `POST /analyze` 🔒 *(requires JWT token)*
Full rule-based phishing analysis of a raw email header.

**Headers required:**
```
Authorization: Bearer <token>
```

**Body:**
```json
{
  "header_text": "From: ...\nSubject: ...\nAuthentication-Results: ..."
}
```

**Response:**
```json
{
  "verdict": "phishing",
  "riskScore": 95,
  "confidence": 100,
  "spf": "FAIL",
  "dkim": "FAIL",
  "dmarc": "FAIL",
  "sender": "security@paypal-login.xyz",
  "subject": "Urgent: Verify your PayPal account",
  "fromIp": "185.220.101.45",
  "reasons": [ "...", "..." ]
}
```

**Detection logic (rule-based, in `analyzer.py`):**
| Check | Points |
|---|---|
| SPF fail | +20 |
| DKIM fail | +20 |
| DMARC fail | +20 |
| From domain ≠ Return-Path domain | +15 |
| Suspicious keyword in subject (e.g. "verify", "urgent") | +10 each |

Verdict is `"phishing"` if total score ≥ 50, otherwise `"safe"`.

**Status:** ✅ Complete, tested (crafted test headers + a real Gmail header), connected to frontend (`UploadPage.jsx` → `ResultPage.jsx`), protected with JWT

---

### `POST /analyze-email`
Lightweight version — extracts only basic identity + auth fields, no scoring.

**Body:**
```json
{ "header_text": "..." }
```

**Response:**
```json
{
  "from": "...",
  "to": "...",
  "subject": "...",
  "spf": "PASS",
  "dkim": "PASS",
  "dmarc": "PASS"
}
```

**Status:** ✅ Complete, tested. Simpler alternative to `/analyze` — **not currently used by the frontend** (frontend uses the full `/analyze` route instead).

---

### `POST /extract-features` 🧪 *(test-only, not yet connected to frontend)*
**Module 1** of the planned ML pipeline. Extracts a full set of raw facts from an email header — no verdict, no scoring — so the same data can later be fed into an ML model as well as shown to the user.

Accepts **either**:
- Pasted text: `{"header_text": "..."}` (JSON body), **or**
- An uploaded file: `multipart/form-data` with key `file` (`.eml` or `.txt` only)

**Response fields:**
| Category | Fields |
|---|---|
| Identity | `from`, `to`, `reply_to`, `return_path`, `subject`, `message_id`, `date` |
| Domains | `from_domain`, `reply_to_domain`, `return_path_domain` |
| Auth | `spf`, `dkim`, `dmarc` (`PASS` / `FAIL` / `NONE` / `UNKNOWN` — missing header ≠ automatic fail) |
| Routing | `hop_count`, `sender_ips`, `received_headers`, `mail_hostnames` |
| Derived flags | `from_reply_to_mismatch`, `from_return_path_mismatch` |
| Content | `suspicious_keywords` |

**Status:** ✅ Implemented and testable via Postman/curl. Deliberately kept separate from `/analyze` — it does not decide phishing/safe, it only extracts facts for later ML training.

---

## Authentication Flow (JWT)

1. User logs in via `/login` → receives a signed JWT token
2. Frontend stores the token in `localStorage` (`phishshield_token`)
3. Frontend attaches the token on protected requests: `Authorization: Bearer <token>`
4. Backend's `@token_required` decorator (in `auth.py`) verifies the token before allowing access to protected routes
5. Token expires after 24 hours

**Currently protected routes:** `/analyze`

---

## Completed Modules

- [x] Project setup (Flask + venv)
- [x] MongoDB connection
- [x] Register (hashed passwords, MongoDB-backed)
- [x] Login (verified passwords, MongoDB-backed)
- [x] JWT authentication (token generation + route protection)
- [x] Email header parsing (`From`, `To`, `Subject`, `Return-Path`, SPF/DKIM/DMARC, sender IP)
- [x] Rule-based phishing scoring engine
- [x] Module 1: ML-ready feature extraction (`feature_extractor.py`, `/extract-features`) — supports pasted text and `.eml`/`.txt` file upload
- [x] Frontend fully connected: Register → Login → Upload → Analyze → Result

## Pending Modules

- [ ] Save scan results to MongoDB (`scans` collection) — **paused mid-implementation**
- [ ] History page — display real saved scans per user
- [ ] Reports page — real aggregated data
- [ ] Organization/Admin dashboard — real aggregated data across users
- [ ] Connect `/extract-features` output to the frontend
- [ ] ML-based detection layer — *optional, time-permitting; current system is intentionally rule-based/heuristic and fully functional on its own*

---

## Notes for Future Development

- `scans_collection` was planned in `db.py` but not yet added — needed before History can be implemented
- The `/analyze` route needs to be updated to insert a scan record into MongoDB after generating each result, tagged with the logged-in user's email (extracted from the verified JWT token via `request.current_user`, **not** from client-sent data)
- Frontend `HistoryPage.jsx` and `ReportsPage.jsx` currently still show hardcoded mock data
- Keep `feature_extractor.py`'s raw dataset separate from the `scans_collection` used for History/Reports — ML training data and user-facing scan history are meant to stay apart
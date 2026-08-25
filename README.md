# PhishShield AI — Backend

Final-year project backend built with **Flask** + **MongoDB**, providing authentication and email header phishing analysis for the PhishShield AI frontend (React/Vite).

---

## Tech Stack

| Component | Technology |
|---|---|
| Backend framework | Flask 3.1.3 |
| Database | MongoDB (local, via `mongodb://localhost:27017`) |
| Password hashing | flask-bcrypt |
| Authentication | JWT (PyJWT) |
| CORS | flask-cors |
| Config management | python-dotenv |

---

## Folder Structure

```
phishshield-backend/
├── venv/                  # Python virtual environment (not shared/committed)
├── .env                   # Secret config (MONGO_URI, DB_NAME, JWT_SECRET)
├── app.py                 # Main Flask app — all routes
├── db.py                  # MongoDB connection + collections
├── analyzer.py            # Email header parsing + rule-based phishing scoring
└── auth.py                # JWT token generation + verification (@token_required)
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
   pip install flask flask-bcrypt flask-cors pymongo python-dotenv pyjwt
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
   Server runs at `http://127.0.0.1:5000`.

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

**Status:** ✅ Complete, tested (both crafted test headers and a real Gmail header), connected to frontend (`UploadPage.jsx` → `ResultPage.jsx`), protected with JWT

---

### `POST /analyze-email`
Lightweight version — extracts only basic fields without scoring.

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

**Status:** ✅ Complete, tested. Built as a simpler alternative to `/analyze` — **not currently used by the frontend** (frontend uses the full `/analyze` route instead).

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
- [x] Frontend fully connected: Register → Login → Upload → Analyze → Result

## Pending Modules

- [ ] Save scan results to MongoDB (`scans` collection) — **paused mid-implementation**
- [ ] History page — display real saved scans per user
- [ ] Reports page — real aggregated data
- [ ] Organization/Admin dashboard — real aggregated data across users
- [ ] ML-based detection layer — *optional, time-permitting; current system is intentionally rule-based/heuristic and fully functional on its own*

---

## Notes for Future Development

- `scans_collection` was planned in `db.py` but not yet added — needed before History can be implemented
- The `/analyze` route needs to be updated to insert a scan record into MongoDB after generating each result, tagged with the logged-in user's email (extracted from the verified JWT token via `request.current_user`, not from client-sent data)
- Frontend `HistoryPage.jsx` and `ReportsPage.jsx` currently still show hardcoded mock data
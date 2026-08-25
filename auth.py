import os
import jwt
import datetime
from functools import wraps
from flask import request, jsonify
from dotenv import load_dotenv

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")

def generate_token(user):
    """Creates a signed token containing the user's email and role."""
    payload = {
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # expires in 24 hours
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token


def token_required(f):
    """A decorator: put @token_required above any route to force login-only access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.current_user = data  # attach user info to the request
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated
import os
from pymongo import MongoClient
from dotenv import load_dotenv

# Load variables from .env file into the environment
load_dotenv()

# Read the connection string and database name from .env
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# Connect to MongoDB
client = MongoClient(MONGO_URI)

# Select our database (creates it automatically on first use if it doesn't exist)
db = client[DB_NAME]

# Define a "users" collection (like a table in SQL) inside that database
users_collection = db["users"]

# Define a "scans" collection - stores each user's scan history / report data.
# NOTE: This is ONLY for the app's Scan History & Reports features.
# It is NOT the ML training dataset - that will come from a separate raw
# dataset later, kept intentionally apart from this collection.
scans_collection = db["scans"]
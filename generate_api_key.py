"""
Utility: generate and store an API key in the database. Run:
    python generate_api_key.py --name my-client

It prints the plaintext key once; store it securely. The DB keeps only a hash.
"""
import argparse
import secrets
from werkzeug.security import generate_password_hash

from app import app, db
from models import APIKey

parser = argparse.ArgumentParser()
parser.add_argument("--name", default=None, help="Optional name/label for the key")
args = parser.parse_args()

key = secrets.token_urlsafe(32)
key_hash = generate_password_hash(key)

with app.app_context():
    ak = APIKey(name=args.name, key_hash=key_hash)
    db.session.add(ak)
    db.session.commit()
    print("API key created:")
    print(key)
    print("Store this value securely; it will not be shown again.")

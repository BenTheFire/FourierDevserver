from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class LogEntry(db.Model):
    __tablename__ = "logs"

    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(64), index=True, nullable=False)
    level = db.Column(db.String(16), index=True, nullable=False)  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    message = db.Column(db.Text, nullable=False)
    metadata_json = db.Column(db.JSON, nullable=True)             # Arbitrary payloads (stack traces, user IDs)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "service": self.service_name,
            "level": self.level,
            "message": self.message,
            "metadata": self.metadata_json,
            "timestamp": self.timestamp.isoformat()
        }

class APIKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=True)
    key_hash = db.Column(db.String(256), nullable=False)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "revoked": self.revoked,
            "created_at": self.created_at.isoformat()
        }
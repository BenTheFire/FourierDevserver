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


class NetworkTarget(db.Model):
    __tablename__ = "network_targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    status = db.Column(db.String(16), default="unknown", nullable=False)
    last_checked = db.Column(db.DateTime, default=None, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip_address,
            "status": self.status,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
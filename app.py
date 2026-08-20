import os
import functools
import secrets
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from models import db, LogEntry, APIKey
from notifier import dispatch_alert
from resource_monitor import monitor

app = Flask(__name__)

# Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///local_logs.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

# Admin credentials (for the dashboard). Set these in environment in production.
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")  # in production, set a secure password

# Init DB
db.init_app(app)
with app.app_context():
    db.create_all()

# Start resource monitor background thread
try:
    monitor.start()
except Exception:
    # If monitoring cannot start, continue — endpoints will report psutil missing
    pass

# Helper: verify API key by checking hash in DB
def verify_api_key(key: str) -> bool:
    if not key:
        return False
    keys = APIKey.query.filter_by(revoked=False).all()
    for k in keys:
        try:
            if check_password_hash(k.key_hash, key):
                return True
        except Exception:
            continue
    return False

# Decorator to protect API endpoints - require an API key in X-API-Key
def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        if not api_key or not verify_api_key(api_key):
            return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated

# Simple session-based login for viewing the dashboard
def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

# Dashboard view protected by login
@app.route("/")
@login_required
def dashboard():
    # dashboard template will call /dashboard_data via fetch or load server-side
    return render_template("dashboard.html", logs=LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(30).all())

# Dashboard data endpoint for UI (no API key required, but requires login)
@app.route("/dashboard_data")
@login_required
def dashboard_data():
    logs = LogEntry.query.order_by(LogEntry.timestamp.desc()).limit(50).all()
    from time import time
    # Collect host metrics using ResourceMonitor; Kubernetes metrics if configured
    metrics = {"host": {}, "kubernetes": {}}
    try:
        cur = monitor.get_current()
        avg = monitor.get_avg(300)
        metrics["host"] = {
            "current": cur,
            "avg_5min": avg,
            "top_current": cur.get('procs') if isinstance(cur, dict) else [],
            "top_5min": avg.get('procs') if isinstance(avg, dict) else []
        }
        # include per-disk and per-cpu details if psutil is available
        try:
            import psutil
            metrics["host"]["per_cpu"] = psutil.cpu_percent(interval=0.5, percpu=True)
            metrics["host"]["disk"] = psutil.disk_usage("/")._asdict()
            metrics["host"]["memory_raw"] = psutil.virtual_memory()._asdict()
        except Exception:
            pass
    except Exception:
        metrics["host"] = {"error": "resource monitor unavailable"}

    # Try to query Kubernetes if client is available and KUBECONFIG present
    try:
        from kubernetes import client, config
        try:
            config.load_kube_config()
        except Exception:
            try:
                config.load_incluster_config()
            except Exception:
                raise
        v1 = client.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces(watch=False)
        nodes = v1.list_node()
        metrics["kubernetes"] = {
            "pod_count": len(pods.items),
            "node_count": len(nodes.items),
            "pods_sample": [ {"name": p.metadata.name, "ns": p.metadata.namespace, "phase": p.status.phase} for p in pods.items[:20] ]
        }
    except Exception:
        metrics["kubernetes"] = {"error": "kubernetes client not configured or unavailable"}

    return jsonify({
        "uptime": int(time()),
        "logs": [l.to_dict() for l in logs],
        "metrics": metrics
    })

# Public APIs require API keys
@app.route("/api/logs", methods=["POST"])
@require_api_key
def ingest_log():
    """Endpoint for microservices, game relays, and bots to push logs."""
    data = request.get_json()
    if not data or not all(k in data for k in ("service", "level", "message")):
        return jsonify({"error": "Missing required fields: service, level, message"}), 400

    level = data["level"].upper()
    entry = LogEntry(
        service_name=data["service"],
        level=level,
        message=data["message"],
        metadata_json=data.get("metadata", {})
    )
    db.session.add(entry)
    db.session.commit()

    # Trigger push alerts on failure
    dispatch_alert(entry.service_name, entry.level, entry.message, entry.id)

    return jsonify({"status": "ingested", "id": entry.id}), 201

@app.route("/api/logs", methods=["GET"])
@require_api_key
def get_logs():
    """Query logs with basic filtering."""
    service = request.args.get("service")
    level = request.args.get("level")
    limit = int(request.args.get("limit", 50))

    query = LogEntry.query.order_by(LogEntry.timestamp.desc())
    if service:
        query = query.filter_by(service_name=service)
    if level:
        query = query.filter_by(level=level.upper())

    logs = query.limit(limit).all()
    return jsonify([log.to_dict() for log in logs])

@app.route("/api/restart/<service_name>", methods=["POST"])
@require_api_key
def trigger_restart(service_name):
    """Target endpoint for the actionable button on your phone alert."""
    # Wire in K8s API or systemd commands here later
    return jsonify({"status": "restart_command_sent", "service": service_name}), 200

@app.route("/api/metrics", methods=["GET"])
@require_api_key
def api_metrics():
    # Minimal host metrics
    try:
        host = {
            "current": monitor.get_current(),
            "avg_5min": monitor.get_avg(300)
        }
    except Exception:
        host = {"error": "resource monitor unavailable"}

    # K8s metrics optional
    k8s = {"note": "install kubernetes python client and set KUBECONFIG to enable"}
    try:
        from kubernetes import client, config
        try:
            config.load_kube_config()
        except Exception:
            config.load_incluster_config()
        v1 = client.CoreV1Api()
        pods = v1.list_pod_for_all_namespaces(watch=False)
        k8s = {"pods": len(pods.items)}
    except Exception:
        pass

    return jsonify({"host": host, "kubernetes": k8s})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "1") == "1")
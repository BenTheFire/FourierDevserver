import json
import os
import functools
import platform
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from models import db, LogEntry, APIKey, NetworkTarget
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
SETTINGS_FILE = Path(__file__).resolve().parent / "settings.json"
DEFAULT_SETTINGS = {
    "refresh_interval": 10,
    "network_refresh_interval": 20,
    "kubernetes_refresh_interval": 30,
    "docker_refresh_interval": 30,
    "show_emulated_data": True,
    "enable_alerts": True,
    "enable_network_checks": True,
    "enable_kubernetes_checks": True,
    "enable_docker_checks": True,
}


def load_settings():
    if not SETTINGS_FILE.exists():
        SETTINGS_FILE.write_text(json.dumps(DEFAULT_SETTINGS, indent=2), encoding="utf-8")
        return DEFAULT_SETTINGS.copy()
    try:
        with SETTINGS_FILE.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except Exception:
        SETTINGS_FILE.write_text(json.dumps(DEFAULT_SETTINGS, indent=2), encoding="utf-8")
        return DEFAULT_SETTINGS.copy()
    merged = DEFAULT_SETTINGS.copy()
    merged.update({k: v for k, v in loaded.items() if k in DEFAULT_SETTINGS})
    return merged


def save_settings(data):
    merged = load_settings()
    merged.update({k: v for k, v in data.items() if k in DEFAULT_SETTINGS})
    SETTINGS_FILE.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return merged


# Init DB
db.init_app(app)
with app.app_context():
    db.create_all()
    app.config["MONITOR_SETTINGS"] = load_settings()

# Start resource monitor background thread
try:
    monitor.start()
except Exception:
    # If monitoring cannot start, continue — endpoints will report psutil missing
    pass

def ping_ip(ip: str, timeout: float = 2.0) -> bool:
    if not ip:
        return False
    if shutil.which("ping") is None:
        return False

    cmd = ["ping"]
    if platform.system().lower() == "windows":
        cmd += ["-n", "1", "-w", str(int(timeout * 1000)), "-4"]
    else:
        cmd += ["-c", "1", "-W", str(timeout), "-4"]
    cmd.append(ip)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout + 1, 3))
    except Exception:
        return False

    output = "\n".join(part for part in (result.stdout, result.stderr) if part).lower()
    if not output:
        return result.returncode == 0

    failure_markers = [
        "destination host unreachable",
        "destination net unreachable",
        "request timed out",
        "ttl expired",
        "100% packet loss",
        "0 received",
        "unreachable",
        "timed out",
    ]
    if any(marker in output for marker in failure_markers):
        return False

    success_markers = [
        "reply from",
        "bytes=",
        "ttl=",
        "1 packets transmitted, 1 received",
        "1 packets transmitted, 1 packets received",
    ]
    if any(marker in output for marker in success_markers):
        return True

    return result.returncode == 0 and "reply from" in output


def get_speedtest_result(test_url: str = "https://www.gstatic.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png"):
    try:
        started = time.perf_counter()
        response = requests.get(test_url, timeout=15)
        response.raise_for_status()
        elapsed = time.perf_counter() - started
        payload_size = len(response.content or b"")
        if elapsed <= 0:
            download_mbps = 0
        else:
            download_mbps = (payload_size * 8 / elapsed) / 1_000_000
        return {
            "status": "ok",
            "latency_ms": round(elapsed * 1000, 2),
            "download_mbps": round(download_mbps, 2),
            "bytes": payload_size,
        }
    except Exception:
        return {"status": "unavailable", "latency_ms": None, "download_mbps": None, "bytes": 0}


def check_network_target(target: NetworkTarget) -> str:
    status = "up" if ping_ip(target.ip_address) else "down"
    target.status = status
    from datetime import datetime
    target.last_checked = datetime.utcnow()
    db.session.commit()
    return status


def get_kubernetes_metrics():
    settings = app.config.get("MONITOR_SETTINGS", load_settings())
    emulated_sample = {
        "mode": "emulated",
        "warning": "Kubernetes was not detected on this host. Showing emulated demo data.",
        "cluster_name": "local-demo-cluster",
        "node_count": 3,
        "pod_count": 12,
        "ready_pods": 10,
        "failed_pods": 1,
        "pods_sample": [
            {"name": "api-gateway", "namespace": "default", "status": "Running", "ready": "1/1"},
            {"name": "worker-queue", "namespace": "default", "status": "Running", "ready": "1/1"},
            {"name": "metrics-exporter", "namespace": "monitoring", "status": "Running", "ready": "1/1"},
            {"name": "redis-cache", "namespace": "default", "status": "CrashLoopBackOff", "ready": "0/1"},
        ],
        "nodes_sample": [
            {"name": "kind-control-plane", "status": "Ready"},
            {"name": "kind-worker", "status": "Ready"},
            {"name": "kind-worker2", "status": "Ready"},
        ],
    }

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

        pod_rows = [
            {"name": p.metadata.name, "namespace": p.metadata.namespace, "status": p.status.phase or "Unknown", "ready": f"{sum(c.ready for c in (p.status.container_statuses or []))}/{len(p.status.container_statuses or []) or 1}"}
            for p in pods.items[:20]
        ]
        node_rows = [{"name": node.metadata.name, "status": node.status.conditions[0].type if node.status.conditions else "Unknown"} for node in nodes.items[:20]]

        ready_count = sum(1 for p in pods.items if getattr(p.status, "phase", "") == "Running")
        return {
            "mode": "live",
            "warning": "",
            "cluster_name": "local-cluster",
            "node_count": len(nodes.items),
            "pod_count": len(pods.items),
            "ready_pods": ready_count,
            "failed_pods": max(len(pods.items) - ready_count, 0),
            "pods_sample": pod_rows,
            "nodes_sample": node_rows,
        }
    except Exception:
        if settings.get("show_emulated_data", True):
            return emulated_sample
        return {"mode": "live", "warning": "Kubernetes checks are disabled in settings.", "cluster_name": "disabled", "node_count": 0, "pod_count": 0, "ready_pods": 0, "failed_pods": 0, "pods_sample": [], "nodes_sample": []}


def get_docker_metrics():
    settings = app.config.get("MONITOR_SETTINGS", load_settings())
    emulated_sample = {
        "mode": "emulated",
        "warning": "Docker was not detected on this host or the daemon is unavailable. Showing emulated demo data.",
        "total_containers": 4,
        "running_containers": 3,
        "stopped_containers": 1,
        "total_volumes": 5,
        "containers": [
            {"name": "web-app", "image": "nginx:latest", "state": "running", "status": "Up 2 hours", "ports": ["80/tcp -> 0.0.0.0:8080"], "volumes": ["/var/log/nginx:/var/log/nginx"], "cpu": "12.3%", "memory": "134MiB"},
            {"name": "redis-cache", "image": "redis:7", "state": "running", "status": "Up 1 hour", "ports": ["6379/tcp -> 0.0.0.0:6379"], "volumes": ["redis-data:/data"], "cpu": "8.6%", "memory": "76MiB"},
            {"name": "postgres-db", "image": "postgres:16", "state": "running", "status": "Up 3 hours", "ports": ["5432/tcp -> 0.0.0.0:5432"], "volumes": ["postgres-data:/var/lib/postgresql/data"], "cpu": "15.1%", "memory": "208MiB"},
            {"name": "worker-job", "image": "python:3.12", "state": "exited", "status": "Exited (1) 19 minutes ago", "ports": [], "volumes": ["/tmp/task:/tmp/task"], "cpu": "0.0%", "memory": "0B"},
        ],
        "volumes": [
            {"name": "redis-data", "driver": "local"},
            {"name": "postgres-data", "driver": "local"},
            {"name": "nginx-logs", "driver": "local"},
            {"name": "task-cache", "driver": "local"},
            {"name": "monitoring-data", "driver": "local"},
        ],
    }

    if not settings.get("enable_docker_checks", True):
        return {"mode": "disabled", "warning": "Docker checks are disabled in settings.", "total_containers": 0, "running_containers": 0, "stopped_containers": 0, "total_volumes": 0, "containers": [], "volumes": []}

    docker_cmd = shutil.which("docker")
    if not docker_cmd:
        return emulated_sample if settings.get("show_emulated_data", True) else {"mode": "disabled", "warning": "Docker is not installed or not available on this host.", "total_containers": 0, "running_containers": 0, "stopped_containers": 0, "total_volumes": 0, "containers": [], "volumes": []}

    try:
        docker_info = subprocess.run([docker_cmd, "info", "--format", "{{json .}}"], capture_output=True, text=True, timeout=10)
        if docker_info.returncode != 0:
            return emulated_sample if settings.get("show_emulated_data", True) else {"mode": "disabled", "warning": "Docker daemon is unavailable.", "total_containers": 0, "running_containers": 0, "stopped_containers": 0, "total_volumes": 0, "containers": [], "volumes": []}
    except Exception:
        return emulated_sample if settings.get("show_emulated_data", True) else {"mode": "disabled", "warning": "Docker daemon is unavailable.", "total_containers": 0, "running_containers": 0, "stopped_containers": 0, "total_volumes": 0, "containers": [], "volumes": []}

    try:
        ps = subprocess.run([docker_cmd, "ps", "-a", "--format", "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}"], capture_output=True, text=True, timeout=10)
        if ps.returncode != 0:
            return emulated_sample

        raw = [line.strip() for line in ps.stdout.splitlines() if line.strip()]
        containers = []
        for line in raw:
            parts = line.split("|", 4)
            if len(parts) < 5:
                continue
            container_id, name, image, status, state = parts
            inspect = subprocess.run([docker_cmd, "inspect", container_id], capture_output=True, text=True, timeout=10)
            if inspect.returncode != 0:
                continue
            obj = json.loads(inspect.stdout)[0]
            ports = []
            port_map = obj.get("NetworkSettings", {}).get("Ports") or {}
            for key, binds in port_map.items():
                if binds:
                    ports.extend(f"{key} -> {bind['HostIp']}:{bind['HostPort']}" for bind in binds)
                else:
                    ports.append(str(key))
            mounts = []
            for mount in obj.get("Mounts") or []:
                source = mount.get("Source") or mount.get("Name")
                target = mount.get("Destination")
                if source and target:
                    mounts.append(f"{source}:{target}")
                elif source:
                    mounts.append(source)
            stats = subprocess.run([docker_cmd, "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}", name], capture_output=True, text=True, timeout=10)
            cpu = "0.0%"
            memory = "0B"
            if stats.returncode == 0 and stats.stdout.strip():
                pieces = stats.stdout.strip().split("\t")
                if len(pieces) >= 4:
                    cpu = pieces[1]
                    memory = pieces[2]
            containers.append({
                "id": container_id[:12],
                "name": name,
                "image": image,
                "state": state.strip().lower(),
                "status": status,
                "ports": ports,
                "volumes": mounts,
                "cpu": cpu,
                "memory": memory,
            })

        volume_list = subprocess.run([docker_cmd, "volume", "ls", "--format", "{{.Name}}"], capture_output=True, text=True, timeout=10)
        volumes = []
        if volume_list.returncode == 0:
            for volume_name in volume_list.stdout.splitlines():
                volume_name = volume_name.strip()
                if volume_name:
                    volumes.append({"name": volume_name, "driver": "local"})

        running = sum(1 for c in containers if c.get("state") == "running")
        stopped = sum(1 for c in containers if c.get("state") != "running")
        return {
            "mode": "live",
            "warning": "",
            "total_containers": len(containers),
            "running_containers": running,
            "stopped_containers": stopped,
            "total_volumes": len(volumes),
            "containers": containers,
            "volumes": volumes,
        }
    except Exception:
        if settings.get("show_emulated_data", True):
            return emulated_sample
        return {"mode": "disabled", "warning": "Docker checks are unavailable.", "total_containers": 0, "running_containers": 0, "stopped_containers": 0, "total_volumes": 0, "containers": [], "volumes": []}


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

    metrics["kubernetes"] = get_kubernetes_metrics()
    metrics["docker"] = get_docker_metrics()

    return jsonify({
        "uptime": int(time()),
        "logs": [l.to_dict() for l in logs],
        "metrics": metrics
    })


@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    if request.method == "GET":
        return jsonify(load_settings())

    data = request.get_json(silent=True) or {}
    updated = save_settings(data)
    app.config["MONITOR_SETTINGS"] = updated
    return jsonify(updated)


@app.route("/api/kubernetes", methods=["GET"])
@login_required
def api_kubernetes_overview():
    return jsonify(get_kubernetes_metrics())


@app.route("/api/docker", methods=["GET"])
@login_required
def api_docker_overview():
    return jsonify(get_docker_metrics())


@app.route("/api/network", methods=["GET"])
@login_required
def api_network_overview():
    site_url = os.getenv("MONITOR_SITE_URL", "https://example.com")
    site_host = urlparse(site_url if "://" in site_url else f"http://{site_url}").hostname or site_url

    site_result = {"url": site_url, "host": site_host, "status": "down"}
    try:
        started = time.perf_counter()
        response = requests.get(site_url, timeout=10)
        elapsed_ms = (time.perf_counter() - started) * 1000
        site_result.update({
            "status": "up" if response.ok else "down",
            "latency_ms": round(elapsed_ms, 2),
            "http_status": response.status_code,
        })
    except Exception:
        site_result.update({
            "status": "down",
            "latency_ms": None,
            "http_status": None,
        })

    speed_result = get_speedtest_result()
    targets = []
    for target in NetworkTarget.query.order_by(NetworkTarget.name.asc()).all():
        check_network_target(target)
        targets.append(target.to_dict())
    return jsonify({
        "site": site_result,
        "speed": speed_result,
        "targets": targets,
    })


@app.route("/api/network/targets", methods=["GET", "POST"])
@login_required
def api_network_targets():
    if request.method == "GET":
        targets = NetworkTarget.query.order_by(NetworkTarget.name.asc()).all()
        return jsonify([target.to_dict() for target in targets])

    data = request.get_json(silent=True) or request.form or {}
    name = (data.get("name") or "").strip()
    ip_address = (data.get("ip") or data.get("ip_address") or "").strip()
    if not name or not ip_address:
        return jsonify({"error": "Name and IP are required"}), 400

    target = NetworkTarget(name=name, ip_address=ip_address, status="unknown")
    db.session.add(target)
    db.session.commit()
    target.status = "up" if ping_ip(ip_address) else "down"
    from datetime import datetime
    target.last_checked = datetime.utcnow()
    db.session.commit()
    return jsonify(target.to_dict()), 201


@app.route("/api/network/targets/<int:target_id>", methods=["DELETE"])
@login_required
def api_delete_network_target(target_id):
    target = NetworkTarget.query.get_or_404(target_id)
    db.session.delete(target)
    db.session.commit()
    return jsonify({"status": "deleted", "id": target_id})


@app.route("/api/network/targets/<int:target_id>/check", methods=["POST"])
@login_required
def api_check_network_target(target_id):
    target = NetworkTarget.query.get_or_404(target_id)
    check_network_target(target)
    return jsonify(target.to_dict())


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
import os
import requests

NTFY_URL = os.getenv("NTFY_URL", "https://ntfy.sh/FourierDev")
ADMIN_BASE_URL = os.getenv("ADMIN_BASE_URL", "https://admin.fouriergames.dev")

def dispatch_alert(service: str, level: str, message: str, log_id: int):
    """Fires push notification to phones for ERROR or CRITICAL events."""
    if level not in ["ERROR", "CRITICAL"]:
        return

    priority = "urgent" if level == "CRITICAL" else "high"
    tags = "rotating_light,skull" if level == "CRITICAL" else "warning"

    headers = {
        "Title": f"[{level}] {service}",
        "Priority": priority,
        "Tags": tags,
        # Interactive action buttons on your phone notification
        "Actions": (
            f"view, View Incident, {ADMIN_BASE_URL}/logs/{log_id}; "
            f"http, Restart Service, {ADMIN_BASE_URL}/api/restart/{service}, method=POST"
        )
    }

    try:
        requests.post(NTFY_URL, data=message.encode("utf-8"), headers=headers, timeout=3)
    except requests.RequestException as e:
        print(f"Failed to dispatch push notification: {e}")
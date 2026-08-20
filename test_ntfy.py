import json
import urllib.request
import urllib.error

# Change this to your topic (or your custom domain if self-hosted)
TOPIC_NAME = "FourierDev"
NTFY_URL = f"https://ntfy.sh/{TOPIC_NAME}"


def send_test_notification():
    payload = "Database connection timed out on worker-02. Click below to take action."

    headers = {
        "Title": "CRITICAL: Database Failure",
        "Priority": "urgent",  # Triggers sound/vibration and bypasses DND
        "Tags": "warning,rotating_light",  # Emoji badges
        # Action buttons shown directly in the notification
        "Actions": (
            "view, Open Dashboard, https://google.com; "
            "http, Restart Service, https://httpbin.org/post, method=POST"
        )
    }

    req = urllib.request.Request(
        NTFY_URL,
        data=payload.encode("utf-8"),
        headers=headers,
        method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            print(f"Status Code: {response.status}")
            print("Response:", response.read().decode("utf-8"))
            print(f"\nNotification sent! Check your phone app or open: https://ntfy.sh/{TOPIC_NAME}")
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.read().decode('utf-8')}")
    except urllib.error.URLError as e:
        print(f"Network Error: {e.reason}")


if __name__ == "__main__":
    send_test_notification()
from flask import Flask, render_template_string
import json
import os

app = Flask(__name__)

LOG_FILE = os.path.expanduser(
    "~/honeypot-project/cowrie/var/log/cowrie/cowrie.json"
)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Cowrie Honeypot Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            background: #101820;
            color: #ffffff;
            font-family: Arial, sans-serif;
            margin: 30px;
        }
        h1 { color: #00ff99; }
        .card {
            display: inline-block;
            background: #1d2b36;
            padding: 20px;
            margin: 10px;
            border-radius: 10px;
            min-width: 150px;
        }
        .number {
            font-size: 32px;
            color: #00ff99;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #354550;
            overflow-wrap: anywhere;
        }
        th { color: #00ff99; }
        .status { color: #00ff99; }
    </style>
</head>
<body>
    <h1>🛡 Cowrie Honeypot Dashboard</h1>
    <p class="status">● Monitoring logs | Auto-refreshes every 5 seconds</p>

    <div class="card">
        Total Events
        <div class="number">{{ total }}</div>
    </div>
    <div class="card">
        SSH Connections
        <div class="number">{{ connections }}</div>
    </div>
    <div class="card">
        Successful Logins
        <div class="number">{{ logins }}</div>
    </div>
    <div class="card">
        Commands Recorded
        <div class="number">{{ commands }}</div>
    </div>

    <h2>Recent Honeypot Activity</h2>
    <table>
        <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Source IP</th>
            <th>Details</th>
        </tr>
        {% for e in events %}
        <tr>
            <td>{{ e.get('timestamp', '') }}</td>
            <td>{{ e.get('eventid', '') }}</td>
            <td>{{ e.get('src_ip', '') }}</td>
            <td>{{ e.get('input', e.get('message', '')) }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def home():
    events = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    connections = sum(
        e.get("eventid") == "cowrie.session.connect" for e in events
    )
    logins = sum(
        e.get("eventid") == "cowrie.login.success" for e in events
    )
    commands = sum(
        e.get("eventid") == "cowrie.command.input" for e in events
    )

    recent = list(reversed(events[-30:]))

    return render_template_string(
        HTML,
        total=len(events),
        connections=connections,
        logins=logins,
        commands=commands,
        events=recent
    )

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

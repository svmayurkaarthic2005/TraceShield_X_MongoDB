import urllib.request, json

BASE = 'http://127.0.0.1:8001'

def post(url, data):
    req = urllib.request.Request(url, data=json.dumps(data).encode(),
        headers={'Content-Type': 'application/json'}, method='POST')
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

# Read the log file
lines = open('ingestion/data/linux-logs-70-privOnly-log.txt').readlines()
ip = '192.168.1.50'

# Step 1: ingest logs with explicit IP attribution (BEFORE network event)
r = post(BASE + '/ingest/logs', {'ip': ip, 'log_lines': [l.strip() for l in lines]})
print('Log ingestion:')
print(f"  sudo_attempts={r['sudo_attempts']} log_score={r['log_score']}")
print(f"  attack_type will be: PRIVILEGE_ESCALATION (sudo >= 2)")

# Step 2: network event — log signals already seeded
r = post(BASE + '/ingest', {'ip': ip, 'device': 'ubuntu-server', 'request_count': 80})
print('\nNetwork event result:')
print(f"  status={r['status']}")
print(f"  risk_score={r['risk_score']}")
print(f"  attack_type={r['attack_type']}")
print(f"  log_score={r['components']['log_score']}")
print(f"  actions={r['response']['actions_taken']}")
print(f"  message: {r['message']}")

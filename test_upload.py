import urllib.request, json

def post_file(url, filepath):
    boundary = b'----TraceShieldBoundary'
    with open(filepath, 'rb') as f:
        content = f.read()
    filename = filepath.replace('\\', '/').split('/')[-1].encode()
    body = (
        b'--' + boundary + b'\r\n'
        b'Content-Disposition: form-data; name="file"; filename="' + filename + b'"\r\n'
        b'Content-Type: text/plain\r\n\r\n'
        + content + b'\r\n'
        b'--' + boundary + b'--\r\n'
    )
    req = urllib.request.Request(url, data=body,
        headers={'Content-Type': 'multipart/form-data; boundary=' + boundary.decode()},
        method='POST')
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

r = post_file(
    'http://127.0.0.1:8001/dataset/upload',
    'ingestion/data/linux-logs-70-privOnly-log.txt'
)
print('Summary:', json.dumps(r['summary'], indent=2))
print('Top results:')
for res in r['results'][:5]:
    at = res.get('attack_type', 'N/A')
    print(f"  ip={res['ip']} status={res['status']} score={res['risk_score']} attack_type={at} actions={res['actions']}")

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from app import app


def run():
    app.run(host="127.0.0.1", port=5050, debug=False, use_reloader=False)

t = threading.Thread(target=run, daemon=True)
t.start()
time.sleep(1.5)

# Health
r = urllib.request.urlopen("http://127.0.0.1:5050/api/health", timeout=3)
print("GET /api/health ->", r.status, r.read().decode())

# Analyze Dockerfile (explicit kind)
df = Path("samples/Dockerfile.bad").read_text(encoding="utf-8")
body = json.dumps({"kind": "dockerfile", "content": df, "filename": "Dockerfile.bad"}).encode()
req = urllib.request.Request("http://127.0.0.1:5050/api/analyze", data=body, headers={"Content-Type": "application/json"})
r = urllib.request.urlopen(req, timeout=3)
data = json.loads(r.read().decode())
print("POST /api/analyze (dockerfile) ->", r.status, "summary:", data["summary"], "findings:", len(data["findings"]))

# Sample endpoint
r = urllib.request.urlopen("http://127.0.0.1:5050/api/sample?which=Dockerfile.bad", timeout=3)
sd = json.loads(r.read().decode())
print("GET /api/sample ->", r.status, "len(content)=", len(sd["content"]))

# Index page
r = urllib.request.urlopen("http://127.0.0.1:5050/", timeout=3)
html = r.read().decode()
print("GET / ->", r.status, "html size=", len(html), "has <h1>:", "<h1>" in html)

# Auto-detect for Dockerfile
body = json.dumps({"content": df, "filename": "Dockerfile.bad"}).encode()
req = urllib.request.Request("http://127.0.0.1:5050/api/analyze", data=body, headers={"Content-Type": "application/json"})
r = urllib.request.urlopen(req, timeout=3)
data = json.loads(r.read().decode())
print("AUTO (Dockerfile.bad) ->", r.status, "summary:", data["summary"])

# Auto-detect for compose
cf = Path("samples/compose-bad.yml").read_text(encoding="utf-8")
body = json.dumps({"content": cf, "filename": "compose-bad.yml"}).encode()
req = urllib.request.Request("http://127.0.0.1:5050/api/analyze", data=body, headers={"Content-Type": "application/json"})
r = urllib.request.urlopen(req, timeout=3)
data = json.loads(r.read().decode())
print("AUTO (compose-bad.yml) ->", r.status, "summary:", data["summary"])

# Empty content
req = urllib.request.Request(
    "http://127.0.0.1:5050/api/analyze",
    data=b'{"content":""}',
    headers={"Content-Type": "application/json"},
)
try:
    r = urllib.request.urlopen(req, timeout=3)
    print("EMPTY ->", r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print("EMPTY ->", e.code, e.read().decode())

# Multipart upload
boundary = "----X"
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="Dockerfile.bad"\r\n'
    f"Content-Type: application/octet-stream\r\n\r\n"
).encode() + df.encode() + f"\r\n--{boundary}--\r\n".encode()
req = urllib.request.Request(
    "http://127.0.0.1:5050/api/analyze",
    data=body,
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
)
r = urllib.request.urlopen(req, timeout=3)
data = json.loads(r.read().decode())
print("MULTIPART upload ->", r.status, "filename=", data["filename"], "findings:", len(data["findings"]))

print("OK")

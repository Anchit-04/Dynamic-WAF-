import subprocess, time, sys, os, signal, requests, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROXY_BIN = BASE_DIR / "target" / "debug" / "secure_farmer_proxy.exe"
BRAIN_SCRIPT = BASE_DIR / "brain" / "main.py"
BRAIN_VENV = BASE_DIR / "brain" / "venv" / "Scripts" / "python.exe"

PROXY_PORT = 18000
BRAIN_PORT = 15000
UPSTREAM_PORT = 18080

UPSTREAM_RESPONSE = b"OK from test upstream"

passed = 0
failed = 0

class UpstreamHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(UPSTREAM_RESPONSE)
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(UPSTREAM_RESPONSE)

def start_upstream():
    server = HTTPServer(("127.0.0.1", UPSTREAM_PORT), UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

def start_brain():
    proc = subprocess.Popen(
        [str(BRAIN_VENV), str(BRAIN_SCRIPT)],
        env={**os.environ, "CUDA_VISIBLE_DEVICES": "", "BRAIN_PORT": str(BRAIN_PORT)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc

def start_proxy():
    proc = subprocess.Popen(
        [str(PROXY_BIN)],
        env={
            **os.environ,
            "UPSTREAM_HOST": "127.0.0.1",
            "UPSTREAM_PORT": str(UPSTREAM_PORT),
            "UPSTREAM_TLS": "false",
            "LISTEN_ADDR": f"0.0.0.0:{PROXY_PORT}",
            "BRAIN_URL": f"http://127.0.0.1:{BRAIN_PORT}/analyze",
        },
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc

def wait_for(url, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            return True
        except requests.ConnectionError:
            time.sleep(0.5)
    return False

def check(label, status, method="GET", url_path="/", headers=None, data=None, expect_status=200, expect_body=None):
    global passed, failed
    url = f"http://127.0.0.1:{PROXY_PORT}{url_path}"
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=5, allow_redirects=False)
        else:
            r = requests.post(url, headers=headers, data=data, timeout=5, allow_redirects=False)

        ok = r.status_code == expect_status
        if expect_body and expect_body not in r.text:
            ok = False
        status_str = "PASS" if ok else "FAIL"
        print(f"  [{status_str}] {label} (got {r.status_code}, expected {expect_status})")
        if not ok:
            print(f"          Response: {r.text[:100]}")
            failed += 1
        else:
            passed += 1
    except Exception as e:
        print(f"  [FAIL] {label} — {e}")
        failed += 1

def main():
    global passed, failed
    print("=" * 60)
    print("  WAF Integration Tests")
    print("=" * 60)

    print("\n[setup] Starting upstream test server...")
    upstream = start_upstream()
    time.sleep(0.5)

    print("[setup] Starting Brain server...")
    brain = start_brain()
    time.sleep(2)

    if not wait_for(f"http://127.0.0.1:{BRAIN_PORT}/docs", timeout=20):
        print("[FAIL] Brain did not start")
        brain.kill()
        upstream.shutdown()
        sys.exit(1)

    print("[setup] Starting WAF Proxy...")
    proxy = start_proxy()
    time.sleep(2)

    if not wait_for(f"http://127.0.0.1:{PROXY_PORT}/", timeout=10):
        print("[FAIL] Proxy did not start")
        proxy.kill()
        brain.kill()
        upstream.shutdown()
        sys.exit(1)

    # --- Test Cases ---
    print()

    # 1. Clean request — should pass through to upstream
    check("Clean GET passes", "Layer 1/2", expect_status=200, expect_body="OK from test upstream")

    # 2. Malicious URI — Layer 1 SQLi pattern
    check("SQLi in URI blocked", "Layer 1 URI",
          url_path="/?id=1 UNION SELECT * FROM users",
          expect_status=403)

    # 3. Malicious User-Agent — Layer 1 header
    check("PowerShell UA blocked", "Layer 1 Header",
          headers={"User-Agent": "WindowsPowerShell/5.1"},
          expect_status=403)

    # 4. Malicious body — Layer 1 regex
    check("XSS in body blocked", "Layer 1 Body",
          method="POST", data="<script>alert('xss')</script>",
          expect_status=403)

    # 5. Clean body POST — should pass
    check("Clean POST passes", "Layer 1/2 Body",
          method="POST", data="hello world this is clean data",
          expect_status=200, expect_body="OK from test upstream")

    # 6. Large clean body (>1000 chars) — should pass (accumulation fix)
    large_body = "A" * 1500
    check("Large clean body passes", "Layer 2 accumulation",
          method="POST", data=large_body,
          expect_status=200, expect_body="OK from test upstream")

    # 7. Brain down failover — kill brain, send clean request
    print("\n[setup] Killing Brain to test failover...")
    brain.kill()
    brain.wait()
    time.sleep(1)
    check("Brain-down pass-through", "Failover",
          expect_status=200, expect_body="OK from test upstream")

    # --- Summary ---
    print()
    print("=" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 60)

    proxy.kill()
    upstream.shutdown()
    sys.exit(1 if failed > 0 else 0)

if __name__ == "__main__":
    main()

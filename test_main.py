import base64
import os

os.environ.setdefault("Q3_HOME_DIR", "/home/agent")
os.environ.setdefault("Q3_CWD", "/home/agent/workspace")
os.environ.setdefault("Q3_SECRET_REL", ".bashrc")
os.environ.setdefault("Q3_WRITE_DIR", "/data/agent/outbox/")
os.environ.setdefault("Q3_ALLOWED_DOMAINS", "registry.npmjs.org,api.github.com")

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_proration_v1():
    r = client.post("/charge", json={
        "old_price": 19, "new_price": 39,
        "days_remaining": 19, "days_in_actual_month": 31, "spec": "v1"
    })
    assert r.status_code == 200
    assert abs(r.json()["charge"] - 12.67) < 0.01


def test_proration_v2():
    r = client.post("/charge", json={
        "old_price": 19, "new_price": 39,
        "days_remaining": 19, "days_in_actual_month": 31, "spec": "v2"
    })
    assert r.status_code == 200
    assert abs(r.json()["charge"] - 12.26) < 0.01


def test_proration_invalid_spec():
    r = client.post("/charge", json={
        "old_price": 19, "new_price": 39,
        "days_remaining": 19, "days_in_actual_month": 31, "spec": "v3"
    })
    assert r.status_code == 400


BASH_BLOCK_CASES = [
    "cat /home/agent/.bashrc",
    "cat $HOME/.bashrc",
    "cat ~/.bashrc",
    "cd /home/agent/workspace && cat ../.bashrc",
    "cat ../.bashrc",
    "sudo cat /home/agent/.bashrc",
    "cat -- /home/agent/.bashrc",
    "less /home/agent/.bashrc",
]

BASH_ALLOW_CASES = [
    "ls -la /home/agent/workspace",
    "cat /home/agent/workspace/notes.txt",
    "cat /etc/hosts",
    "pwd",
]


def test_bash_blocks_secret_reads():
    for cmd in BASH_BLOCK_CASES:
        r = client.post("/q3/check", json={"tool": "bash", "command": cmd})
        assert r.json()["decision"] == "block", f"expected block for: {cmd}"


def test_bash_blocks_base64_wrapped():
    b64 = base64.b64encode(b"cat /home/agent/.bashrc").decode()
    r = client.post("/q3/check", json={"tool": "bash", "command": f"echo {b64} | base64 -d | bash"})
    assert r.json()["decision"] == "block"


def test_bash_allows_safe_reads():
    for cmd in BASH_ALLOW_CASES:
        r = client.post("/q3/check", json={"tool": "bash", "command": cmd})
        assert r.json()["decision"] == "allow", f"expected allow for: {cmd}"


def test_write_inside_allowed_dir():
    for path in ["/data/agent/outbox/report.json", "/data/agent/outbox/sub/dir/f.json", "relative.json"]:
        r = client.post("/q3/check", json={"tool": "write_file", "path": path, "content": "{}"})
        assert r.json()["decision"] == "allow", f"expected allow for: {path}"


def test_write_outside_allowed_dir():
    for path in ["/tmp/evil.txt", "/data/agent/outbox/../../etc/passwd", "/home/agent/.bashrc"]:
        r = client.post("/q3/check", json={"tool": "write_file", "path": path, "content": "x"})
        assert r.json()["decision"] == "block", f"expected block for: {path}"


def test_http_allowed_hosts():
    for url in ["https://registry.npmjs.org/express", "https://api.github.com/repos/foo/bar"]:
        r = client.post("/q3/check", json={"tool": "http_request", "method": "GET", "url": url})
        assert r.json()["decision"] == "allow", f"expected allow for: {url}"


def test_http_blocks_domain_confusion():
    for url in [
        "https://registry.npmjs.org.attacker.com/evil",
        "https://evil.registry.npmjs.org/evil",
        "https://pypi.org/simple",
        "http://1.2.3.4/evil",
    ]:
        r = client.post("/q3/check", json={"tool": "http_request", "method": "GET", "url": url})
        assert r.json()["decision"] == "block", f"expected block for: {url}"

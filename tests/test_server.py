"""Tests against a tiny fake Termix server. Run: python -m unittest discover tests"""
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from termix_mcp import server

HOSTS: dict[int, dict] = {}
NEXT = [1]
GOOD_KEY = "tmx_testkey"


class Fake(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _auth(self):
        return self.headers.get("Authorization") == f"Bearer {GOOD_KEY}"

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if not self._auth():
            return self._send(401, {"error": "bad key"})
        if self.path == "/host/db/host":
            return self._send(200, list(HOSTS.values()))
        if self.path.startswith("/host/db/host/"):
            hid = int(self.path.rsplit("/", 1)[1])
            return self._send(200, HOSTS[hid]) if hid in HOSTS else self._send(404, {})
        if self.path == "/credentials":
            return self._send(200, [{"id": 1, "name": "k", "password": "hunter2", "key": "PRIV"}])
        self._send(404, {})

    def do_POST(self):
        if not self._auth():
            return self._send(401, {})
        b = self._body()
        b["id"] = NEXT[0]
        HOSTS[NEXT[0]] = b
        NEXT[0] += 1
        self._send(200, b)

    def do_PUT(self):
        hid = int(self.path.rsplit("/", 1)[1])
        HOSTS[hid].update(self._body())
        self._send(200, HOSTS[hid])

    def do_DELETE(self):
        hid = int(self.path.rsplit("/", 1)[1])
        HOSTS.pop(hid, None)
        self._send(200, {"ok": True})


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        os.environ["TERMIX_URL"] = f"http://127.0.0.1:{cls.srv.server_port}"
        os.environ["TERMIX_API_KEY"] = GOOD_KEY

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        HOSTS.clear()
        NEXT[0] = 1
        os.environ["TERMIX_API_KEY"] = GOOD_KEY

    def test_health(self):
        r = server.termix_health()
        self.assertTrue(r["server_up"])
        self.assertTrue(r["api_key_works"])

    def test_bad_key_hidden_and_reported(self):
        os.environ["TERMIX_API_KEY"] = "tmx_wrong"
        r = server.termix_health()
        self.assertFalse(r["api_key_works"])
        self.assertNotIn("tmx_wrong", json.dumps(r))

    def test_add_needs_confirm(self):
        r = server.termix_hosts("add", data={"name": "a", "ip": "1.2.3.4"})
        self.assertTrue(r.get("needs_confirm"))
        self.assertEqual(HOSTS, {})

    def test_add_get_update_list(self):
        r = server.termix_hosts("add", data={"name": "a", "ip": "1.2.3.4"}, confirm=True)
        self.assertTrue(r["ok"])
        self.assertEqual(server.termix_hosts("get", host_id=1)["data"]["name"], "a")
        server.termix_hosts("update", host_id=1, data={"name": "b"}, confirm=True)
        self.assertEqual(server.termix_hosts("list")["data"][0]["name"], "b")

    def test_delete_needs_phrase(self):
        server.termix_hosts("add", data={"name": "a"}, confirm=True)
        r = server.termix_hosts("delete", host_id=1, confirm=True)
        self.assertTrue(r.get("needs_confirm"))
        self.assertIn(1, HOSTS)
        r = server.termix_hosts("delete", host_id=1, confirm=True,
                                confirm_phrase="DELETE /host/db/host/1")
        self.assertTrue(r["ok"])
        self.assertNotIn(1, HOSTS)

    def test_add_many(self):
        rows = [{"name": f"h{i}", "ip": f"10.0.0.{i}"} for i in range(3)]
        self.assertTrue(server.termix_add_many_hosts(rows)["needs_confirm"])
        r = server.termix_add_many_hosts(rows, confirm=True)
        self.assertEqual(r["added"], 3)

    def test_secrets_hidden(self):
        r = server.termix_credentials("list")
        txt = json.dumps(r)
        self.assertNotIn("hunter2", txt)
        self.assertNotIn("PRIV", txt)

    def test_blocked_paths(self):
        self.assertFalse(server.termix_call("POST", "/credentials", body={"password": "x"}, confirm=True)["ok"])
        self.assertFalse(server.termix_call("POST", "/users/login", body={}, confirm=True)["ok"])

    def test_call_get_runs(self):
        self.assertTrue(server.termix_call("GET", "/health")["ok"])


if __name__ == "__main__":
    unittest.main()

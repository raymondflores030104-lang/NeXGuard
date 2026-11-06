import json, os, tempfile, time, unittest
from nexguard import core
from nexguard.app import create_app

PW = "correct-horse-battery"
class Base(unittest.TestCase):
    def setUp(self):
        self.t = 1_800_000_000.0; core.clock = lambda: self.t
        self.f = tempfile.NamedTemporaryFile(suffix=".db", delete=False); self.f.close()
        self.app = create_app(self.f.name); self.c = self.app.test_client(); self.sec = {}
        for n, role in [("root","super_admin"),("secadm","security_admin"),("analyst1","analyst"),("auditor1","auditor"),("viewer1","viewer")]:
            self.mkuser(n, role)
        self.tok = {}
    def tearDown(self): os.unlink(self.f.name)
    def mkuser(self, n, role):
        db = core.connect(self.f.name); s = core.new_totp_secret(); self.sec[n] = s
        with core.tx(db): db.execute("INSERT INTO users(username,pw_hash,role,totp_secret) VALUES(?,?,?,?)", (n, core.hash_pw(PW), role, s))
        db.close()
    def login(self, n, code=None, pw=PW):
        r = self.c.post("/api/login", json={"username": n, "password": pw, "totp": code or core.totp_now(self.sec[n])})
        if r.status_code == 200: self.tok[n] = {"Authorization": "Bearer " + r.get_json()["token"]}
        return r
    def req(self, n, m, url, **k): return getattr(self.c, m)(url, headers=self.tok[n], **k)
    def advance(self, s=31): self.t += s
    def env(self, name="TestEnv"):
        self.login("secadm"); r = self.req("secadm", "post", "/api/environments", json={"name": name}).get_json()
        return r["id"], {"X-Ingest-Key": r["ingest_key"]}
    def send(self, h, type_, sev="medium", **ev): return self.c.post("/api/events", headers=h, json={"type": type_, "severity": sev, "evidence": ev})
    def db(self): return core.connect(self.f.name)

class T(Base):
    def test_login_mfa_and_lockout(self):
        self.assertEqual(self.login("root").status_code, 200)
        self.assertEqual(self.login("secadm", code="000000").status_code, 401)
        self.assertEqual(self.login("secadm", pw="wrong-password-x").status_code, 401)
        for _ in range(5): self.login("analyst1", pw="bad-bad-bad-bad")
        self.advance(); self.assertEqual(self.login("analyst1").status_code, 401)  # locked even with valid creds
    def test_totp_replay_rejected(self):
        code = core.totp_now(self.sec["root"]); self.assertEqual(self.login("root", code).status_code, 200)
        self.assertEqual(self.login("root", code).status_code, 401)
    def test_rbac(self):
        for n in ("viewer1", "auditor1", "analyst1"): self.login(n)
        self.assertEqual(self.req("viewer1", "get", "/api/audit").status_code, 403)
        self.assertEqual(self.req("viewer1", "get", "/api/dashboard").status_code, 200)
        self.assertEqual(self.req("auditor1", "get", "/api/audit").status_code, 200)
        self.assertEqual(self.req("analyst1", "post", "/api/environments", json={"name": "xxx"}).status_code, 403)
        self.assertEqual(self.req("analyst1", "post", "/api/users", json={}).status_code, 403)
        self.assertEqual(self.c.get("/api/dashboard").status_code, 401)
    def test_ingest_validation_and_isolation(self):
        a, ha = self.env("EnvA"); b, hb = self.env("EnvB")
        self.assertEqual(self.send({"X-Ingest-Key": "nope"}, "x_evt").status_code, 401)
        self.assertEqual(self.send(ha, "bad type!").status_code, 400)
        self.assertEqual(self.c.post("/api/events", headers=ha, json={"type": "t_ok", "severity": "zzz"}).status_code, 400)
        self.assertEqual(self.send(ha, "t_ok").status_code, 202)
        self.login("analyst1")
        self.assertEqual(len(self.req("analyst1", "get", "/api/events?env=" + a).get_json()), 1)
        self.assertEqual(len(self.req("analyst1", "get", "/api/events?env=" + b).get_json()), 0)
    def test_bruteforce_detection_dedupe(self):
        _, h = self.env()
        for i in range(4): self.assertEqual(self.send(h, "auth_failed", ip="203.0.113.9").get_json()["incidents"], [])
        r = self.send(h, "auth_failed", ip="203.0.113.9").get_json(); self.assertEqual(len(r["incidents"]), 1)
        self.send(h, "auth_failed", ip="203.0.113.9"); self.send(h, "auth_failed", ip="198.51.100.1")
        db = self.db(); rows = db.execute("SELECT count,risk FROM incidents WHERE rule_id='R-AUTH-BRUTE'").fetchall()
        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]["count"], 2)
    def test_single_event_rules_and_self_protection(self):
        _, h = self.env()
        self.assertEqual(len(self.send(h, "privilege_change", "high", user="x").get_json()["incidents"]), 1)
        db = self.db(); self.assertEqual(db.execute("SELECT severity FROM incidents WHERE rule_id='R-PRIV-CHANGE'").fetchone()[0], "critical")
        for _ in range(5): self.login("viewer1", pw="bad-bad-bad-bad")   # NEXGUARD watches itself
        self.assertTrue(db.execute("SELECT 1 FROM incidents WHERE env_id='env-nexguard' AND rule_id='R-AUTH-BRUTE'").fetchone())
    def _brute(self, h, ip="203.0.113.9"):
        for _ in range(5): self.send(h, "auth_failed", ip=ip)
        return self.db().execute("SELECT id FROM incidents WHERE rule_id='R-AUTH-BRUTE' AND dedupe_key LIKE ?", ("%" + ip,)).fetchone()[0]
    def test_human_approval_flow_with_stepup_and_rollback(self):
        _, h = self.env(); iid = self._brute(h); db = self.db()
        rid = db.execute("SELECT id,status,level FROM responses WHERE incident_id=?", (iid,)).fetchone()
        self.assertEqual((rid["status"], rid["level"]), ("pending_approval", 4)); rid = rid["id"]
        self.assertEqual(db.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0], 0)     # nothing runs without a human
        self.login("analyst1"); self.assertEqual(self.req("analyst1", "post", f"/api/responses/{rid}/approve", json={}).status_code, 403)
        self.assertEqual(self.req("secadm", "post", f"/api/responses/{rid}/approve", json={}).status_code, 401)           # no step-up
        self.assertEqual(self.req("secadm", "post", f"/api/responses/{rid}/approve", json={"totp_code": "123456"}).status_code, 401)
        self.advance(); code = core.totp_now(self.sec["secadm"])
        r = self.req("secadm", "post", f"/api/responses/{rid}/approve", json={"totp_code": code}); self.assertEqual(r.get_json()["status"], "verified")
        self.assertEqual(db.execute("SELECT ip FROM blocklist").fetchone()[0], "203.0.113.9")
        self.assertEqual(self.req("secadm", "post", f"/api/responses/{rid}/rollback", json={"totp_code": code}).status_code, 401)  # replay refused
        self.advance(); r = self.req("secadm", "post", f"/api/responses/{rid}/rollback", json={"totp_code": core.totp_now(self.sec["secadm"])})
        self.assertTrue(r.get_json()["rolled_back"]); self.assertEqual(db.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0], 0)
        self.assertTrue(db.execute("SELECT 1 FROM audit WHERE action='response.approved'").fetchone())
    def test_preauthorized_containment(self):
        _, h = self.env(); self.login("secadm")
        self.assertEqual(self.req("secadm", "patch", "/api/rules/R-AUTH-BRUTE", json={"preauthorized": 1}).status_code, 401)  # needs step-up
        self.advance(); self.assertEqual(self.req("secadm", "patch", "/api/rules/R-AUTH-BRUTE", json={"preauthorized": 1, "totp_code": core.totp_now(self.sec["secadm"])}).status_code, 200)
        self.assertEqual(self.req("secadm", "patch", "/api/rules/R-PRIV-CHANGE", json={"preauthorized": 1}).status_code, 400)
        self._brute(h); db = self.db()
        self.assertEqual(db.execute("SELECT status,level,origin FROM responses").fetchone()[:], ("verified", 3, "rule"))
        self.assertEqual(db.execute("SELECT ip FROM blocklist").fetchone()[0], "203.0.113.9")
    def test_ai_failure_and_untrusted_output(self):
        _, h = self.env(); iid = self._brute(h); self.login("analyst1")
        class Down:
            name = "down"
            def investigate(self, c): raise TimeoutError("provider down")
        class Evil:
            name = "evil"
            def investigate(self, c): return json.dumps({"summary": "x", "recommendations": [
                {"action": "mint_flwrx", "params": {"amount": 10**9}}, {"action": "block_ip", "params": {"ip": "127.0.0.1"}},
                {"action": "block_ip", "params": {"ip": "not-an-ip"}}, {"action": "block_ip", "params": {"ip": "198.51.100.77"}}]})
        self.app.config["AI_PROVIDER"] = Down()
        self.assertEqual(self.req("analyst1", "post", f"/api/incidents/{iid}/investigate").get_json()["status"], "unavailable")
        self.assertEqual(self.send(h, "privilege_change", "high").status_code, 202)     # detection unaffected
        self.app.config["AI_PROVIDER"] = Evil(); self.advance(61)
        r = self.req("analyst1", "post", f"/api/incidents/{iid}/investigate").get_json()
        self.assertEqual(len(r["accepted"]), 1); self.assertEqual(len(r["rejected"]), 3)
        db = self.db(); self.assertEqual(db.execute("SELECT status FROM responses WHERE id=?", (r["accepted"][0]["response_id"],)).fetchone()[0], "pending_approval")
        self.assertEqual(db.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0], 0)
    def test_default_provider_and_lifecycle(self):
        _, h = self.env(); iid = self._brute(h); self.login("analyst1")
        self.assertEqual(self.req("analyst1", "post", f"/api/incidents/{iid}/investigate").get_json()["status"], "ok")
        self.assertEqual(self.req("analyst1", "post", f"/api/incidents/{iid}/status", json={"status": "closed"}).status_code, 409)  # pending approval blocks closure
        self.assertEqual(self.req("analyst1", "post", f"/api/incidents/{iid}/status", json={"status": "detected"}).status_code, 409)
        self.assertEqual(self.req("analyst1", "post", f"/api/incidents/{iid}/status", json={"status": "investigating"}).status_code, 200)
    def test_audit_integrity_and_tamper(self):
        self.login("root"); db = self.db(); self.assertTrue(core.verify_audit(db)["ok"])
        with self.assertRaises(Exception): db.execute("UPDATE audit SET actor='x'")
        with self.assertRaises(Exception): db.execute("DELETE FROM audit")
        db.execute("DROP TRIGGER audit_no_update"); db.execute("UPDATE audit SET body=replace(body,'login','l0gin') WHERE seq=1")  # attacker with raw DB access
        self.assertFalse(core.verify_audit(db)["ok"])
    def test_dashboard_reflects_backend(self):
        self.login("viewer1"); d = self.req("viewer1", "get", "/api/dashboard").get_json(); self.assertEqual(d["open_incidents"], 0)
        _, h = self.env(); self.send(h, "ioc_match", "critical"); self.send(h, "heartbeat", "info")
        d = self.req("viewer1", "get", "/api/dashboard").get_json(); self.assertEqual(d["incidents_by_severity"], {"critical": 1})
        envs = {e["name"]: e["monitoring"] for e in self.req("viewer1", "get", "/api/environments").get_json()}
        self.assertEqual((envs["TestEnv"], envs["AXIS"]), ("healthy", "no_data"))
        self.assertTrue(all(i["status"] == "not_implemented" for i in self.req("viewer1", "get", "/api/integrations").get_json()))
    def test_backup_recovery(self):
        _, h = self.env(); self.send(h, "ioc_match", "critical"); db = self.db()
        bk = self.f.name + ".bak"; b = core.connect(bk); db.backup(b); b.close()
        r = core.connect(bk); self.assertEqual(r.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1); self.assertTrue(core.verify_audit(r)["ok"]); os.unlink(bk)
    def test_ingest_throughput(self):
        _, h = self.env(); n = 500; t0 = time.perf_counter()
        for i in range(n): self.send(h, "api_request_log", ip="192.0.2.1", n=i)
        eps = n / (time.perf_counter() - t0); print("\n[perf] sequential ingest via Flask test client: %.0f events/s (single process, sqlite)" % eps); self.assertGreater(eps, 0)

if __name__ == "__main__": unittest.main()

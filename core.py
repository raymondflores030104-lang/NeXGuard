"""NEXGUARD core: storage, auth primitives, audit chain, detection, response, AI adapter."""
import base64, hashlib, hmac, ipaddress, json, os, re, sqlite3, struct, time, uuid, urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone

clock = time.time  # overridable in tests

def iso(t=None):
    return datetime.fromtimestamp(clock() if t is None else t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

# ---------- schema ----------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('super_admin','security_admin','analyst','auditor','viewer')),
 totp_secret TEXT NOT NULL, last_totp_step INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
 locked_until REAL NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS environments(id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, type TEXT NOT NULL,
 policy TEXT NOT NULL DEFAULT '{}', key_hash TEXT NOT NULL, last_heartbeat TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, env_id TEXT NOT NULL REFERENCES environments(id), ts TEXT NOT NULL,
 source TEXT NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL, evidence TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_ev_lookup ON events(env_id,type,ts);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, name TEXT NOT NULL, event_type TEXT NOT NULL, threshold INTEGER NOT NULL DEFAULT 1,
 window_sec INTEGER NOT NULL DEFAULT 300, group_field TEXT, severity TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
 explanation TEXT NOT NULL, recommendation TEXT NOT NULL, response_action TEXT, response_level INTEGER NOT NULL DEFAULT 1,
 preauthorized INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_rules_type ON rules(event_type);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, env_id TEXT NOT NULL REFERENCES environments(id),
 rule_id TEXT NOT NULL REFERENCES rules(id), dedupe_key TEXT NOT NULL, severity TEXT NOT NULL, risk INTEGER NOT NULL,
 status TEXT NOT NULL, title TEXT NOT NULL, explanation TEXT NOT NULL, recommendation TEXT NOT NULL,
 count INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_inc_open ON incidents(dedupe_key) WHERE status!='closed';
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents(status, severity);
CREATE TABLE IF NOT EXISTS incident_events(incident_id TEXT NOT NULL REFERENCES incidents(id), event_id TEXT NOT NULL REFERENCES events(id),
 PRIMARY KEY(incident_id,event_id));
CREATE TABLE IF NOT EXISTS ai_investigations(id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), provider TEXT NOT NULL,
 status TEXT NOT NULL, summary TEXT, accepted TEXT, rejected TEXT, error TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS responses(id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), action TEXT NOT NULL,
 params TEXT NOT NULL, level INTEGER NOT NULL, status TEXT NOT NULL, origin TEXT NOT NULL, requested_by TEXT, approved_by TEXT,
 created TEXT NOT NULL, executed_at TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS blocklist(ip TEXT PRIMARY KEY, response_id INTEGER NOT NULL REFERENCES responses(id), created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
 target TEXT, body TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ev_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS ev_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, dedupe_key TEXT UNIQUE NOT NULL, severity TEXT NOT NULL,
 message TEXT NOT NULL, created TEXT NOT NULL, ack INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS integrations(name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, config TEXT NOT NULL DEFAULT '{}',
 status TEXT NOT NULL DEFAULT 'not_implemented', last_check TEXT, last_error TEXT);
"""
INTEGRATIONS = ["wazuh","falco","suricata","zeek","semgrep","owasp_zap","codeql","trivy","gitleaks","opentelemetry"]

# (id, name, event_type, threshold, window, group_field, severity, explanation, recommendation, action, level)
DEFAULT_RULES = [
 ("R-AUTH-BRUTE","Brute-force login","auth_failed",5,300,"ip","high","Repeated failed logins from one IP inside the window suggest password guessing.","Block the source IP and review targeted accounts.","block_ip",4),
 ("R-PRIV-CHANGE","Privilege change","privilege_change",1,0,None,"critical","A role or privilege was modified; unauthorized changes enable takeover.","Verify the change with the requesting administrator.",None,2),
 ("R-ADMIN-ACCESS","Unexpected admin access","admin_access",1,0,None,"high","Administrative access outside the expected pattern was reported.","Confirm identity and session origin.",None,2),
 ("R-API-BURST","Abnormal API request rate","api_request",300,60,"ip","medium","Request volume from one IP exceeds the configured baseline.","Rate-limit or block the source.","block_ip",4),
 ("R-CONFIG-CHANGE","Unauthorized config change","config_change",1,0,None,"high","A monitored configuration changed.","Compare against the approved change record and roll back if unapproved.",None,2),
 ("R-DB-ACCESS","Suspicious database access","db_suspicious_access",1,0,None,"high","Database access flagged as anomalous by the reporting agent.","Review query origin and credentials.",None,2),
 ("R-IOC","Known malicious indicator","ioc_match",1,0,None,"critical","Traffic or files matched a known malicious indicator.","Isolate the affected host via your own tooling.",None,2),
 ("R-VULN-DEP","Vulnerable dependency","vulnerable_dependency",1,0,None,"medium","A dependency with a known vulnerability was reported.","Upgrade or patch the dependency.",None,2),
 ("R-FILE-MOD","Suspicious file modification","file_modified",1,0,None,"high","A protected file changed unexpectedly.","Verify against deployment records.",None,2),
 ("R-EXFIL","Potential data exfiltration","data_egress_large",1,0,None,"critical","Unusually large outbound transfer reported.","Identify destination and halt the transfer.",None,2),
]
BOOT_ENVS = [("env-nexguard","NEXGUARD","self"),("env-flouraxiom","FLOURAXIOM Website","website"),
             ("env-axis","AXIS","application"),("env-flrxcore","FLRXCORE","blockchain")]

def connect(path):
    db = sqlite3.connect(path, isolation_level=None, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA journal_mode=WAL")
    return db

@contextmanager
def tx(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK"); raise

def init_db(path):
    db = connect(path); db.executescript(SCHEMA)
    with tx(db):
        for n in INTEGRATIONS: db.execute("INSERT OR IGNORE INTO integrations(name) VALUES(?)", (n,))
        for r in DEFAULT_RULES:
            db.execute("INSERT OR IGNORE INTO rules(id,name,event_type,threshold,window_sec,group_field,severity,explanation,recommendation,response_action,response_level) VALUES(?,?,?,?,?,?,?,?,?,?,?)", r)
        for eid, name, typ in BOOT_ENVS:  # registry entries; ingest key unset until rotated by an admin
            db.execute("INSERT OR IGNORE INTO environments(id,name,type,key_hash,created) VALUES(?,?,?,?,?)",
                       (eid, name, typ, "unset", iso()))
    db.close()

# ---------- crypto/auth ----------
def hash_pw(pw):
    salt = os.urandom(16)
    return "scrypt$%s$%s" % (salt.hex(), hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex())
DUMMY = hash_pw("dummy-timing-equalizer")
def check_pw(pw, stored):
    try:
        _, s, h = stored.split("$")
        c = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(s), n=2**14, r=8, p=1, dklen=32).hex()
        return hmac.compare_digest(c, h)
    except Exception:
        return False
def new_totp_secret(): return base64.b32encode(os.urandom(20)).decode()
def _hotp(secret, counter):
    d = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), "sha1").digest(); o = d[-1] & 15
    return "%06d" % ((struct.unpack(">I", d[o:o+4])[0] & 0x7FFFFFFF) % 10**6)
def totp_now(secret): return _hotp(secret, int(clock() // 30))
def verify_totp(secret, code):
    """Return the matching 30s step number or None."""
    base = int(clock() // 30)
    for s in (base - 1, base, base + 1):
        if hmac.compare_digest(_hotp(secret, s), str(code)): return s
    return None
def sha(s): return hashlib.sha256(s.encode()).hexdigest()

# ---------- audit chain ----------
def audit(db, actor, action, target=None, detail=None):
    row = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    prev = row[0] if row else "0" * 64
    ts = iso()
    body = json.dumps({"actor": actor, "action": action, "target": target, "detail": detail, "ts": ts}, sort_keys=True)
    db.execute("INSERT INTO audit(ts,actor,action,target,body,prev_hash,hash) VALUES(?,?,?,?,?,?,?)",
               (ts, actor, action, target, body, prev, sha(prev + body)))

def verify_audit(db):
    prev = "0" * 64
    for r in db.execute("SELECT seq,body,prev_hash,hash FROM audit ORDER BY seq"):
        if r["prev_hash"] != prev or sha(prev + r["body"]) != r["hash"]:
            return {"ok": False, "broken_at": r["seq"]}
        prev = r["hash"]
    return {"ok": True, "head": prev}

# ---------- detection ----------
SEV = {"info": 10, "low": 20, "medium": 40, "high": 70, "critical": 90}
SAFE_FIELD = re.compile(r"^[A-Za-z0-9_]{1,40}$")

def emit_event(db, env_id, source, type_, severity, evidence):
    eid = str(uuid.uuid4()); ts = iso()
    db.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (eid, env_id, ts, source, type_, severity, json.dumps(evidence)))
    if type_ == "heartbeat":
        db.execute("UPDATE environments SET last_heartbeat=? WHERE id=?", (ts, env_id)); return eid, []
    return eid, _detect(db, eid, env_id, type_, evidence)

def _detect(db, eid, env_id, type_, ev):
    out = []
    for r in db.execute("SELECT * FROM rules WHERE enabled=1 AND event_type=?", (type_,)).fetchall():
        gf = r["group_field"]; gv = "*"
        if gf:
            if ev.get(gf) is None: continue
            gv = str(ev[gf])
        n = 1
        if r["threshold"] > 1:
            cut = iso(clock() - r["window_sec"])
            q, a = "SELECT COUNT(*) FROM events WHERE env_id=? AND type=? AND ts>=?", [env_id, type_, cut]
            if gf: q += " AND CAST(json_extract(evidence,?) AS TEXT)=?"; a += ["$." + gf, gv]
            n = db.execute(q, a).fetchone()[0]
            if n < r["threshold"]: continue
        out.append(_raise(db, r, env_id, gv, eid, n))
    return out

def _raise(db, r, env_id, gv, eid, n):
    key = "%s|%s|%s" % (r["id"], env_id, gv); ts = iso()
    risk = min(100, SEV[r["severity"]] + min(10, n))
    inc = db.execute("SELECT id,count FROM incidents WHERE dedupe_key=? AND status!='closed'", (key,)).fetchone()
    if inc:
        db.execute("UPDATE incidents SET count=count+1, updated=?, risk=? WHERE id=?", (ts, risk, inc["id"]))
        if db.execute("SELECT COUNT(*) FROM incident_events WHERE incident_id=?", (inc["id"],)).fetchone()[0] < 200:
            db.execute("INSERT OR IGNORE INTO incident_events VALUES(?,?)", (inc["id"], eid))
        return inc["id"]
    iid = str(uuid.uuid4())
    db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (iid, env_id, r["id"], key, r["severity"], risk, "classified", r["name"] + (" (%s)" % gv if gv != "*" else ""),
                r["explanation"], r["recommendation"], 1, ts, ts))
    db.execute("INSERT INTO incident_events VALUES(?,?)", (iid, eid))
    audit(db, "system", "incident.created", iid, {"rule": r["id"], "env": env_id, "risk": risk, "group": gv})
    if r["severity"] in ("high", "critical"):
        db.execute("INSERT OR IGNORE INTO notifications(dedupe_key,severity,message,created) VALUES(?,?,?,?)",
                   (key, r["severity"], "%s on %s" % (r["name"], env_id), ts))
    if r["response_action"] and r["response_level"] >= 2:
        params = {"ip": gv} if r["group_field"] == "ip" else {}
        if r["preauthorized"] and r["response_action"] in PREAUTH:
            rid = _new_response(db, iid, r["response_action"], params, 3, "approved", "rule", "rule:" + r["id"])
            execute(db, rid, "system")
        else:
            _new_response(db, iid, r["response_action"], params, r["response_level"], "recommended" if r["response_level"] == 2 else "pending_approval", "rule", "rule:" + r["id"])
    return iid

# ---------- response ----------
PREAUTH = {"block_ip"}          # only these may ever run without a human
ACTIONS = {"block_ip", "revoke_sessions"}   # closed whitelist; nothing touching FLRXCORE/AXIS business logic exists

def validate_action(action, params):
    if action not in ACTIONS: raise ValueError("action not allowed: %r" % str(action)[:40])
    if not isinstance(params, dict): raise ValueError("params must be an object")
    if action == "block_ip":
        ip = ipaddress.ip_address(str(params.get("ip")))
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast: raise ValueError("refusing to block this address")
        return {"ip": str(ip)}
    uid = params.get("user_id")
    if not isinstance(uid, int): raise ValueError("user_id required")
    return {"user_id": uid}

def _new_response(db, iid, action, params, level, status, origin, by):
    cur = db.execute("INSERT INTO responses(incident_id,action,params,level,status,origin,requested_by,created) VALUES(?,?,?,?,?,?,?,?)",
                     (iid, action, json.dumps(params), level, status, origin, by, iso()))
    return cur.lastrowid

def execute(db, rid, actor):
    r = db.execute("SELECT * FROM responses WHERE id=?", (rid,)).fetchone()
    if r["status"] != "approved": raise PermissionError("response not authorized")
    p = validate_action(r["action"], json.loads(r["params"])); res = {}
    try:
        if r["action"] == "block_ip":
            if db.execute("SELECT COUNT(*) FROM blocklist").fetchone()[0] >= 50: raise RuntimeError("blocklist cap reached")
            db.execute("INSERT OR REPLACE INTO blocklist VALUES(?,?,?)", (p["ip"], rid, iso()))
            res["verified"] = db.execute("SELECT 1 FROM blocklist WHERE ip=?", (p["ip"],)).fetchone() is not None
        else:
            n = db.execute("DELETE FROM sessions WHERE user_id=?", (p["user_id"],)).rowcount
            res = {"sessions_revoked": n, "verified": db.execute("SELECT 1 FROM sessions WHERE user_id=?", (p["user_id"],)).fetchone() is None}
        status = "verified" if res.get("verified") else "failed"
    except Exception as e:
        res, status = {"error": str(e)}, "failed"
    db.execute("UPDATE responses SET status=?, executed_at=?, result=? WHERE id=?", (status, iso(), json.dumps(res), rid))
    audit(db, actor, "response.executed", str(rid), {"action": r["action"], "params": p, "status": status, "level": r["level"]})
    return status

def rollback(db, rid, actor):
    r = db.execute("SELECT * FROM responses WHERE id=?", (rid,)).fetchone()
    if r["action"] != "block_ip" or r["status"] not in ("verified", "executed"): return False
    db.execute("DELETE FROM blocklist WHERE response_id=?", (rid,))
    db.execute("UPDATE responses SET status='rolled_back' WHERE id=?", (rid,))
    audit(db, actor, "response.rolled_back", str(rid), None); return True

# ---------- AI adapter (output is untrusted) ----------
class RuleBasedProvider:
    name = "rule-based-local"
    def investigate(self, ctx):
        recs = []
        if ctx.get("suggested_action") and ctx.get("suggested_params"):
            recs.append({"action": ctx["suggested_action"], "params": ctx["suggested_params"], "reason": "Rule-defined response"})
        return json.dumps({"summary": "%s: %d matching events. %s" % (ctx["title"], ctx["count"], ctx["explanation"]), "recommendations": recs})

class HttpJsonProvider:
    """Generic JSON-over-HTTP adapter. UNTESTED against a real service; point NEXGUARD_AI_URL at a compatible gateway."""
    name = "http-json"
    def __init__(self, url, key): self.url, self.key = url, key
    def investigate(self, ctx):
        req = urllib.request.Request(self.url, json.dumps(ctx).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + self.key})
        with urllib.request.urlopen(req, timeout=15) as r: return r.read(65536).decode()

def get_provider():
    u = os.environ.get("NEXGUARD_AI_URL")
    return HttpJsonProvider(u, os.environ.get("NEXGUARD_AI_KEY", "")) if u else RuleBasedProvider()

def investigate(db, iid, actor, provider):
    inc = db.execute("SELECT i.*, r.response_action FROM incidents i JOIN rules r ON r.id=i.rule_id WHERE i.id=?", (iid,)).fetchone()
    evs = [dict(e) for e in db.execute("SELECT e.ts,e.type,e.severity,e.evidence FROM events e JOIN incident_events ie ON ie.event_id=e.id WHERE ie.incident_id=? LIMIT 25", (iid,))]
    params = {}
    if inc["response_action"] == "block_ip":
        k = inc["dedupe_key"].split("|")[-1]; params = {"ip": k}
    ctx = {"title": inc["title"], "count": inc["count"], "explanation": inc["explanation"], "events": evs,
           "suggested_action": inc["response_action"], "suggested_params": params}
    try:
        data = json.loads(provider.investigate(ctx))
        summary, recs = str(data["summary"])[:4000], data.get("recommendations", [])
        if not isinstance(recs, list): raise ValueError("recommendations must be a list")
    except Exception as e:
        db.execute("INSERT INTO ai_investigations(incident_id,provider,status,error,created) VALUES(?,?,?,?,?)",
                   (iid, provider.name, "unavailable", str(e)[:300], iso()))
        audit(db, actor, "ai.unavailable", iid, {"provider": provider.name}); return {"status": "unavailable", "error": str(e)[:300]}
    acc, rej = [], []
    for r in recs[:10]:
        try:
            p = validate_action(r["action"], r.get("params", {}))
            dup = db.execute("SELECT 1 FROM responses WHERE incident_id=? AND action=? AND params=? AND status IN ('pending_approval','recommended')", (iid, r["action"], json.dumps(p))).fetchone()
            rid = None if dup else _new_response(db, iid, r["action"], p, 4, "pending_approval", "ai", "ai:" + provider.name)
            acc.append({"action": r["action"], "params": p, "response_id": rid})
        except Exception as e:
            rej.append({"raw": str(r)[:200], "reason": str(e)[:120]})
    db.execute("INSERT INTO ai_investigations(incident_id,provider,status,summary,accepted,rejected,created) VALUES(?,?,?,?,?,?,?)",
               (iid, provider.name, "ok", summary, json.dumps(acc), json.dumps(rej), iso()))
    audit(db, actor, "ai.investigated", iid, {"provider": provider.name, "accepted": len(acc), "rejected": len(rej)})
    return {"status": "ok", "summary": summary, "accepted": acc, "rejected": rej}

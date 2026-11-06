import json, os, re, secrets, sys, uuid
from collections import defaultdict, deque
from functools import wraps
from flask import Flask, g, jsonify, request
from . import core
from .core import tx, audit, iso

PERMS = {
 "super_admin": {"*"},
 "security_admin": {"dashboard.view","events.view","incident.manage","incident.investigate","response.approve","env.manage","rules.manage","audit.view"},
 "analyst": {"dashboard.view","events.view","incident.manage","incident.investigate"},
 "auditor": {"dashboard.view","events.view","audit.view"},
 "viewer": {"dashboard.view"},
}
STAGES = ["detected","classified","investigating","risk_assessed","response_recommended","authorized","executed","verified","closed"]
SEVS = {"info","low","medium","high","critical"}
NAME = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")

def create_app(db_path):
    core.init_db(db_path)
    app = Flask(__name__); app.config["DB"] = db_path; app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    app.config["AI_PROVIDER"] = None
    hits = defaultdict(deque)

    def limited(key, n, per=60):
        q = hits[key]; t = core.clock()
        while q and q[0] < t - per: q.popleft()
        if len(q) >= n: return True
        q.append(t); return False

    @app.before_request
    def _open():
        g.db = core.connect(app.config["DB"]); g.user = None
        if g.db.execute("SELECT 1 FROM blocklist WHERE ip=?", (request.remote_addr,)).fetchone():
            return jsonify(error="blocked"), 403
        h = request.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            r = g.db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1",
                             (core.sha(h[7:]), core.clock())).fetchone()
            g.user = r
    @app.teardown_request
    def _close(_):
        db = g.pop("db", None)
        if db: db.close()

    def need(perm):
        def deco(f):
            @wraps(f)
            def w(*a, **k):
                if not g.user: return jsonify(error="unauthenticated"), 401
                perms = PERMS[g.user["role"]]
                if "*" not in perms and perm not in perms:
                    with tx(g.db): audit(g.db, g.user["username"], "access.denied", request.path, {"perm": perm})
                    return jsonify(error="forbidden"), 403
                return f(*a, **k)
            return w
        return deco
    actor = lambda: g.user["username"]
    body = lambda: request.get_json(silent=True) or {}

    def step_up():
        """Fresh TOTP code required for consequential actions; one-time per 30s step."""
        s = core.verify_totp(g.user["totp_secret"], str(body().get("totp_code", "")))
        if s is None or s <= g.user["last_totp_step"]: return False
        g.db.execute("UPDATE users SET last_totp_step=? WHERE id=?", (s, g.user["id"])); return True

    # ---- auth ----
    @app.post("/api/login")
    def login():
        d = body(); ip = request.remote_addr
        if limited("login:" + ip, 10): return jsonify(error="rate limited"), 429
        u = g.db.execute("SELECT * FROM users WHERE username=?", (str(d.get("username", "")),)).fetchone()
        ok, step = False, None
        pw_ok = core.check_pw(str(d.get("password", "")), u["pw_hash"] if u else core.DUMMY)
        if u and pw_ok and u["active"] and u["locked_until"] < core.clock():
            step = core.verify_totp(u["totp_secret"], str(d.get("totp", "")))
            ok = step is not None and step > u["last_totp_step"]
        with tx(g.db):
            if not ok:
                if u:
                    f = u["failed"] + 1
                    g.db.execute("UPDATE users SET failed=?, locked_until=? WHERE id=?", (f, core.clock() + 900 if f >= 5 else u["locked_until"], u["id"]))
                core.emit_event(g.db, "env-nexguard", "nexguard-auth", "auth_failed", "medium", {"ip": ip, "username": str(d.get("username", ""))[:64]})
                audit(g.db, "anonymous", "login.failed", str(d.get("username", ""))[:64], {"ip": ip})
                return jsonify(error="invalid credentials"), 401
            tok = secrets.token_urlsafe(32)
            g.db.execute("UPDATE users SET failed=0, last_totp_step=? WHERE id=?", (step, u["id"]))
            g.db.execute("INSERT INTO sessions VALUES(?,?,?)", (core.sha(tok), u["id"], core.clock() + 8 * 3600))
            audit(g.db, u["username"], "login.ok", None, {"ip": ip})
        return jsonify(token=tok, role=u["role"])

    @app.post("/api/logout")
    @need("dashboard.view")
    def logout():
        with tx(g.db):
            g.db.execute("DELETE FROM sessions WHERE token_hash=?", (core.sha(request.headers["Authorization"][7:]),))
        return jsonify(ok=True)

    @app.post("/api/users")
    @need("users.manage")
    def make_user():
        d = body(); role = d.get("role"); pw = str(d.get("password", ""))
        if not NAME.match(str(d.get("username", ""))) or role not in PERMS or len(pw) < 12: return jsonify(error="invalid username, role or password (min 12 chars)"), 400
        sec = core.new_totp_secret()
        with tx(g.db):
            try: g.db.execute("INSERT INTO users(username,pw_hash,role,totp_secret) VALUES(?,?,?,?)", (d["username"], core.hash_pw(pw), role, sec))
            except Exception: return jsonify(error="username exists"), 409
            audit(g.db, actor(), "user.created", d["username"], {"role": role})
            core.emit_event(g.db, "env-nexguard", "nexguard-admin", "privilege_change", "high", {"user": d["username"], "role": role, "by": actor()})
        return jsonify(username=d["username"], totp_secret=sec), 201

    # ---- environments / ingestion ----
    @app.post("/api/environments")
    @need("env.manage")
    def reg_env():
        d = body(); key = secrets.token_urlsafe(32); eid = "env-" + uuid.uuid4().hex[:8]
        if not NAME.match(str(d.get("name", ""))): return jsonify(error="invalid name"), 400
        with tx(g.db):
            try: g.db.execute("INSERT INTO environments(id,name,type,policy,key_hash,created) VALUES(?,?,?,?,?,?)",
                              (eid, d["name"], str(d.get("type", "application"))[:32], json.dumps(d.get("policy", {})), core.sha(key), iso()))
            except Exception: return jsonify(error="name exists"), 409
            audit(g.db, actor(), "environment.registered", eid, {"name": d["name"]})
        return jsonify(id=eid, ingest_key=key), 201

    @app.post("/api/environments/<eid>/rotate-key")
    @need("env.manage")
    def rotate(eid):
        key = secrets.token_urlsafe(32)
        with tx(g.db):
            if not g.db.execute("UPDATE environments SET key_hash=? WHERE id=?", (core.sha(key), eid)).rowcount: return jsonify(error="not found"), 404
            audit(g.db, actor(), "environment.key_rotated", eid, None)
        return jsonify(ingest_key=key)

    @app.get("/api/environments")
    @need("dashboard.view")
    def envs():
        out = []
        for e in g.db.execute("SELECT * FROM environments ORDER BY name"):
            hb = e["last_heartbeat"]; st = "no_data" if not hb else ("healthy" if core.clock() - _ts(hb) < 120 else "stale")
            last = g.db.execute("SELECT type,severity,ts FROM events WHERE env_id=? ORDER BY ts DESC LIMIT 1", (e["id"],)).fetchone()
            out.append({"id": e["id"], "name": e["name"], "type": e["type"], "monitoring": st, "last_heartbeat": hb,
                        "policy": json.loads(e["policy"]), "latest_event": dict(last) if last else None, "ingest_key_set": e["key_hash"] != "unset"})
        return jsonify(out)

    def _ts(s):
        from datetime import datetime, timezone
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()

    @app.post("/api/events")
    def ingest():
        key = request.headers.get("X-Ingest-Key", "")
        env = g.db.execute("SELECT id FROM environments WHERE key_hash=? AND key_hash!='unset'", (core.sha(key),)).fetchone() if key else None
        if not env: return jsonify(error="invalid ingest key"), 401
        if limited("ing:" + env["id"], 600): return jsonify(error="rate limited"), 429
        d = body(); t = str(d.get("type", "")); sev = d.get("severity", "info"); ev = d.get("evidence", {})
        if not NAME.match(t) or sev not in SEVS or not isinstance(ev, dict) or len(json.dumps(ev)) > 16384: return jsonify(error="invalid event"), 400
        with tx(g.db): eid, inc = core.emit_event(g.db, env["id"], str(d.get("source", "agent"))[:64], t, sev, ev)
        return jsonify(event_id=eid, incidents=inc), 202

    @app.get("/api/events")
    @need("events.view")
    def events():
        lim = min(int(request.args.get("limit", 50)), 200); before = request.args.get("before", "9")
        q, a = "SELECT * FROM events WHERE ts<?", [before]
        if request.args.get("env"): q += " AND env_id=?"; a.append(request.args["env"])
        rows = g.db.execute(q + " ORDER BY ts DESC LIMIT ?", a + [lim]).fetchall()
        return jsonify([dict(r, evidence=json.loads(r["evidence"])) for r in rows])

    # ---- rules ----
    @app.get("/api/rules")
    @need("events.view")
    def rules(): return jsonify([dict(r) for r in g.db.execute("SELECT * FROM rules")])

    @app.patch("/api/rules/<rid>")
    @need("rules.manage")
    def patch_rule(rid):
        d = body(); sets, a = [], []
        for k, ok in (("threshold", lambda v: isinstance(v, int) and 1 <= v <= 100000), ("window_sec", lambda v: isinstance(v, int) and 0 <= v <= 86400),
                      ("enabled", lambda v: v in (0, 1)), ("severity", lambda v: v in SEVS), ("response_level", lambda v: v in (1, 2, 3, 4)),
                      ("preauthorized", lambda v: v in (0, 1))):
            if k in d:
                if not ok(d[k]): return jsonify(error="invalid " + k), 400
                sets.append(k + "=?"); a.append(d[k])
        if d.get("preauthorized") == 1:
            r = g.db.execute("SELECT response_action FROM rules WHERE id=?", (rid,)).fetchone()
            if not r or r["response_action"] not in core.PREAUTH: return jsonify(error="rule action cannot be preauthorized"), 400
            if "response_level" not in d: sets.append("response_level=?"); a.append(3)
        if not sets: return jsonify(error="nothing to change"), 400
        if (d.get("preauthorized") == 1 or d.get("enabled") == 0) and not step_up(): return jsonify(error="step-up verification required"), 401
        with tx(g.db):
            if not g.db.execute("UPDATE rules SET %s WHERE id=?" % ",".join(sets), a + [rid]).rowcount: return jsonify(error="not found"), 404
            audit(g.db, actor(), "rule.changed", rid, d)
        return jsonify(ok=True)

    # ---- incidents / AI / responses ----
    @app.get("/api/incidents")
    @need("events.view")
    def incidents():
        lim = min(int(request.args.get("limit", 50)), 200)
        return jsonify([dict(r) for r in g.db.execute("SELECT * FROM incidents ORDER BY risk DESC, updated DESC LIMIT ?", (lim,))])

    @app.get("/api/incidents/<iid>")
    @need("events.view")
    def incident(iid):
        i = g.db.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        if not i: return jsonify(error="not found"), 404
        return jsonify(incident=dict(i),
            ai=[dict(r) for r in g.db.execute("SELECT * FROM ai_investigations WHERE incident_id=? ORDER BY id DESC", (iid,))],
            responses=[dict(r) for r in g.db.execute("SELECT * FROM responses WHERE incident_id=?", (iid,))])

    @app.post("/api/incidents/<iid>/status")
    @need("incident.manage")
    def status(iid):
        new = body().get("status"); i = g.db.execute("SELECT status FROM incidents WHERE id=?", (iid,)).fetchone()
        if not i: return jsonify(error="not found"), 404
        if new not in STAGES or STAGES.index(new) <= STAGES.index(i["status"]): return jsonify(error="transition not allowed"), 409
        with tx(g.db):
            if new == "closed" and g.db.execute("SELECT 1 FROM responses WHERE incident_id=? AND status='pending_approval'", (iid,)).fetchone():
                return jsonify(error="pending approvals must be resolved first"), 409
            g.db.execute("UPDATE incidents SET status=?, updated=? WHERE id=?", (new, iso(), iid))
            audit(g.db, actor(), "incident.status", iid, {"from": i["status"], "to": new})
        return jsonify(ok=True)

    @app.post("/api/incidents/<iid>/investigate")
    @need("incident.investigate")
    def invest(iid):
        if not g.db.execute("SELECT 1 FROM incidents WHERE id=?", (iid,)).fetchone(): return jsonify(error="not found"), 404
        if limited("ai:" + iid, 2): return jsonify(error="investigation rate limited"), 429
        with tx(g.db): r = core.investigate(g.db, iid, actor(), app.config["AI_PROVIDER"] or core.get_provider())
        return jsonify(r)

    @app.post("/api/responses/<int:rid>/<verb>")
    @need("response.approve")
    def respond(rid, verb):
        if verb not in ("approve", "reject", "rollback"): return jsonify(error="unknown"), 404
        r = g.db.execute("SELECT * FROM responses WHERE id=?", (rid,)).fetchone()
        if not r: return jsonify(error="not found"), 404
        if not step_up(): return jsonify(error="step-up verification required"), 401
        with tx(g.db):
            if verb == "reject" and r["status"] in ("recommended", "pending_approval"):
                g.db.execute("UPDATE responses SET status='rejected', approved_by=? WHERE id=?", (actor(), rid))
                audit(g.db, actor(), "response.rejected", str(rid), None); return jsonify(status="rejected")
            if verb == "rollback": return jsonify(rolled_back=core.rollback(g.db, rid, actor()))
            if verb != "approve" or r["status"] not in ("recommended", "pending_approval"): return jsonify(error="invalid state"), 409
            g.db.execute("UPDATE responses SET status='approved', approved_by=? WHERE id=?", (actor(), rid))
            audit(g.db, actor(), "response.approved", str(rid), {"action": r["action"], "params": json.loads(r["params"])})
            return jsonify(status=core.execute(g.db, rid, actor()))

    # ---- audit / dashboard ----
    @app.get("/api/audit")
    @need("audit.view")
    def audit_list():
        lim = min(int(request.args.get("limit", 50)), 200)
        return jsonify([dict(r) for r in g.db.execute("SELECT seq,ts,actor,action,target,hash FROM audit ORDER BY seq DESC LIMIT ?", (lim,))])

    @app.get("/api/audit/verify")
    @need("audit.view")
    def audit_verify(): return jsonify(core.verify_audit(g.db))

    @app.get("/api/integrations")
    @need("dashboard.view")
    def integrations(): return jsonify([dict(r) for r in g.db.execute("SELECT name,enabled,status,last_check,last_error FROM integrations")])

    @app.get("/api/dashboard")
    @need("dashboard.view")
    def dashboard():
        q = lambda s, *a: g.db.execute(s, a).fetchall()
        since = iso(core.clock() - 86400)
        return jsonify(
            incidents_by_severity={r[0]: r[1] for r in q("SELECT severity,COUNT(*) FROM incidents WHERE status!='closed' GROUP BY severity")},
            open_incidents=q("SELECT COUNT(*) FROM incidents WHERE status!='closed'")[0][0],
            critical=[dict(r) for r in q("SELECT id,title,risk,status,updated FROM incidents WHERE severity='critical' AND status!='closed' ORDER BY risk DESC LIMIT 10")],
            timeline=[{"hour": r[0], "events": r[1]} for r in q("SELECT substr(ts,1,13),COUNT(*) FROM events WHERE ts>=? GROUP BY 1 ORDER BY 1", since)],
            pending_approvals=q("SELECT COUNT(*) FROM responses WHERE status='pending_approval'")[0][0],
            recent_responses=[dict(r) for r in q("SELECT id,incident_id,action,level,status,origin,executed_at FROM responses ORDER BY id DESC LIMIT 10")],
            ai=[dict(r) for r in q("SELECT incident_id,provider,status,summary,created FROM ai_investigations ORDER BY id DESC LIMIT 5")],
            notifications=[dict(r) for r in q("SELECT severity,message,created FROM notifications ORDER BY id DESC LIMIT 10")],
            audit_integrity=core.verify_audit(g.db),
            admin_sessions=[dict(r) for r in q("SELECT ts,actor,action FROM audit WHERE action LIKE 'login.%' OR action LIKE 'user.%' ORDER BY seq DESC LIMIT 10")])

    @app.get("/")
    def index():
        return open(os.path.join(os.path.dirname(__file__), "dashboard.html"), encoding="utf-8").read()
    return app

if __name__ == "__main__":
    path = os.environ.get("NEXGUARD_DB", "nexguard.db")
    if len(sys.argv) > 2 and sys.argv[1] == "create-admin":
        import getpass; core.init_db(path); db = core.connect(path); pw = os.environ.get("NEXGUARD_ADMIN_PASSWORD") or getpass.getpass("Password (min 12): ")
        assert len(pw) >= 12; sec = core.new_totp_secret()
        with tx(db):
            db.execute("INSERT INTO users(username,pw_hash,role,totp_secret) VALUES(?,?,?,?)", (sys.argv[2], core.hash_pw(pw), "super_admin", sec))
            audit(db, "cli", "user.created", sys.argv[2], {"role": "super_admin"})
        print("TOTP secret (add to authenticator now; shown once):", sec)
    else:
        create_app(path).run(host=os.environ.get("NEXGUARD_HOST", "127.0.0.1"), port=int(os.environ.get("NEXGUARD_PORT", 8080)))

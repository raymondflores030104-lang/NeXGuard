# NEXGUARD (MVP vertical slice)

Security monitoring, deterministic detection, incident response with human approval, AI-assisted investigation (untrusted output), and a tamper-evident audit chain, for FLOURAXIOM, AXIS and FLRXCORE.
Stack: Python 3.12, Flask, SQLite (WAL), stdlib crypto (scrypt, TOTP). Chosen because only Flask was installed and the network was disabled; production should use PostgreSQL + gunicorn + a queue.

## Run
    pip install -r requirements.txt
    NEXGUARD_ADMIN_PASSWORD='<12+ chars>' python -m nexguard.app create-admin root   # prints TOTP secret once
    python -m nexguard.app                      # http://127.0.0.1:8080  (put TLS reverse proxy in front)
    python -m unittest discover -s tests -v
Docker: `docker build -t nexguard . && docker run -p 8080:8080 -v ng:/data -e NEXGUARD_DB=/data/nexguard.db nexguard` (Dockerfile not build-tested here).

## Ingest (per-environment key from POST /api/environments or /rotate-key)
    curl -H "X-Ingest-Key: $KEY" -H 'Content-Type: application/json' -d '{"type":"auth_failed","severity":"medium","evidence":{"ip":"203.0.113.9"}}' http://host:8080/api/events
Send `heartbeat` events to mark an environment healthy (stale after 120 s).

## API
POST /api/login, /logout, /users | GET,POST /api/environments, POST /environments/<id>/rotate-key | POST,GET /api/events | GET /api/rules, PATCH /api/rules/<id> | GET /api/incidents[/<id>], POST /incidents/<id>/status, /investigate | POST /api/responses/<id>/approve|reject|rollback (needs fresh `totp_code`) | GET /api/audit, /audit/verify, /dashboard, /integrations

## Security design
- AI output is parsed as untrusted JSON; actions must be in a closed whitelist (`block_ip`, `revoke_sessions`) with validated params; accepted items become `pending_approval`. Nothing the AI returns can execute. No action touching FLWRX, balances, keys, DCA or business logic exists in code.
- Only rules explicitly set `preauthorized` (needs step-up) and whose action is in `PREAUTH` run without a human.
- Audit: SHA-256 hash chain, DB triggers block UPDATE/DELETE. Events table is append-only by trigger (not individually chained).
- Config: `NEXGUARD_AI_URL`/`NEXGUARD_AI_KEY` (optional), `NEXGUARD_DB`, `NEXGUARD_HOST`, `NEXGUARD_PORT`.

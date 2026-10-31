# Open Redirect Training Lab

A deliberately vulnerable Flask app for local security testing and Nuclei-template practice.

## Run with Docker (recommended)

From this directory:

```bash
docker compose up --build
```

Open `http://127.0.0.1:5000` in your browser. The Docker port is explicitly bound to the host loopback interface (`127.0.0.1`), not to all network interfaces.

Stop it with:

```bash
docker compose down
```

## Run directly with Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /` | Lab home page |
| `GET /redirect?url=https://example.org` | Intentionally vulnerable open redirect (302) |
| `GET /safe-redirect?url=/` | Same-site-path-only comparison route |
| `GET /healthz` | Health check |

## Verify the vulnerability

```bash
curl -i 'http://127.0.0.1:5000/redirect?url=https%3A%2F%2Fexample.org'
```

Expected evidence: a `302` response and a `Location: https://example.org` header.

Compare the safe route:

```bash
curl -i 'http://127.0.0.1:5000/safe-redirect?url=https%3A%2F%2Fexample.org'
```

Expected evidence: `400 BAD REQUEST` because external absolute URLs are rejected.

## Safety

This application is intentionally insecure. Use it only on your own machine or an isolated lab network. Do not deploy it to a public server or expose port 5000 to the internet.

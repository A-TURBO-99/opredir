"""Intentionally vulnerable Open Redirect training lab.

Run locally by default: python app.py
For Docker only, docker-compose sets LAB_HOST=0.0.0.0 inside the container;
the published port is still bound to 127.0.0.1 on the host.
"""

import os
from urllib.parse import urlsplit

from flask import Flask, abort, redirect, render_template, request

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/redirect")
def vulnerable_redirect():
    """VULNERABLE: redirects to a user-controlled URL without validation."""
    destination = request.args.get("url", "https://example.org")
    return redirect(destination, code=302)


@app.get("/safe-redirect")
def safe_redirect():
    """Safer comparison route: allow local absolute-path redirects only."""
    destination = request.args.get("url", "/")
    parsed = urlsplit(destination)

    # Reject absolute URLs, protocol-relative URLs and ambiguous backslashes.
    if (
        parsed.scheme
        or parsed.netloc
        or not destination.startswith("/")
        or destination.startswith("//")
        or "\\" in destination
    ):
        abort(400, description="Only same-site paths are allowed.")

    return redirect(destination, code=302)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "lab": "open-redirect"}


if __name__ == "__main__":
    host = os.environ.get("LAB_HOST", "127.0.0.1")
    port = int(os.environ.get("LAB_PORT", "5000"))
    app.run(host=host, port=port, debug=False)

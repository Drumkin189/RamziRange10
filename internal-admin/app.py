#!/usr/bin/env python3
"""
internal-admin - a mock internal service with NO host port (reachable only from
inside the Docker network, e.g. via the main app's SSRF).

RR10 change: the endpoints the SSRF carriers point at are deliberately
CREDENTIAL-FREE. On RR9 the SSRF target returned SSH_DEPLOY_PASSWORD, so the
"Exposed Credentials in Web Response" detector outranked the SSRF detector and
H3-2025-0076 / H3-2026-0024 never got their own finding. Internal topology,
metadata and metrics prove the SSRF just as well and collide with nothing.

/creds still exists for manual chain demos, but nothing links to it.
Deliberately insecure; lab use only.
"""
import subprocess
from flask import Flask, request, Response

app = Flask(__name__)


@app.route("/")
def index():
    return ("internal-admin (not internet-facing)\n"
            "endpoints: /status  /latest/meta-data/  /metrics  /exec?cmd=\n")


# ---------------------------------------------------------------------------
# SSRF proof surfaces - NO credential-shaped strings anywhere below.
# ---------------------------------------------------------------------------

@app.route("/status")
def status():
    """Internal service registry. Proves the SSRF reached a non-routable host."""
    return Response(
        "internal-admin: ok\n"
        "cluster: rr10-prod-internal\n"
        "bound: 0.0.0.0:5000 (docker network 'range', no published port)\n"
        "\n"
        "service registry:\n"
        "  rr10-app        10.30.0.11:5000   up    flask/3.x\n"
        "  rr10-db         10.30.0.12:3306   up    mariadb/10.5\n"
        "  internal-admin  10.30.0.13:5000   up    flask/3.x\n"
        "  rr10-proxy      10.30.0.10:9700   up    nginx/1.27\n"
        "\n"
        "this host is only reachable from inside the container network.\n",
        mimetype="text/plain")


@app.route("/latest/meta-data/")
@app.route("/latest/meta-data/<path:sub>")
def metadata(sub=""):
    """Cloud-metadata shaped, but without an IAM credential document."""
    tree = {
        "": "ami-id\nhostname\ninstance-id\ninstance-type\nlocal-ipv4\n"
            "placement/\nnetwork/\n",
        "ami-id": "ami-0ffee1nternal10\n",
        "hostname": "internal-admin.range.local\n",
        "instance-id": "i-0ffee1nternal10\n",
        "instance-type": "t3.medium\n",
        "local-ipv4": "10.30.0.13\n",
        "placement/": "availability-zone\nregion\n",
        "placement/availability-zone": "us-east-1c\n",
        "placement/region": "us-east-1\n",
        "network/": "interfaces/\n",
        "network/interfaces/": "macs/\n",
    }
    return Response(tree.get(sub.rstrip("/") if sub else "", tree.get(sub, "not found\n")),
                    mimetype="text/plain")


@app.route("/metrics")
def metrics():
    """Prometheus-shaped internal metrics. Pure numbers, nothing secret."""
    return Response(
        "# HELP rr10_internal_requests_total Requests handled by internal-admin\n"
        "# TYPE rr10_internal_requests_total counter\n"
        'rr10_internal_requests_total{service="internal-admin"} 48213\n'
        "# HELP rr10_internal_up Service liveness\n"
        "# TYPE rr10_internal_up gauge\n"
        'rr10_internal_up{service="rr10-app"} 1\n'
        'rr10_internal_up{service="rr10-db"} 1\n'
        'rr10_internal_up{service="internal-admin"} 1\n'
        "# HELP rr10_db_connections Active DB connections\n"
        "# TYPE rr10_db_connections gauge\n"
        "rr10_db_connections 7\n",
        mimetype="text/plain")


# ---------------------------------------------------------------------------
# Not linked from the range. Kept for manual SSRF-to-lateral-movement demos.
# ---------------------------------------------------------------------------

@app.route("/creds")
def creds():
    return Response("# internal service account registry\n"
                    "SVC_DEPLOY_USER=svc_deploy\n"
                    "SVC_DEPLOY_PASSWORD=D3pl0y!R3l3ase2026\n"
                    "REDIS_PASSWORD=r3d1s-internal-2026\n"
                    "FLAG=RR10{ssrf_reached_internal_admin}\n",
                    mimetype="text/plain")


@app.route("/exec")
def exec_cmd():
    """Internal RCE - if the SSRF can drive this, it's a second host-compromise hop."""
    cmd = request.args.get("cmd", "")
    if not cmd:
        return "usage: /exec?cmd=<command>\n"
    try:
        return subprocess.run(cmd, shell=True, capture_output=True,
                              text=True, timeout=10).stdout
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

"""AegisNet's local Flask API and dashboard. All statistics come from SQLite."""
from contextlib import closing
import csv
import io
import ipaddress
import math
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from app.database.database import Database, DATABASE_FILE
from app.dashboard import capture_control

DATABASE_PATH = str(DATABASE_FILE)
app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=4096)
RANGES = {"5m": 300, "15m": 900, "1h": 3600, "24h": 86400, "all": None}
PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPv6", "ARP", "OTHER"}


def initialize_database():
    db = Database(DATABASE_PATH)
    for name, column in [("timestamp", "timestamp"), ("source", "source_ip"), ("protocol", "protocol")]:
        db.connection.execute(f"CREATE INDEX IF NOT EXISTS idx_flow_{name} ON flow_records({column})")
    db.connection.execute("CREATE INDEX IF NOT EXISTS idx_response_timestamp ON response_events(timestamp)")
    db.connection.commit()
    db.connection.close()


def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def query_filters(conn, args, include_search=True):
    bounds = conn.execute("SELECT MIN(timestamp) first, MAX(timestamp) last FROM flow_records").fetchone()
    period = args.get("range", "5m")
    if period not in RANGES:
        raise ValueError("Choose a valid time range.")
    clauses, params = ["1=1"], []
    cutoff = None
    if bounds["last"] and RANGES[period]:
        cutoff = (datetime.fromisoformat(bounds["last"]) - timedelta(seconds=RANGES[period])).isoformat()
        clauses.append("timestamp >= ?")
        params.append(cutoff)
    protocol = args.get("protocol", "all")
    if protocol != "all":
        if protocol not in PROTOCOLS:
            raise ValueError("Unknown transport/network protocol.")
        clauses.append("protocol = ?")
        params.append(protocol)
    kind = args.get("kind", "all")
    if kind == "alerts":
        clauses.append("COALESCE(alert_count,0)>0")
    elif kind == "ml":
        clauses.append("ml_anomaly=1")
    elif kind == "flagged":
        clauses.append("(COALESCE(alert_count,0)>0 OR ml_anomaly=1)")
    elif kind != "all":
        raise ValueError("Unknown detection filter.")
    q = args.get("q", "").strip()[:100] if include_search else ""
    if q:
        pattern = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        clauses.append("(source_ip LIKE ? ESCAPE '\\' OR destination_ip LIKE ? ESCAPE '\\' OR CAST(source_port AS TEXT) LIKE ? ESCAPE '\\' OR CAST(destination_port AS TEXT) LIKE ? ESCAPE '\\' OR alert_types LIKE ? ESCAPE '\\')")
        params.extend([pattern] * 5)
    return " AND ".join(clauses), params, dict(bounds), cutoff


def enrich(row):
    row = dict(row)
    protocol = row.get("protocol") or "OTHER"
    if protocol == "ARP":
        family = "ARP / IPv4 mapping"
    else:
        try:
            family = "IPv" + str(ipaddress.ip_address(row["source_ip"]).version)
        except (ValueError, KeyError):
            family = "Unknown"
    ports = {row.get("source_port"), row.get("destination_port")}
    app_proto = row.get("application_protocol")
    service = None
    if app_proto == "DNS":
        service = "DNS · decoded"
    else:
        hints = [(53, "DNS"), (443, "HTTPS / QUIC" if protocol == "UDP" else "HTTPS"),
                 (80, "HTTP"), (22, "SSH"), (123, "NTP"), (67, "DHCP"), (68, "DHCP"), (5353, "mDNS")]
        service = next((name + " · port hint" for port, name in hints if port in ports), None)
    row.update(family=family, service=service or protocol, alerts=[x for x in (row.get("alert_types") or "").split(",") if x])
    return row


def dashboard_data(args):
    with closing(get_db()) as conn:
        where, params, bounds, cutoff = query_filters(conn, args)
        summary = dict(conn.execute(f"""SELECT COUNT(*) flows, COALESCE(SUM(packet_count),0) packets,
            COALESCE(SUM(total_bytes),0) bytes, COALESCE(SUM(alert_count),0) rule_alerts,
            COALESCE(SUM(CASE WHEN ml_anomaly=1 THEN 1 ELSE 0 END),0) anomalies,
            COALESCE(SUM(CASE WHEN alert_count>0 OR ml_anomaly=1 THEN 1 ELSE 0 END),0) flagged,
            COALESCE(SUM(syn_count),0) syn, COALESCE(SUM(ack_count),0) ack,
            COALESCE(SUM(fin_count),0) fin, COALESCE(SUM(rst_count),0) rst,
            MIN(timestamp) first, MAX(timestamp) last
            FROM flow_records WHERE {where}""", params).fetchone())
        summary["endpoints"] = conn.execute(f"SELECT COUNT(*) FROM (SELECT source_ip ip FROM flow_records WHERE {where} UNION SELECT destination_ip FROM flow_records WHERE {where}) WHERE ip IS NOT NULL", params * 2).fetchone()[0]
        summary["average_packet_size"] = summary["bytes"] / summary["packets"] if summary["packets"] else 0
        protocols = [dict(r) for r in conn.execute(f"SELECT protocol, SUM(packet_count) packets, COUNT(*) flows, SUM(total_bytes) bytes FROM flow_records WHERE {where} GROUP BY protocol ORDER BY packets DESC", params)]
        talkers = [dict(r) for r in conn.execute(f"""SELECT source_ip, SUM(total_bytes) bytes,
            SUM(packet_count) packets, COUNT(*) flows, MAX(threat_score) peak_score
            FROM flow_records WHERE {where} GROUP BY source_ip ORDER BY bytes DESC LIMIT 6""", params)]
        recent = [enrich(r) for r in conn.execute(f"SELECT * FROM flow_records WHERE {where} ORDER BY id DESC LIMIT 6", params)]
        flagged = [enrich(r) for r in conn.execute(f"SELECT * FROM flow_records WHERE {where} AND (alert_count>0 OR ml_anomaly=1) ORDER BY id DESC LIMIT 5", params)]
        # The rate is captured bytes / displayed time bucket, not link utilization.
        series = []
        if summary["first"]:
            first = datetime.fromisoformat(summary["first"])
            last = datetime.fromisoformat(summary["last"])
            interval = max(5, math.ceil(max((last-first).total_seconds(), 1) / 60))
            buckets = [dict(r) for r in conn.execute(f"""SELECT CAST(strftime('%s',timestamp) AS INTEGER) / ? bucket,
                SUM(total_bytes) bytes, SUM(packet_count) packets FROM flow_records
                WHERE {where} GROUP BY bucket ORDER BY bucket""", [interval] + params)]
            values = {r["bucket"]: r for r in buckets if r["bucket"] is not None}
            if values:
                for bucket in range(min(values), max(values) + 1):
                    r = values.get(bucket, {"bytes": 0, "packets": 0})
                    stamp = datetime.fromtimestamp(bucket * interval, timezone.utc).replace(tzinfo=None)
                    series.append({"time": stamp.isoformat(), "bytes": r["bytes"], "packets": r["packets"],
                                   "bps": r["bytes"] * 8 / interval, "pps": r["packets"] / interval})
        else:
            interval = 5
        summary["average_bps"] = sum(x["bps"] for x in series) / len(series) if series else 0
        # Response events are window-level decisions and scoped only by time.
        response_where, response_params = ("timestamp >= ?", [cutoff]) if cutoff else ("1=1", [])
        events = [dict(r) for r in conn.execute(f"SELECT * FROM response_events WHERE {response_where} ORDER BY id DESC LIMIT 80", response_params)]
        total_events = conn.execute(f"SELECT COUNT(*) FROM response_events WHERE {response_where}", response_params).fetchone()[0]
        return {"summary": summary, "protocols": protocols, "talkers": talkers, "series": series,
                "interval": interval, "recent": recent, "flagged": flagged,
                "events": events, "event_count": total_events, "bounds": bounds,
                "capture": capture_control.status(), "period": args.get("range", "5m"),
                "notes": {"clock": "Capture host local time", "response": "Window-level simulated decisions; not confirmed attacks."}}


@app.after_request
def headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(ValueError)
def invalid_request(exc):
    return jsonify(success=False, error=str(exc)), 400


@app.errorhandler(sqlite3.Error)
def database_error(exc):
    app.logger.error("Database query failed: %s", exc)
    return jsonify(success=False, error="The database is busy or unavailable. Retry in a moment; check the server terminal if this continues."), 503


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/dashboard")
def dashboard_api():
    return jsonify(success=True, data=dashboard_data(request.args))


@app.route("/api/flows")
def flows_api():
    page = max(1, min(int(request.args.get("page", 1)), 100000))
    limit = 25
    sort = request.args.get("sort", "newest")
    orders = {"newest": "id DESC", "oldest": "id ASC", "bytes": "total_bytes DESC, id DESC", "risk": "threat_score DESC, id DESC"}
    if sort not in orders:
        raise ValueError("Choose a valid sort order.")
    with closing(get_db()) as conn:
        where, params, bounds, _ = query_filters(conn, request.args)
        count = conn.execute(f"SELECT COUNT(*) FROM flow_records WHERE {where}", params).fetchone()[0]
        page = min(page, max(1, math.ceil(count / limit)))
        rows = [enrich(r) for r in conn.execute(f"SELECT * FROM flow_records WHERE {where} ORDER BY {orders[sort]} LIMIT ? OFFSET ?", params + [limit, (page-1)*limit])]
    return jsonify(success=True, data=rows, total=count, page=page, pages=max(1, math.ceil(count/limit)), limit=limit)


@app.route("/api/flows/<int:record_id>")
def flow_api(record_id):
    with closing(get_db()) as conn:
        row = conn.execute("SELECT * FROM flow_records WHERE id=?", (record_id,)).fetchone()
    if row is None:
        return jsonify(success=False, error="Flow record not found."), 404
    return jsonify(success=True, data=enrich(row))


@app.route("/api/export.csv")
def csv_export():
    args = request.args.copy()
    with closing(get_db()) as conn:
        where, params, _, _ = query_filters(conn, args)
    fields = ["id", "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packet_count", "total_bytes", "duration", "threat_score", "alert_types", "ml_anomaly", "ml_anomaly_score", "response_mode"]
    def generate():
        conn = get_db()
        buf = io.StringIO()
        writer = csv.writer(buf)
        try:
            writer.writerow(fields)
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)
            for row in conn.execute(f"SELECT * FROM flow_records WHERE {where} ORDER BY id DESC", params):
                values = [row[k] for k in fields]
                values = [("'" + v) if isinstance(v, str) and v.startswith(("=", "+", "-", "@")) else v for v in values]
                writer.writerow(values)
                yield buf.getvalue()
                buf.seek(0); buf.truncate(0)
        finally:
            conn.close()
    return Response(stream_with_context(generate()), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=AegisNet_Flows.csv"})


@app.route("/api/report.json")
def report_export():
    data = dashboard_data(request.args)
    data["project"] = "Real-Time Network Traffic Monitoring and Intrusion Detection System"
    data["generated_at"] = datetime.now().isoformat()
    data["scope"] = "Selected range ending at latest saved record; event list capped at 80. Anomaly scores are not attack probabilities."
    response = jsonify(data)
    response.headers["Content-Disposition"] = "attachment; filename=AegisNet_Report.json"
    return response


@app.route("/api/capture")
def capture_api():
    return jsonify(success=True, data=capture_control.status())


@app.route("/api/interfaces")
def interfaces_api():
    try:
        return jsonify(success=True, data=capture_control.interfaces())
    except Exception as exc:
        return jsonify(success=False, error=f"Cannot list adapters: {exc}. Install Scapy and Npcap on Windows."), 503


@app.route("/api/capture", methods=["POST"])
def capture_action():
    # Same-origin JSON + custom header prevent a different site starting capture.
    if request.headers.get("X-AegisNet") != "local-dashboard" or not request.is_json:
        return jsonify(success=False, error="Use capture controls in the local dashboard."), 403
    if request.headers.get("Origin") and request.headers["Origin"] != request.host_url.rstrip("/"):
        return jsonify(success=False, error="Origin is not allowed."), 403
    body = request.get_json()
    if not isinstance(body, dict):
        raise ValueError("Expected a JSON object.")
    if body.get("action") == "start":
        result = capture_control.start(body.get("interface"))
    elif body.get("action") == "stop":
        result = capture_control.stop()
    else:
        raise ValueError("Unknown capture action.")
    return jsonify(success=True, data=result)


@app.route("/api/subnet")
def subnet_api():
    interface = ipaddress.ip_interface(request.args.get("cidr", "192.168.1.10/24"))
    net = interface.network
    if net.version == 4:
        usable = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
        first = net.network_address if net.prefixlen >= 31 else net.network_address + 1
        last = net.broadcast_address if net.prefixlen >= 31 else net.broadcast_address - 1
        broadcast = str(net.broadcast_address) if net.prefixlen < 31 else "Not used on /31 or /32"
    else:
        usable, first, last, broadcast = None, None, None, "IPv6 has no broadcast"
    return jsonify(success=True, data={"address": str(interface.ip), "version": net.version, "network": str(net),
        "netmask": str(net.netmask), "broadcast": broadcast, "addresses": str(net.num_addresses),
        "usable": str(usable) if usable is not None else "Depends on IPv6 address scope",
        "first": str(first) if first else "—", "last": str(last) if last else "—"})


initialize_database()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

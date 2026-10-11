import os
import sqlite3
from datetime import datetime

from flask import Flask, jsonify, render_template_string


BASE_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "data",
    "aegisnet.db"
)

app = Flask(__name__)


# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(
        DATABASE_PATH,
        timeout=5,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")

    return conn


def initialize_database():

    os.makedirs(
        os.path.dirname(DATABASE_PATH),
        exist_ok=True
    )

    conn = get_db()

    try:

        # ----------------------------------------------------
        # FLOW RECORD INDEXES
        # ----------------------------------------------------

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_flow_timestamp
            ON flow_records(timestamp)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_flow_source
            ON flow_records(source_ip)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_flow_window
            ON flow_records(window_id)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_flow_protocol
            ON flow_records(protocol)
        """)

        # ----------------------------------------------------
        # RESPONSE EVENT INDEXES
        # ----------------------------------------------------

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_response_timestamp
            ON response_events(timestamp)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_response_source
            ON response_events(source_ip)
        """)

        conn.commit()

    except sqlite3.Error as e:

        print(
            "[DATABASE] Initialization warning:",
            e
        )

    finally:
        conn.close()


# ============================================================
# HELPERS
# ============================================================

def safe_number(value, default=0):

    try:

        if value is None:
            return default

        return float(value)

    except (TypeError, ValueError):

        return default


def safe_int(value, default=0):

    try:

        if value is None:
            return default

        return int(value)

    except (TypeError, ValueError):

        return default


def format_timestamp(value):

    if not value:
        return "-"

    try:

        text = str(value)

        if "T" in text:
            text = text.replace("T", " ")

        if "." in text:
            text = text.split(".")[0]

        if " " in text:

            parts = text.split(" ")

            if len(parts) >= 2:

                return parts[1][:8]

        return text[-8:]

    except Exception:

        return str(value)


def clean_row(row):

    if row is None:
        return None

    return dict(row)


# ============================================================
# DASHBOARD DATA
# ============================================================

def get_dashboard_data():

    conn = get_db()

    try:

        # ====================================================
        # SUMMARY
        # ====================================================

        summary_row = conn.execute("""
            SELECT
                COUNT(*) AS flow_records,
                COALESCE(SUM(packet_count), 0) AS packets,
                COALESCE(SUM(
                    CASE
                        WHEN ml_anomaly = 1 THEN 1
                        ELSE 0
                    END
                ), 0) AS ml_anomalies,
                COALESCE(SUM(alert_count), 0) AS security_alerts
            FROM flow_records
        """).fetchone()

        response_count_row = conn.execute("""
            SELECT COUNT(*) AS defense_events
            FROM response_events
        """).fetchone()

        summary = {
            "flow_records": safe_int(
                summary_row["flow_records"]
            ),
            "packets": safe_int(
                summary_row["packets"]
            ),
            "ml_anomalies": safe_int(
                summary_row["ml_anomalies"]
            ),
            "security_alerts": safe_int(
                summary_row["security_alerts"]
            ),
            "defense_events": safe_int(
                response_count_row["defense_events"]
            )
        }

        # ====================================================
        # CURRENT RESPONSE STATE
        # ====================================================

        latest_response = conn.execute("""
            SELECT
                timestamp,
                source_ip,
                threat_score,
                threat_state,
                previous_state,
                action,
                mode,
                effectiveness,
                recommendation,
                previous_score,
                current_score,
                improvement_ratio
            FROM response_events
            ORDER BY id DESC
            LIMIT 1
        """).fetchone()

        current = {
            "fused_score": 0,
            "peak_fused_score": 0,
            "threat_state": "NORMAL",
            "action": "MONITOR",
            "mode": "SIMULATION",
            "timestamp": None
        }

        peak_row = conn.execute("""
            SELECT
                MAX(threat_score) AS peak_score
            FROM response_events
        """).fetchone()

        if peak_row and peak_row["peak_score"] is not None:

            current["peak_fused_score"] = round(
                safe_number(
                    peak_row["peak_score"]
                ),
                2
            )

        if latest_response:

            current["fused_score"] = round(
                safe_number(
                    latest_response["threat_score"]
                ),
                2
            )

            current["threat_state"] = (
                latest_response["threat_state"]
                or "NORMAL"
            )

            current["action"] = (
                latest_response["action"]
                or "MONITOR"
            )

            current["mode"] = (
                latest_response["mode"]
                or "SIMULATION"
            )

            current["timestamp"] = (
                latest_response["timestamp"]
            )

        # ====================================================
        # TEMPORAL INTELLIGENCE
        # ====================================================

        temporal_row = conn.execute("""
            SELECT
                source_ip,
                temporal_state,
                temporal_streak,
                temporal_persistence_ratio,
                temporal_confidence,
                temporal_persistent
            FROM flow_records
            WHERE temporal_streak IS NOT NULL
            ORDER BY
                temporal_streak DESC,
                temporal_persistence_ratio DESC,
                id DESC
            LIMIT 1
        """).fetchone()

        temporal = {
            "source_ip": "-",
            "state": "-",
            "streak": 0,
            "persistence_ratio": 0,
            "confidence": "-",
            "persistent": False
        }

        if temporal_row:

            temporal["source_ip"] = (
                temporal_row["source_ip"]
                or "-"
            )

            temporal["state"] = (
                temporal_row["temporal_state"]
                or "NORMAL"
            )

            temporal["streak"] = safe_int(
                temporal_row["temporal_streak"]
            )

            temporal["persistence_ratio"] = (
                safe_number(
                    temporal_row[
                        "temporal_persistence_ratio"
                    ]
                )
            )

            temporal["confidence"] = (
                temporal_row[
                    "temporal_confidence"
                ]
                or "NONE"
            )

            temporal["persistent"] = bool(
                temporal_row[
                    "temporal_persistent"
                ]
            )

        # ====================================================
        # PERSISTENT SOURCE COUNT
        # ====================================================

        persistent_row = conn.execute("""
            SELECT COUNT(*) AS count
            FROM (
                SELECT source_ip
                FROM flow_records
                WHERE temporal_persistent = 1
                GROUP BY source_ip
            )
        """).fetchone()

        summary["persistent_sources"] = safe_int(
            persistent_row["count"]
        )

        # ====================================================
        # FUSED THREAT TIMELINE
        # ONLY RECENT EVENTS
        # ====================================================

        timeline_rows = conn.execute("""
            SELECT
                timestamp,
                threat_score,
                threat_state,
                action,
                source_ip
            FROM response_events
            ORDER BY id DESC
            LIMIT 40
        """).fetchall()

        timeline_rows = list(
            reversed(timeline_rows)
        )

        timeline = []

        for row in timeline_rows:

            timeline.append({
                "time": format_timestamp(
                    row["timestamp"]
                ),
                "score": round(
                    safe_number(
                        row["threat_score"]
                    ),
                    2
                ),
                "state": (
                    row["threat_state"]
                    or "NORMAL"
                ),
                "action": (
                    row["action"]
                    or "MONITOR"
                ),
                "source": (
                    row["source_ip"]
                    or "-"
                )
            })

        # ====================================================
        # PROTOCOL DISTRIBUTION
        # ====================================================

        protocol_rows = conn.execute("""
            SELECT
                protocol,
                COUNT(*) AS count
            FROM flow_records
            GROUP BY protocol
            ORDER BY count DESC
        """).fetchall()

        protocols = {
            "TCP": 0,
            "UDP": 0,
            "OTHER": 0
        }

        for row in protocol_rows:

            protocol = (
                str(row["protocol"])
                .upper()
                if row["protocol"]
                else "OTHER"
            )

            count = safe_int(
                row["count"]
            )

            if protocol == "TCP":

                protocols["TCP"] += count

            elif protocol == "UDP":

                protocols["UDP"] += count

            else:

                protocols["OTHER"] += count

        # ====================================================
        # NETWORK ACTIVITY BY WINDOW
        # ====================================================

        window_rows = conn.execute("""
            SELECT
                window_id,
                COALESCE(SUM(packet_count), 0)
                    AS packets,
                COALESCE(SUM(total_bytes), 0)
                    AS bytes
            FROM flow_records
            WHERE window_id IS NOT NULL
            GROUP BY window_id
            ORDER BY MAX(id) DESC
            LIMIT 20
        """).fetchall()

        window_rows = list(
            reversed(window_rows)
        )

        windows = []

        for row in window_rows:

            windows.append({
                "window": str(
                    row["window_id"]
                ),
                "packets": safe_int(
                    row["packets"]
                ),
                "bytes": safe_int(
                    row["bytes"]
                )
            })

        # ====================================================
        # RECENT SECURITY ACTIVITY
        # ====================================================

        recent_rows = conn.execute("""
            SELECT
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                packet_count,
                threat_score,
                ml_anomaly,
                temporal_state,
                temporal_streak,
                alert_count
            FROM flow_records
            ORDER BY id DESC
            LIMIT 30
        """).fetchall()

        recent = []

        for row in recent_rows:

            recent.append({
                "timestamp": format_timestamp(
                    row["timestamp"]
                ),
                "source_ip": (
                    row["source_ip"]
                    or "-"
                ),
                "destination_ip": (
                    row["destination_ip"]
                    or "-"
                ),
                "protocol": (
                    row["protocol"]
                    or "OTHER"
                ),
                "packets": safe_int(
                    row["packet_count"]
                ),
                "threat_score": round(
                    safe_number(
                        row["threat_score"]
                    ),
                    2
                ),
                "ml_anomaly": bool(
                    row["ml_anomaly"]
                ),
                "temporal_state": (
                    row["temporal_state"]
                    or "NORMAL"
                ),
                "temporal_streak": safe_int(
                    row["temporal_streak"]
                ),
                "alert_count": safe_int(
                    row["alert_count"]
                )
            })

        # ====================================================
        # DEFENSE FEEDBACK HISTORY
        # ====================================================

        feedback_rows = conn.execute("""
            SELECT
                timestamp,
                source_ip,
                threat_score,
                previous_state,
                threat_state,
                action,
                effectiveness,
                recommendation,
                previous_score,
                current_score,
                improvement_ratio
            FROM response_events
            ORDER BY id DESC
            LIMIT 25
        """).fetchall()

        feedback = []

        for row in feedback_rows:

            feedback.append({
                "timestamp": format_timestamp(
                    row["timestamp"]
                ),
                "source_ip": (
                    row["source_ip"]
                    or "-"
                ),
                "threat_score": round(
                    safe_number(
                        row["threat_score"]
                    ),
                    2
                ),
                "previous_state": (
                    row["previous_state"]
                    or "NORMAL"
                ),
                "current_state": (
                    row["threat_state"]
                    or "NORMAL"
                ),
                "action": (
                    row["action"]
                    or "MONITOR"
                ),
                "effectiveness": (
                    row["effectiveness"]
                ),
                "recommendation": (
                    row["recommendation"]
                ),
                "previous_score": (
                    None
                    if row["previous_score"] is None
                    else round(
                        safe_number(
                            row["previous_score"]
                        ),
                        2
                    )
                ),
                "current_score": (
                    None
                    if row["current_score"] is None
                    else round(
                        safe_number(
                            row["current_score"]
                        ),
                        2
                    )
                ),
                "improvement_ratio": (
                    None
                    if row["improvement_ratio"] is None
                    else safe_number(
                        row["improvement_ratio"]
                    )
                )
            })

        # ====================================================
        # PERSISTENT SOURCES
        # ====================================================

        persistent_rows = conn.execute("""
            SELECT
                source_ip,
                MAX(temporal_streak)
                    AS max_streak,
                MAX(temporal_persistence_ratio)
                    AS max_ratio,
                MAX(temporal_confidence)
                    AS confidence
            FROM flow_records
            WHERE temporal_persistent = 1
            GROUP BY source_ip
            ORDER BY max_streak DESC
            LIMIT 10
        """).fetchall()

        persistent_sources = []

        for row in persistent_rows:

            persistent_sources.append({
                "source_ip": (
                    row["source_ip"]
                    or "-"
                ),
                "streak": safe_int(
                    row["max_streak"]
                ),
                "ratio": safe_number(
                    row["max_ratio"]
                ),
                "confidence": (
                    row["confidence"]
                    or "NONE"
                )
            })

        # ====================================================
        # FINAL DATA
        # ====================================================

        return {
            "summary": summary,
            "current": current,
            "temporal": temporal,
            "timeline": timeline,
            "protocols": protocols,
            "windows": windows,
            "recent": recent,
            "feedback": feedback,
            "persistent_sources": persistent_sources
        }

    finally:

        conn.close()


# ============================================================
# HTML
# ============================================================

HTML = r"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>AegisNet Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family:
        Arial,
        Helvetica,
        sans-serif;

    background: #080d1d;

    color: #f3f6ff;
}

.container {

    width: 94%;

    max-width: 1500px;

    margin: auto;

    padding: 28px 0 45px;
}

.header {

    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 28px;
}

.title h1 {

    margin: 0;

    font-size: 31px;
}

.subtitle {

    margin-top: 7px;

    color: #91b9ef;

    font-size: 14px;
}

.live {

    padding: 10px 17px;

    border-radius: 25px;

    background: #10263d;

    color: #56ffb0;

    font-weight: bold;

    font-size: 12px;
}

.live::before {

    content: "● ";

}

.cards {

    display: grid;

    grid-template-columns:
        repeat(6, 1fr);

    gap: 14px;

    margin-bottom: 20px;
}

.card,
.panel {

    background: #11182b;

    border: 1px solid #202d49;

    border-radius: 11px;
}

.card {

    padding: 20px;

    min-height: 110px;
}

.label {

    color: #89a8d7;

    font-size: 11px;

    letter-spacing: 1px;

    margin-bottom: 16px;
}

.value {

    font-size: 25px;

    font-weight: bold;
}

.grid-two {

    display: grid;

    grid-template-columns:
        2fr 1fr;

    gap: 18px;

    margin-bottom: 20px;
}

.panel {

    padding: 20px;

    margin-bottom: 20px;
}

.panel h2 {

    margin: 0 0 20px;

    font-size: 17px;
}

.state-grid {

    display: grid;

    grid-template-columns:
        repeat(2, 1fr);

    gap: 12px;
}

.state-item {

    background: #0c1325;

    padding: 18px;

    border-radius: 8px;
}

.state-item .label {

    margin-bottom: 8px;
}

.state-value {

    font-size: 18px;

    font-weight: bold;
}

.normal {

    color: #4cffb0;
}

.suspicious {

    color: #ffd84d;
}

.high {

    color: #ff9d3d;
}

.critical {

    color: #ff5f6d;
}

.chart-grid {

    display: grid;

    grid-template-columns:
        2fr 1fr;

    gap: 18px;
}

.chart-box {

    height: 370px;
}

.chart-box canvas {

    width: 100% !important;

    height: 310px !important;
}

.loop {

    display: flex;

    justify-content: center;

    align-items: center;

    gap: 12px;

    flex-wrap: wrap;
}

.step {

    min-width: 155px;

    text-align: center;

    padding: 17px 13px;

    border: 1px solid #294266;

    border-radius: 8px;

    background: #0d1528;
}

.step strong {

    display: block;

    font-size: 12px;

    margin-bottom: 8px;
}

.step span {

    color: #91a9d3;

    font-size: 12px;
}

.arrow {

    color: #72b4ff;

    font-size: 22px;
}

.description {

    text-align: center;

    color: #7192c0;

    margin-top: 17px;

    font-size: 12px;
}

.table-wrap {

    overflow-x: auto;

    max-height: 520px;

    overflow-y: auto;
}

table {

    width: 100%;

    border-collapse: collapse;

    font-size: 12px;
}

th {

    color: #87a8d8;

    font-size: 10px;

    letter-spacing: .7px;

    text-align: left;

    padding: 12px 9px;

    border-bottom: 1px solid #26334f;

    white-space: nowrap;
}

td {

    padding: 11px 9px;

    border-bottom: 1px solid #1d2942;

    white-space: nowrap;
}

.badge {

    display: inline-block;

    padding: 5px 8px;

    border-radius: 5px;

    font-size: 9px;

    font-weight: bold;
}

.badge-anomaly {

    background: #45202b;

    color: #ff6676;
}

.badge-normal {

    background: #102c27;

    color: #51e9aa;
}

.badge-strong {

    background: #182c4b;

    color: #79b8ff;
}

.badge-weak {

    background: #1d293e;

    color: #9db2d2;
}

.badge-action {

    background: #403717;

    color: #ffd947;
}

.persistent-list {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 14px;
}

.source-card {

    background: #0c1325;

    border: 1px solid #24324d;

    border-radius: 8px;

    padding: 16px;
}

.source-ip {

    font-weight: bold;

    margin-bottom: 12px;
}

.source-meta {

    color: #91a9cf;

    font-size: 12px;

    line-height: 1.8;
}

.empty {

    padding: 28px;

    text-align: center;

    color: #718bb4;
}

.footer {

    text-align: center;

    color: #55719e;

    font-size: 12px;

    margin-top: 25px;
}

.error {

    background: #351821;

    border: 1px solid #713340;

    color: #ff8692;

    padding: 12px;

    border-radius: 7px;

    margin-bottom: 15px;

    display: none;
}

@media(max-width: 1100px) {

    .cards {

        grid-template-columns:
            repeat(3, 1fr);
    }

    .grid-two,
    .chart-grid {

        grid-template-columns: 1fr;
    }
}

@media(max-width: 700px) {

    .cards {

        grid-template-columns:
            repeat(2, 1fr);
    }

    .state-grid {

        grid-template-columns: 1fr;
    }

    .persistent-list {

        grid-template-columns: 1fr;
    }

    .header {

        align-items: flex-start;

        gap: 15px;

        flex-direction: column;
    }
}

</style>

</head>


<body>

<div class="container">

<div class="header">

<div class="title">

<h1>AegisNet Security Dashboard</h1>

<div class="subtitle">
Context-Aware Reversible Network Defense &amp; Intrusion Detection System
</div>

</div>

<div class="live">
LIVE MONITORING
</div>

</div>


<div id="error" class="error"></div>


<!-- =====================================================
     SUMMARY
====================================================== -->

<div class="cards">

<div class="card">
<div class="label">FLOW RECORDS</div>
<div class="value" id="flowRecords">-</div>
</div>

<div class="card">
<div class="label">PACKETS</div>
<div class="value" id="packets">-</div>
</div>

<div class="card">
<div class="label">ML ANOMALIES</div>
<div class="value" id="mlAnomalies">-</div>
</div>

<div class="card">
<div class="label">SECURITY ALERTS</div>
<div class="value" id="securityAlerts">-</div>
</div>

<div class="card">
<div class="label">DEFENSE EVENTS</div>
<div class="value" id="defenseEvents">-</div>
</div>

<div class="card">
<div class="label">PERSISTENT SOURCES</div>
<div class="value" id="persistentSources">-</div>
</div>

</div>


<!-- =====================================================
     CURRENT STATE + TEMPORAL
====================================================== -->

<div class="grid-two">

<div class="panel">

<h2>Current Defense State</h2>

<div class="state-grid">

<div class="state-item">

<div class="label">
CURRENT FUSED SCORE
</div>

<div
    class="state-value"
    id="currentScore"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
PEAK FUSED SCORE
</div>

<div
    class="state-value"
    id="peakScore"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
THREAT STATE
</div>

<div
    class="state-value"
    id="threatState"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
CURRENT ACTION
</div>

<div
    class="state-value"
    id="currentAction"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
DEFENSE MODE
</div>

<div
    class="state-value"
    id="defenseMode"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
LAST UPDATE
</div>

<div
    class="state-value"
    id="lastUpdate"
>
-
</div>

</div>

</div>

</div>


<div class="panel">

<h2>Temporal Intelligence</h2>

<div class="state-grid">

<div class="state-item">

<div class="label">
TOP SOURCE
</div>

<div
    class="state-value"
    id="temporalSource"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
TEMPORAL STATE
</div>

<div
    class="state-value"
    id="temporalState"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
PERSISTENCE STREAK
</div>

<div
    class="state-value"
    id="temporalStreak"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
PERSISTENCE RATIO
</div>

<div
    class="state-value"
    id="temporalRatio"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
TEMPORAL CONFIDENCE
</div>

<div
    class="state-value"
    id="temporalConfidence"
>
-
</div>

</div>


<div class="state-item">

<div class="label">
PERSISTENT
</div>

<div
    class="state-value"
    id="temporalPersistent"
>
-
</div>

</div>

</div>

<div class="description">
Temporal persistence represents sustained anomalous behavior across multiple windows; the current defense state reflects the latest fused threat score.
</div>

</div>

</div>


<!-- =====================================================
     CHARTS
====================================================== -->

<div class="chart-grid">

<div class="panel chart-box">

<h2>Fused Threat Timeline</h2>

<canvas id="threatChart"></canvas>

</div>


<div class="panel chart-box">

<h2>Protocol Distribution</h2>

<canvas id="protocolChart"></canvas>

</div>

</div>


<div class="panel chart-box">

<h2>Network Activity by Window</h2>

<canvas id="networkChart"></canvas>

</div>


<!-- =====================================================
     FEEDBACK CONTROL LOOP
====================================================== -->

<div class="panel">

<h2>Defense Feedback Control Loop</h2>

<div class="loop">

<div class="step">

<strong>THREAT DETECTED</strong>

<span>Threat Fusion</span>

</div>

<div class="arrow">→</div>

<div class="step">

<strong>TEMPORARY DEFENSE</strong>

<span>Limit / Block</span>

</div>

<div class="arrow">→</div>

<div class="step">

<strong>MEASURE EFFECT</strong>

<span>Response Monitor</span>

</div>

<div class="arrow">→</div>

<div class="step">

<strong>DECIDE</strong>

<span>Effective / Partial / Failed</span>

</div>

<div class="arrow">→</div>

<div class="step">

<strong>RESTORE / ESCALATE</strong>

<span>Reversible Controller</span>

</div>

</div>

<div class="description">

AegisNet evaluates the effect of a temporary defensive intervention before deciding whether to maintain, restore, or escalate the response.

</div>

</div>


<!-- =====================================================
     PERSISTENT SOURCES
====================================================== -->

<div class="panel">

<h2>Persistent Threat Sources</h2>

<div
    id="persistentContainer"
    class="persistent-list"
>
</div>

</div>


<!-- =====================================================
     RECENT SECURITY ACTIVITY
====================================================== -->

<div class="panel">

<h2>Recent Security Activity</h2>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>TIME</th>
<th>SOURCE</th>
<th>DESTINATION</th>
<th>PROTOCOL</th>
<th>PACKETS</th>
<th>FLOW THREAT</th>
<th>ML</th>
<th>TEMPORAL</th>
<th>STREAK</th>
<th>ALERTS</th>

</tr>

</thead>

<tbody id="recentBody">

</tbody>

</table>

</div>

</div>


<!-- =====================================================
     RESPONSE HISTORY
====================================================== -->

<div class="panel">

<h2>Defense Feedback &amp; Response History</h2>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>TIME</th>
<th>SOURCE</th>
<th>FUSED SCORE</th>
<th>PREVIOUS STATE</th>
<th>CURRENT STATE</th>
<th>ACTION</th>
<th>EFFECTIVENESS</th>
<th>RECOMMENDATION</th>
<th>PREVIOUS SCORE</th>
<th>CURRENT SCORE</th>
<th>IMPROVEMENT</th>

</tr>

</thead>

<tbody id="feedbackBody">

</tbody>

</table>

</div>

</div>


<div class="footer">

AegisNet • Real-Time Network Traffic Intelligence • Defense Mode: Simulation

</div>

</div>


<script>

let threatChart = null;
let protocolChart = null;
let networkChart = null;


function number(value) {

    if (value === null || value === undefined) {
        return 0;
    }

    return Number(value) || 0;
}


function setText(id, value) {

    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


function stateClass(state) {

    if (!state) {
        return "";
    }

    const s = state.toUpperCase();

    if (s === "NORMAL") {
        return "normal";
    }

    if (
        s === "SUSPICIOUS" ||
        s === "LOW"
    ) {
        return "suspicious";
    }

    if (
        s === "HIGH" ||
        s === "HIGH_RISK"
    ) {
        return "high";
    }

    if (
        s === "CRITICAL"
    ) {
        return "critical";
    }

    return "";
}


function showError(message) {

    const box =
        document.getElementById("error");

    box.textContent =
        "Dashboard data error: " + message;

    box.style.display = "block";
}


function hideError() {

    const box =
        document.getElementById("error");

    box.style.display = "none";
}


function renderCharts(data) {

    // ----------------------------------------------------
    // THREAT TIMELINE
    // ----------------------------------------------------

    const timeline =
        data.timeline || [];

    const labels =
        timeline.map(
            item => item.time
        );

    const scores =
        timeline.map(
            item => number(item.score)
        );


    if (threatChart) {
        threatChart.destroy();
    }


    threatChart =
        new Chart(
            document.getElementById(
                "threatChart"
            ),
            {
                type: "line",

                data: {

                    labels: labels,

                    datasets: [{
                        label:
                            "Fused Threat Score",

                        data: scores,

                        tension: 0.25,

                        fill: false,

                        pointRadius: 3
                    }]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    scales: {

                        y: {

                            beginAtZero: true,

                            max: 100

                        }

                    }

                }
            }
        );


    // ----------------------------------------------------
    // PROTOCOL
    // ----------------------------------------------------

    const protocols =
        data.protocols || {};


    if (protocolChart) {
        protocolChart.destroy();
    }


    protocolChart =
        new Chart(
            document.getElementById(
                "protocolChart"
            ),
            {
                type: "doughnut",

                data: {

                    labels: [
                        "OTHER",
                        "TCP",
                        "UDP"
                    ],

                    datasets: [{

                        data: [
                            number(
                                protocols.OTHER
                            ),
                            number(
                                protocols.TCP
                            ),
                            number(
                                protocols.UDP
                            )
                        ]
                    }]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false

                }
            }
        );


    // ----------------------------------------------------
    // NETWORK ACTIVITY
    // ----------------------------------------------------

    const windows =
        data.windows || [];


    const windowLabels =
        windows.map(
            item => "W" + item.window
        );

    const packets =
        windows.map(
            item => number(
                item.packets
            )
        );

    const bytes =
        windows.map(
            item => number(
                item.bytes
            )
        );


    if (networkChart) {
        networkChart.destroy();
    }


    networkChart =
        new Chart(
            document.getElementById(
                "networkChart"
            ),
            {
                type: "bar",

                data: {

                    labels: windowLabels,

                    datasets: [

                        {
                            label: "Packets",

                            data: packets
                        },

                        {
                            label: "Bytes",

                            data: bytes
                        }

                    ]
                },

                options: {

                    responsive: true,

                    maintainAspectRatio: false,

                    scales: {

                        y: {

                            beginAtZero: true

                        }

                    }

                }
            }
        );
}


function renderPersistentSources(
    sources
) {

    const container =
        document.getElementById(
            "persistentContainer"
        );


    container.innerHTML = "";


    if (
        !sources ||
        sources.length === 0
    ) {

        container.innerHTML =
            '<div class="empty">' +
            'No currently persistent sources detected.' +
            '</div>';

        return;
    }


    sources.forEach(
        source => {

            const card =
                document.createElement(
                    "div"
                );

            card.className =
                "source-card";


            card.innerHTML = `

                <div class="source-ip">
                    ${source.source_ip}
                </div>

                <div class="source-meta">

                    Persistence streak:
                    <strong>
                        ${number(source.streak)}
                    </strong>

                    <br>

                    Persistence ratio:
                    <strong>
                        ${(number(source.ratio) * 100).toFixed(1)}%
                    </strong>

                    <br>

                    Confidence:
                    <strong>
                        ${source.confidence || "NONE"}
                    </strong>

                </div>
            `;


            container.appendChild(card);

        }
    );
}


function renderRecent(rows) {

    const body =
        document.getElementById(
            "recentBody"
        );


    body.innerHTML = "";


    if (
        !rows ||
        rows.length === 0
    ) {

        body.innerHTML =
            '<tr><td colspan="10" class="empty">' +
            'Waiting for flow records...' +
            '</td></tr>';

        return;
    }


    rows.forEach(
        row => {

            const tr =
                document.createElement(
                    "tr"
                );


            const ml =
                row.ml_anomaly
                    ? '<span class="badge badge-anomaly">ANOMALY</span>'
                    : '<span class="badge badge-normal">NORMAL</span>';


            const temporal =
                row.temporal_state === "NORMAL"
                    ? '<span class="badge badge-normal">NORMAL</span>'
                    : (
                        row.temporal_state === "WEAK"
                            ? '<span class="badge badge-weak">WEAK</span>'
                            : '<span class="badge badge-strong">' +
                              (row.temporal_state || "NORMAL") +
                              '</span>'
                    );


            tr.innerHTML = `

                <td>${row.timestamp || "-"}</td>

                <td>${row.source_ip || "-"}</td>

                <td>${row.destination_ip || "-"}</td>

                <td>${row.protocol || "-"}</td>

                <td>${number(row.packets).toLocaleString()}</td>

                <td>${number(row.threat_score).toFixed(2)}</td>

                <td>${ml}</td>

                <td>${temporal}</td>

                <td>${number(row.temporal_streak)}</td>

                <td>${number(row.alert_count)}</td>

            `;


            body.appendChild(tr);

        }
    );
}


function renderFeedback(rows) {

    const body =
        document.getElementById(
            "feedbackBody"
        );


    body.innerHTML = "";


    if (
        !rows ||
        rows.length === 0
    ) {

        body.innerHTML =
            '<tr><td colspan="11" class="empty">' +
            'Waiting for response events...' +
            '</td></tr>';

        return;
    }


    rows.forEach(
        row => {

            const tr =
                document.createElement(
                    "tr"
                );


            const effectiveness =
                row.effectiveness
                    ? row.effectiveness
                    : "-";


            const recommendation =
                row.recommendation
                    ? row.recommendation
                    : "-";


            let improvement = "-";


            if (
                row.improvement_ratio !== null &&
                row.improvement_ratio !== undefined
            ) {

                improvement =
                    (
                        number(
                            row.improvement_ratio
                        ) * 100
                    ).toFixed(2) + "%";
            }


            tr.innerHTML = `

                <td>${row.timestamp || "-"}</td>

                <td>${row.source_ip || "-"}</td>

                <td>${number(row.threat_score).toFixed(2)}</td>

                <td>${row.previous_state || "-"}</td>

                <td>${row.current_state || "-"}</td>

                <td>
                    <span class="badge badge-action">
                        ${row.action || "MONITOR"}
                    </span>
                </td>

                <td>${effectiveness}</td>

                <td>${recommendation}</td>

                <td>
                    ${
                        row.previous_score === null ||
                        row.previous_score === undefined
                            ? "-"
                            : number(
                                row.previous_score
                              ).toFixed(2)
                    }
                </td>

                <td>
                    ${
                        row.current_score === null ||
                        row.current_score === undefined
                            ? "-"
                            : number(
                                row.current_score
                              ).toFixed(2)
                    }
                </td>

                <td>${improvement}</td>

            `;


            body.appendChild(tr);

        }
    );
}


function updateDashboard(data) {

    hideError();


    // ----------------------------------------------------
    // SUMMARY
    // ----------------------------------------------------

    const summary =
        data.summary || {};


    setText(
        "flowRecords",
        number(
            summary.flow_records
        ).toLocaleString()
    );


    setText(
        "packets",
        number(
            summary.packets
        ).toLocaleString()
    );


    setText(
        "mlAnomalies",
        number(
            summary.ml_anomalies
        ).toLocaleString()
    );


    setText(
        "securityAlerts",
        number(
            summary.security_alerts
        ).toLocaleString()
    );


    setText(
        "defenseEvents",
        number(
            summary.defense_events
        ).toLocaleString()
    );


    setText(
        "persistentSources",
        number(
            summary.persistent_sources
        ).toLocaleString()
    );


    // ----------------------------------------------------
    // CURRENT STATE
    // ----------------------------------------------------

    const current =
        data.current || {};


    setText(
        "currentScore",
        number(
            current.fused_score
        ).toFixed(2)
    );


    setText(
        "peakScore",
        number(
            current.peak_fused_score
        ).toFixed(2)
    );


    const threatState =
        document.getElementById(
            "threatState"
        );


    threatState.textContent =
        current.threat_state ||
        "NORMAL";


    threatState.className =
        "state-value " +
        stateClass(
            current.threat_state
        );


    setText(
        "currentAction",
        current.action ||
        "MONITOR"
    );


    setText(
        "defenseMode",
        current.mode ||
        "SIMULATION"
    );


    setText(
        "lastUpdate",
        current.timestamp
            ? current.timestamp
            : "-"
    );


    if (
        current.timestamp
    ) {

        const text =
            String(
                current.timestamp
            ).replace(
                "T",
                " "
            );


        const parts =
            text.split(" ");


        if (
            parts.length >= 2
        ) {

            setText(
                "lastUpdate",
                parts[1].substring(
                    0,
                    8
                )
            );
        }
    }


    // ----------------------------------------------------
    // TEMPORAL
    // ----------------------------------------------------

    const temporal =
        data.temporal || {};


    setText(
        "temporalSource",
        temporal.source_ip || "-"
    );


    setText(
        "temporalState",
        temporal.state || "-"
    );


    setText(
        "temporalStreak",
        number(
            temporal.streak
        )
    );


    setText(
        "temporalRatio",
        (
            number(
                temporal.persistence_ratio
            ) * 100
        ).toFixed(1) + "%"
    );


    setText(
        "temporalConfidence",
        temporal.confidence || "-"
    );


    setText(
        "temporalPersistent",
        temporal.persistent
            ? "YES"
            : "NO"
    );


    // ----------------------------------------------------
    // OTHER SECTIONS
    // ----------------------------------------------------

    renderCharts(data);

    renderPersistentSources(
        data.persistent_sources || []
    );

    renderRecent(
        data.recent || []
    );

    renderFeedback(
        data.feedback || []
    );
}


async function loadDashboard() {

    try {

        const response =
            await fetch(
                "/api/dashboard?ts=" +
                Date.now(),
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            const text =
                await response.text();

            throw new Error(
                "HTTP " +
                response.status +
                ": " +
                text.substring(
                    0,
                    200
                )
            );
        }


        const data =
            await response.json();


        if (
            !data ||
            !data.success
        ) {

            throw new Error(
                data && data.error
                    ? data.error
                    : "Invalid dashboard response"
            );
        }


        updateDashboard(
            data.data
        );

    }

    catch (error) {

        console.error(
            "Dashboard error:",
            error
        );

        showError(
            error.message
        );

    }
}


// Initial load

loadDashboard();


// Refresh every 5 seconds

setInterval(
    loadDashboard,
    5000
);

</script>

</body>

</html>
"""


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def dashboard():

    return render_template_string(
        HTML
    )


@app.route("/api/dashboard")
def dashboard_api():

    try:

        data = get_dashboard_data()

        return jsonify({
            "success": True,
            "data": data
        })

    except sqlite3.OperationalError as e:

        print(
            "[API ERROR]",
            e
        )

        return jsonify({
            "success": False,
            "error":
                "SQLite is busy. "
                "The dashboard will retry automatically.",
            "details": str(e)
        }), 503

    except Exception as e:

        print(
            "[API ERROR]",
            repr(e)
        )

        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print("=" * 70)

    print(
        "             AEGISNET DASHBOARD"
    )

    print("=" * 70)

    print(
        f"Dashboard: http://127.0.0.1:5000"
    )

    print(
        f"Database: {DATABASE_PATH}"
    )

    print(
        "Auto-refresh: 5 seconds"
    )

    print(
        "SQLite mode: WAL"
    )

    print("=" * 70)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True
    )
import sqlite3
import os
import statistics
from datetime import datetime

DATABASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "aegisnet.db")
)


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def safe_mean(values):
    return statistics.mean(values) if values else 0.0


def safe_percentage(part, total):
    return (part / total * 100) if total else 0.0


def evaluate_database():
    connection = get_connection()

    flow_count = 0
    packet_count = 0
    byte_count = 0

    ml_anomalies = 0
    security_alerts = 0

    temporal_persistent = 0
    temporal_very_strong = 0

    threat_scores = []
    response_scores = []
    improvement_values = []

    response_count = 0
    ineffective_count = 0
    effective_count = 0
    escalations = 0
    restores = 0

    response_states = {}
    response_actions = {}
    temporal_states = {}

    try:
        flow_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(flow_records)"
            ).fetchall()
        }

        response_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(response_events)"
            ).fetchall()
        }

        flow_count = connection.execute(
            "SELECT COUNT(*) FROM flow_records"
        ).fetchone()[0]

        if "packet_count" in flow_columns:
            packet_count = connection.execute(
                "SELECT COALESCE(SUM(packet_count), 0) FROM flow_records"
            ).fetchone()[0]

        if "total_bytes" in flow_columns:
            byte_count = connection.execute(
                "SELECT COALESCE(SUM(total_bytes), 0) FROM flow_records"
            ).fetchone()[0]

        if "ml_anomaly" in flow_columns:
            ml_anomalies = connection.execute(
                """
                SELECT COUNT(*)
                FROM flow_records
                WHERE ml_anomaly = 1
                """
            ).fetchone()[0]

        if "rule_alerts" in flow_columns:
            security_alerts = connection.execute(
                """
                SELECT COUNT(*)
                FROM flow_records
                WHERE rule_alerts IS NOT NULL
                AND rule_alerts != ''
                AND rule_alerts != '[]'
                """
            ).fetchone()[0]

        if "threat_score" in flow_columns:
            rows = connection.execute(
                """
                SELECT threat_score
                FROM flow_records
                WHERE threat_score IS NOT NULL
                """
            ).fetchall()

            threat_scores = [
                float(row["threat_score"])
                for row in rows
                if row["threat_score"] is not None
            ]

        if "temporal_persistent" in flow_columns:
            temporal_persistent = connection.execute(
                """
                SELECT COUNT(*)
                FROM flow_records
                WHERE temporal_persistent = 1
                """
            ).fetchone()[0]

        if "very_strong_persistent" in flow_columns:
            temporal_very_strong = connection.execute(
                """
                SELECT COUNT(*)
                FROM flow_records
                WHERE very_strong_persistent = 1
                """
            ).fetchone()[0]

        if "temporal_state" in flow_columns:
            rows = connection.execute(
                """
                SELECT temporal_state, COUNT(*) AS count
                FROM flow_records
                WHERE temporal_state IS NOT NULL
                GROUP BY temporal_state
                """
            ).fetchall()

            temporal_states = {
                row["temporal_state"]: row["count"]
                for row in rows
            }

        if response_columns:
            response_count = connection.execute(
                "SELECT COUNT(*) FROM response_events"
            ).fetchone()[0]

            if "threat_score" in response_columns:
                rows = connection.execute(
                    """
                    SELECT threat_score
                    FROM response_events
                    WHERE threat_score IS NOT NULL
                    """
                ).fetchall()

                response_scores = [
                    float(row["threat_score"])
                    for row in rows
                    if row["threat_score"] is not None
                ]

            if "effectiveness" in response_columns:
                rows = connection.execute(
                    """
                    SELECT effectiveness, COUNT(*) AS count
                    FROM response_events
                    WHERE effectiveness IS NOT NULL
                    GROUP BY effectiveness
                    """
                ).fetchall()

                for row in rows:
                    value = row["effectiveness"]

                    if value == "EFFECTIVE":
                        effective_count = row["count"]

                    elif value == "INEFFECTIVE":
                        ineffective_count = row["count"]

            if "recommendation" in response_columns:
                escalations = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM response_events
                    WHERE recommendation = 'ESCALATE'
                    """
                ).fetchone()[0]

                restores = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM response_events
                    WHERE recommendation = 'RESTORE'
                    """
                ).fetchone()[0]

            if "threat_state" in response_columns:
                rows = connection.execute(
                    """
                    SELECT threat_state, COUNT(*) AS count
                    FROM response_events
                    GROUP BY threat_state
                    """
                ).fetchall()

                response_states = {
                    row["threat_state"]: row["count"]
                    for row in rows
                }

            if "action" in response_columns:
                rows = connection.execute(
                    """
                    SELECT action, COUNT(*) AS count
                    FROM response_events
                    GROUP BY action
                    """
                ).fetchall()

                response_actions = {
                    row["action"]: row["count"]
                    for row in rows
                }

            if "improvement_ratio" in response_columns:
                rows = connection.execute(
                    """
                    SELECT improvement_ratio
                    FROM response_events
                    WHERE improvement_ratio IS NOT NULL
                    """
                ).fetchall()

                improvement_values = [
                    float(row["improvement_ratio"]) * 100
                    for row in rows
                    if row["improvement_ratio"] is not None
                ]

    finally:
        connection.close()

    print("=" * 72)
    print("                 AEGISNET SYSTEM EVALUATION")
    print("=" * 72)

    print("\n[1] DATASET / TRAFFIC COVERAGE")
    print("-" * 72)
    print(f"Flow records              : {flow_count:,}")
    print(f"Total packets             : {packet_count:,}")
    print(f"Total bytes               : {byte_count:,}")

    print("\n[2] DETECTION RESULTS")
    print("-" * 72)
    print(f"ML anomalies              : {ml_anomalies:,}")
    print(f"ML anomaly rate           : "
          f"{safe_percentage(ml_anomalies, flow_count):.2f}%")
    print(f"Security alerts           : {security_alerts:,}")
    print(f"Alert rate                : "
          f"{safe_percentage(security_alerts, flow_count):.2f}%")

    print("\n[3] THREAT SCORE ANALYSIS")
    print("-" * 72)

    if threat_scores:
        print(f"Average flow threat score : {safe_mean(threat_scores):.2f}")
        print(f"Maximum flow threat score : {max(threat_scores):.2f}")
        print(f"Minimum flow threat score : {min(threat_scores):.2f}")
    else:
        print("No flow threat scores available.")

    if response_scores:
        print(f"Average fused score       : "
              f"{safe_mean(response_scores):.2f}")
        print(f"Maximum fused score       : "
              f"{max(response_scores):.2f}")
    else:
        print("No response-event scores available.")

    print("\n[4] TEMPORAL INTELLIGENCE")
    print("-" * 72)
    print(f"Persistent records        : {temporal_persistent:,}")
    print(f"Very-strong persistent    : {temporal_very_strong:,}")

    if temporal_states:
        for state, count in sorted(
            temporal_states.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"{state:<25}: {count:,}")
    else:
        print("No temporal state data available.")

    print("\n[5] DEFENSE RESPONSE")
    print("-" * 72)
    print(f"Total response events     : {response_count:,}")
    print(f"Effective responses       : {effective_count:,}")
    print(f"Ineffective responses     : {ineffective_count:,}")
    print(f"Escalation recommendations: {escalations:,}")
    print(f"Restore recommendations   : {restores:,}")

    if effective_count + ineffective_count:
        evaluated = effective_count + ineffective_count
        effectiveness_rate = safe_percentage(
            effective_count,
            evaluated
        )

        print(f"Response effectiveness    : "
              f"{effectiveness_rate:.2f}%")

    print("\n[6] RESPONSE STATE DISTRIBUTION")
    print("-" * 72)

    if response_states:
        for state, count in sorted(
            response_states.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"{str(state):<25}: {count:,}")
    else:
        print("No response state data available.")

    print("\n[7] RESPONSE ACTION DISTRIBUTION")
    print("-" * 72)

    if response_actions:
        for action, count in sorted(
            response_actions.items(),
            key=lambda item: item[1],
            reverse=True
        ):
            print(f"{str(action):<25}: {count:,}")
    else:
        print("No response action data available.")

    print("\n[8] DEFENSE FEEDBACK EFFECT")
    print("-" * 72)

    if improvement_values:
        positive = [
            value for value in improvement_values
            if value > 0
        ]

        print(f"Evaluated interventions   : "
              f"{len(improvement_values):,}")
        print(f"Average improvement       : "
              f"{safe_mean(improvement_values):.2f}%")
        print(f"Positive improvements     : "
              f"{len(positive):,}")
        print(f"Improvement success rate  : "
              f"{safe_percentage(len(positive), len(improvement_values)):.2f}%")
        print(f"Best improvement          : "
              f"{max(improvement_values):.2f}%")
        print(f"Worst improvement         : "
              f"{min(improvement_values):.2f}%")
    else:
        print("No feedback-effect measurements available.")

    print("\n" + "=" * 72)
    print("Evaluation completed.")
    print("=" * 72)


if __name__ == "__main__":
    evaluate_database()
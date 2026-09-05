import sqlite3
import os
import pandas as pd
import matplotlib.pyplot as plt


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

DATABASE_PATH = os.path.join(
    BASE_DIR,
    "data",
    "aegisnet.db"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "data",
    "evaluation"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_connection():
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA busy_timeout=30000"
    )

    return connection


def save_dataframe(df, filename):
    path = os.path.join(
        OUTPUT_DIR,
        filename
    )

    df.to_csv(
        path,
        index=False
    )

    print(f"Created: {path}")


def generate_ml_anomaly_graph(connection):

    query = """
        SELECT
            ml_anomaly,
            COUNT(*) AS count
        FROM flow_records
        GROUP BY ml_anomaly
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    labels = []
    values = []

    for _, row in df.iterrows():

        value = row["ml_anomaly"]

        if pd.isna(value):
            continue

        try:
            value = int(value)
        except (ValueError, TypeError):
            continue

        if value == 1:
            labels.append("Anomalous")
        else:
            labels.append("Normal")

        values.append(
            int(row["count"])
        )

    if labels:

        plt.figure(
            figsize=(8, 5)
        )

        plt.bar(
            labels,
            values
        )

        plt.title(
            "ML Anomaly Detection Distribution"
        )

        plt.xlabel(
            "Classification"
        )

        plt.ylabel(
            "Number of Flow Records"
        )

        plt.tight_layout()

        path = os.path.join(
            OUTPUT_DIR,
            "ml_anomaly_distribution.png"
        )

        plt.savefig(
            path,
            dpi=200
        )

        plt.close()

        print(f"Created: {path}")

    else:
        print(
            "No valid ML anomaly data available."
        )

    save_dataframe(
        df,
        "ml_anomaly_distribution.csv"
    )


def generate_threat_score_graph(connection):

    query = """
        SELECT
            threat_score
        FROM flow_records
        WHERE threat_score IS NOT NULL
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    if df.empty:

        print(
            "No flow threat-score data available."
        )

        save_dataframe(
            df,
            "threat_scores.csv"
        )

        return

    df["threat_score"] = pd.to_numeric(
        df["threat_score"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["threat_score"]
    )

    if df.empty:

        print(
            "No valid flow threat-score data available."
        )

        save_dataframe(
            df,
            "threat_scores.csv"
        )

        return

    plt.figure(
        figsize=(9, 5)
    )

    plt.hist(
        df["threat_score"],
        bins=20
    )

    plt.title(
        "Flow Threat Score Distribution"
    )

    plt.xlabel(
        "Threat Score"
    )

    plt.ylabel(
        "Number of Flow Records"
    )

    plt.tight_layout()

    path = os.path.join(
        OUTPUT_DIR,
        "threat_score_distribution.png"
    )

    plt.savefig(
        path,
        dpi=200
    )

    plt.close()

    print(f"Created: {path}")

    save_dataframe(
        df,
        "threat_scores.csv"
    )


def generate_temporal_graph(connection):

    query = """
        SELECT
            temporal_state,
            COUNT(*) AS count
        FROM flow_records
        WHERE temporal_state IS NOT NULL
        GROUP BY temporal_state
        ORDER BY count DESC
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    if df.empty:

        print(
            "No temporal-state data available."
        )

        save_dataframe(
            df,
            "temporal_state_distribution.csv"
        )

        return

    plt.figure(
        figsize=(9, 5)
    )

    plt.bar(
        df["temporal_state"],
        df["count"]
    )

    plt.title(
        "Temporal Threat State Distribution"
    )

    plt.xlabel(
        "Temporal State"
    )

    plt.ylabel(
        "Number of Flow Records"
    )

    plt.xticks(
        rotation=20
    )

    plt.tight_layout()

    path = os.path.join(
        OUTPUT_DIR,
        "temporal_state_distribution.png"
    )

    plt.savefig(
        path,
        dpi=200
    )

    plt.close()

    print(f"Created: {path}")

    save_dataframe(
        df,
        "temporal_state_distribution.csv"
    )


def generate_response_state_graph(connection):

    query = """
        SELECT
            threat_state,
            COUNT(*) AS count
        FROM response_events
        WHERE threat_state IS NOT NULL
        GROUP BY threat_state
        ORDER BY count DESC
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    if df.empty:

        print(
            "No response-state data available."
        )

        save_dataframe(
            df,
            "defense_state_distribution.csv"
        )

        return

    plt.figure(
        figsize=(9, 5)
    )

    plt.bar(
        df["threat_state"],
        df["count"]
    )

    plt.title(
        "Defense Threat-State Distribution"
    )

    plt.xlabel(
        "Threat State"
    )

    plt.ylabel(
        "Number of Response Events"
    )

    plt.xticks(
        rotation=20
    )

    plt.tight_layout()

    path = os.path.join(
        OUTPUT_DIR,
        "defense_state_distribution.png"
    )

    plt.savefig(
        path,
        dpi=200
    )

    plt.close()

    print(f"Created: {path}")

    save_dataframe(
        df,
        "defense_state_distribution.csv"
    )


def generate_response_action_graph(connection):

    query = """
        SELECT
            COALESCE(
                action,
                'NO_ACTION_RECORDED'
            ) AS action,
            COUNT(*) AS count
        FROM response_events
        GROUP BY action
        ORDER BY count DESC
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    if df.empty:

        print(
            "No response-action data available."
        )

        save_dataframe(
            df,
            "response_action_distribution.csv"
        )

        return

    plt.figure(
        figsize=(10, 5)
    )

    plt.bar(
        df["action"],
        df["count"]
    )

    plt.title(
        "Defense Response Action Distribution"
    )

    plt.xlabel(
        "Response Action"
    )

    plt.ylabel(
        "Number of Events"
    )

    plt.xticks(
        rotation=25
    )

    plt.tight_layout()

    path = os.path.join(
        OUTPUT_DIR,
        "response_action_distribution.png"
    )

    plt.savefig(
        path,
        dpi=200
    )

    plt.close()

    print(f"Created: {path}")

    save_dataframe(
        df,
        "response_action_distribution.csv"
    )


def generate_feedback_graph(connection):

    query = """
        SELECT
            improvement_ratio
        FROM response_events
        WHERE improvement_ratio IS NOT NULL
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    if df.empty:

        print(
            "No defense-feedback data available."
        )

        save_dataframe(
            df,
            "defense_feedback_improvement.csv"
        )

        return

    df["improvement_ratio"] = pd.to_numeric(
        df["improvement_ratio"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["improvement_ratio"]
    )

    if df.empty:

        print(
            "No valid defense-feedback data available."
        )

        save_dataframe(
            df,
            "defense_feedback_improvement.csv"
        )

        return

    df["improvement_percent"] = (
        df["improvement_ratio"] * 100
    )

    plt.figure(
        figsize=(10, 5)
    )

    plt.hist(
        df["improvement_percent"],
        bins=15
    )

    plt.axvline(
        0,
        linestyle="--"
    )

    plt.title(
        "Defense Feedback Improvement Distribution"
    )

    plt.xlabel(
        "Threat Score Improvement (%)"
    )

    plt.ylabel(
        "Number of Interventions"
    )

    plt.tight_layout()

    path = os.path.join(
        OUTPUT_DIR,
        "defense_feedback_improvement.png"
    )

    plt.savefig(
        path,
        dpi=200
    )

    plt.close()

    print(f"Created: {path}")

    save_dataframe(
        df,
        "defense_feedback_improvement.csv"
    )


def generate_fused_score_graph(connection):

    query = """
        SELECT
            id,
            timestamp,
            source_ip,
            threat_score,
            threat_state
        FROM response_events
        WHERE threat_score IS NOT NULL
        ORDER BY id
    """

    df = pd.read_sql_query(
        query,
        connection
    )

    if df.empty:

        print(
            "No response-event scores available."
        )

        save_dataframe(
            df,
            "fused_threat_score_timeline.csv"
        )

        return

    df["threat_score"] = pd.to_numeric(
        df["threat_score"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["threat_score"]
    )

    if df.empty:

        print(
            "No valid response-event scores available."
        )

        save_dataframe(
            df,
            "fused_threat_score_timeline.csv"
        )

        return

    plt.figure(
        figsize=(12, 5)
    )

    plt.plot(
        range(len(df)),
        df["threat_score"]
    )

    plt.axhline(
        60,
        linestyle="--",
        label="HIGH_RISK threshold"
    )

    plt.axhline(
        80,
        linestyle="--",
        label="CRITICAL threshold"
    )

    plt.title(
        "Fused Threat Score Over Response Events"
    )

    plt.xlabel(
        "Response Event"
    )

    plt.ylabel(
        "Fused Threat Score"
    )

    plt.legend()

    plt.tight_layout()

    path = os.path.join(
        OUTPUT_DIR,
        "fused_threat_score_timeline.png"
    )

    plt.savefig(
        path,
        dpi=200
    )

    plt.close()

    print(f"Created: {path}")

    save_dataframe(
        df,
        "fused_threat_score_timeline.csv"
    )


def generate_summary_table(connection):

    flow_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM flow_records
        """
    ).fetchone()[0]

    packets = connection.execute(
        """
        SELECT
            COALESCE(
                SUM(packet_count),
                0
            )
        FROM flow_records
        """
    ).fetchone()[0]

    bytes_total = connection.execute(
        """
        SELECT
            COALESCE(
                SUM(total_bytes),
                0
            )
        FROM flow_records
        """
    ).fetchone()[0]

    ml_anomalies = connection.execute(
        """
        SELECT COUNT(*)
        FROM flow_records
        WHERE ml_anomaly = 1
        """
    ).fetchone()[0]

    persistent = connection.execute(
        """
        SELECT COUNT(*)
        FROM flow_records
        WHERE temporal_persistent = 1
        """
    ).fetchone()[0]

    response_events = connection.execute(
        """
        SELECT COUNT(*)
        FROM response_events
        """
    ).fetchone()[0]

    effective = connection.execute(
        """
        SELECT COUNT(*)
        FROM response_events
        WHERE effectiveness = 'EFFECTIVE'
        """
    ).fetchone()[0]

    ineffective = connection.execute(
        """
        SELECT COUNT(*)
        FROM response_events
        WHERE effectiveness = 'INEFFECTIVE'
        """
    ).fetchone()[0]

    improvement = connection.execute(
        """
        SELECT improvement_ratio
        FROM response_events
        WHERE improvement_ratio IS NOT NULL
        """
    ).fetchall()

    improvement_values = []

    for row in improvement:

        value = row[0]

        if value is None:
            continue

        try:
            value = float(value)
        except (ValueError, TypeError):
            continue

        improvement_values.append(
            value * 100
        )

    response_effectiveness = 0

    if effective + ineffective > 0:

        response_effectiveness = (
            effective /
            (effective + ineffective)
        ) * 100

    ml_anomaly_rate = 0

    if flow_count > 0:

        ml_anomaly_rate = (
            ml_anomalies /
            flow_count
        ) * 100

    average_improvement = 0
    best_improvement = 0
    worst_improvement = 0

    if improvement_values:

        average_improvement = (
            sum(improvement_values) /
            len(improvement_values)
        )

        best_improvement = max(
            improvement_values
        )

        worst_improvement = min(
            improvement_values
        )

    summary = {
        "Metric": [
            "Flow Records",
            "Total Packets",
            "Total Bytes",
            "ML Anomalies",
            "ML Anomaly Rate (%)",
            "Persistent Records",
            "Response Events",
            "Effective Responses",
            "Ineffective Responses",
            "Response Effectiveness (%)",
            "Average Improvement (%)",
            "Best Improvement (%)",
            "Worst Improvement (%)"
        ],

        "Value": [
            flow_count,
            packets,
            bytes_total,
            ml_anomalies,
            round(
                ml_anomaly_rate,
                2
            ),
            persistent,
            response_events,
            effective,
            ineffective,
            round(
                response_effectiveness,
                2
            ),
            round(
                average_improvement,
                2
            ),
            round(
                best_improvement,
                2
            ),
            round(
                worst_improvement,
                2
            )
        ]
    }

    df = pd.DataFrame(
        summary
    )

    save_dataframe(
        df,
        "system_evaluation_summary.csv"
    )


def main():

    print("=" * 72)

    print(
        "              AEGISNET RESULTS GENERATOR"
    )

    print("=" * 72)

    if not os.path.exists(
        DATABASE_PATH
    ):

        print(
            f"ERROR: Database not found:\n{DATABASE_PATH}"
        )

        return

    connection = get_connection()

    try:

        generate_ml_anomaly_graph(
            connection
        )

        generate_threat_score_graph(
            connection
        )

        generate_temporal_graph(
            connection
        )

        generate_response_state_graph(
            connection
        )

        generate_response_action_graph(
            connection
        )

        generate_feedback_graph(
            connection
        )

        generate_fused_score_graph(
            connection
        )

        generate_summary_table(
            connection
        )

    finally:

        connection.close()

    print(
        "\n" + "=" * 72
    )

    print(
        "All evaluation results generated successfully."
    )

    print(
        f"Output directory: {OUTPUT_DIR}"
    )

    print(
        "=" * 72
    )


if __name__ == "__main__":
    main()
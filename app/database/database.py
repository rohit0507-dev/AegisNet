import sqlite3
from pathlib import Path
from datetime import datetime
import os


BASE_DIR = Path(__file__).resolve().parents[2]

DATABASE_DIR = BASE_DIR / "data"

DATABASE_FILE = Path(os.environ.get("AEGISNET_DB", str(DATABASE_DIR / "aegisnet.db"))).resolve()


class Database:

    def __init__(self, path=None):

        self.path = Path(path or DATABASE_FILE)

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection = sqlite3.connect(
            self.path,
            timeout=30,
            check_same_thread=False
        )

        # Allow the dashboard to read while packet capture writes.
        # WAL prevents normal read/write contention from causing
        # "database is locked" errors.
        self.connection.execute(
            "PRAGMA journal_mode=WAL"
        )

        self.connection.execute(
            "PRAGMA synchronous=NORMAL"
        )

        self.connection.execute(
            "PRAGMA busy_timeout=30000"
        )

        self.create_tables()

        self.add_missing_columns()

    # =========================================================
    # TABLE CREATION
    # =========================================================

    def create_tables(self):

        cursor = self.connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flow_records (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                source_ip TEXT,
                destination_ip TEXT,

                source_port INTEGER,
                destination_port INTEGER,

                protocol TEXT,

                packet_count INTEGER,
                total_bytes INTEGER,

                duration REAL,

                packets_per_second REAL,
                bytes_per_second REAL,

                average_packet_size REAL,

                syn_count INTEGER,
                ack_count INTEGER,
                fin_count INTEGER,
                rst_count INTEGER,

                syn_ratio REAL,
                ack_ratio REAL,
                fin_ratio REAL,
                rst_ratio REAL,

                window_id INTEGER,

                threat_score REAL,
                threat_severity TEXT,

                alert_count INTEGER,
                alert_types TEXT,

                ml_anomaly INTEGER,
                ml_anomaly_score REAL,

                temporal_state TEXT,
                temporal_streak INTEGER,
                temporal_persistence_ratio REAL,
                temporal_confidence TEXT,
                temporal_persistent INTEGER,
                very_strong_persistent INTEGER,

                response_state TEXT,
                response_action TEXT,
                response_mode TEXT,

                response_effectiveness TEXT,
                response_recommendation TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS response_events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                source_ip TEXT,

                threat_score REAL,

                threat_state TEXT,

                previous_state TEXT,

                action TEXT,

                mode TEXT,

                effectiveness TEXT,

                recommendation TEXT,

                previous_score REAL,

                current_score REAL,

                improvement_ratio REAL,

                event_type TEXT
            )
        """)

        self.connection.commit()

    # =========================================================
    # MIGRATION SUPPORT
    # =========================================================

    def add_missing_columns(self):

        cursor = self.connection.cursor()

        cursor.execute(
            "PRAGMA table_info(flow_records)"
        )

        existing_columns = {
            row[1]
            for row in cursor.fetchall()
        }

        new_columns = {
            "application_protocol": "TEXT",
            "ip_version": "INTEGER",
            "ml_available": "INTEGER",

            "syn_ratio": "REAL",
            "ack_ratio": "REAL",
            "fin_ratio": "REAL",
            "rst_ratio": "REAL",

            "window_id": "INTEGER",

            "threat_score": "REAL",
            "threat_severity": "TEXT",

            "ml_anomaly": "INTEGER",
            "ml_anomaly_score": "REAL",

            "temporal_state": "TEXT",
            "temporal_streak": "INTEGER",
            "temporal_persistence_ratio": "REAL",
            "temporal_confidence": "TEXT",
            "temporal_persistent": "INTEGER",
            "very_strong_persistent": "INTEGER",

            "response_state": "TEXT",
            "response_action": "TEXT",
            "response_mode": "TEXT",

            "response_effectiveness": "TEXT",
            "response_recommendation": "TEXT"
        }

        for column, data_type in new_columns.items():

            if column not in existing_columns:

                cursor.execute(
                    f"""
                    ALTER TABLE flow_records
                    ADD COLUMN {column} {data_type}
                    """
                )

        self.connection.commit()

    # =========================================================
    # FLOW INSERTION
    # =========================================================

    def insert_flow(
        self,
        features,
        threat,
        alerts,
        window_id=None,
        ml_result=None,
        response_result=None,
        temporal_result=None
    ):

        if ml_result is None:

            ml_result = {
                "is_anomaly": False,
                "anomaly_score": 0.0
            }

        if response_result is None:

            response_result = {
                "state": {
                    "current_state": "NORMAL",
                    "previous_state": "NORMAL"
                },

                "decision": {
                    "action": "MONITOR",
                    "mode": "SIMULATION"
                },

                "monitor": None
            }

        if temporal_result is None:

            temporal_result = {
                "current_state": "NORMAL",
                "consecutive_anomalies": 0,
                "persistence_ratio": 0.0,
                "temporal_confidence": "NONE",
                "persistent": False,
                "very_strong_persistent": False
            }

        # -----------------------------------------------------
        # RESPONSE STATE
        # -----------------------------------------------------

        state = response_result.get(
            "state",
            {}
        )

        if isinstance(state, str):

            current_state = state

        else:

            current_state = state.get(
                "current_state",
                state.get(
                    "state",
                    "NORMAL"
                )
            )

        # -----------------------------------------------------
        # RESPONSE DECISION
        # -----------------------------------------------------

        decision = response_result.get(
            "decision",
            {}
        )

        if not isinstance(
            decision,
            dict
        ):

            decision = {}

        response_action = decision.get(
            "action",
            response_result.get(
                "action"
            )
        )

        response_mode = decision.get(
            "mode",
            response_result.get(
                "mode",
                "SIMULATION"
            )
        )

        # -----------------------------------------------------
        # RESPONSE MONITOR
        # -----------------------------------------------------

        monitor = response_result.get(
            "monitor"
        )

        effectiveness = None
        recommendation = None

        if isinstance(
            monitor,
            dict
        ):

            effectiveness = monitor.get(
                "effectiveness"
            )

            recommendation = monitor.get(
                "recommendation"
            )

        # -----------------------------------------------------
        # ALERT TYPES
        # -----------------------------------------------------

        if alerts is None:

            alerts = []

        alert_types = ",".join(
            str(alert.get("type", "UNKNOWN"))
            for alert in alerts
            if isinstance(alert, dict)
        )

        # -----------------------------------------------------
        # ML VALUES
        # -----------------------------------------------------

        is_anomaly = bool(
            ml_result.get(
                "is_anomaly",
                ml_result.get(
                    "anomaly",
                    False
                )
            )
        )

        anomaly_score = float(
            ml_result.get(
                "anomaly_score",
                0.0
            )
        )

        # -----------------------------------------------------
        # TEMPORAL VALUES
        # -----------------------------------------------------

        temporal_state = temporal_result.get(
            "current_state",
            "NORMAL"
        )

        temporal_streak = int(
            temporal_result.get(
                "consecutive_anomalies",
                0
            )
        )

        temporal_persistence_ratio = float(
            temporal_result.get(
                "persistence_ratio",
                0.0
            )
        )

        temporal_confidence = temporal_result.get(
            "temporal_confidence",
            "NONE"
        )

        temporal_persistent = bool(
            temporal_result.get(
                "persistent",
                False
            )
        )

        very_strong_persistent = bool(
            temporal_result.get(
                "very_strong_persistent",
                False
            )
        )

        # -----------------------------------------------------
        # THREAT VALUES
        # -----------------------------------------------------

        if not isinstance(
            threat,
            dict
        ):

            threat = {}

        threat_score = float(
            threat.get(
                "score",
                0.0
            )
        )

        threat_severity = threat.get(
            "severity",
            "LOW"
        )

        # -----------------------------------------------------
        # DATA
        # -----------------------------------------------------

        data = {

            "timestamp":
                datetime.now().isoformat(),

            "source_ip":
                features.get(
                    "source_ip"
                ),

            "destination_ip":
                features.get(
                    "destination_ip"
                ),

            "source_port":
                features.get(
                    "source_port"
                ),

            "destination_port":
                features.get(
                    "destination_port"
                ),

            "protocol":
                features.get(
                    "protocol"
                ),

            "packet_count":
                features.get(
                    "packet_count",
                    0
                ),

            "total_bytes":
                features.get(
                    "total_bytes",
                    0
                ),

            "duration":
                features.get(
                    "duration",
                    0.0
                ),

            "packets_per_second":
                features.get(
                    "packets_per_second",
                    0.0
                ),

            "bytes_per_second":
                features.get(
                    "bytes_per_second",
                    0.0
                ),

            "average_packet_size":
                features.get(
                    "average_packet_size",
                    0.0
                ),

            "syn_count":
                features.get(
                    "syn_count",
                    0
                ),

            "ack_count":
                features.get(
                    "ack_count",
                    0
                ),

            "fin_count":
                features.get(
                    "fin_count",
                    0
                ),

            "rst_count":
                features.get(
                    "rst_count",
                    0
                ),

            "syn_ratio":
                features.get(
                    "syn_ratio",
                    0.0
                ),

            "ack_ratio":
                features.get(
                    "ack_ratio",
                    0.0
                ),

            "fin_ratio":
                features.get(
                    "fin_ratio",
                    0.0
                ),

            "rst_ratio":
                features.get(
                    "rst_ratio",
                    0.0
                ),

            "window_id":
                window_id,

            "threat_score":
                threat_score,

            "threat_severity":
                threat_severity,

            "alert_count":
                len(alerts),

            "alert_types":
                alert_types,

            "ml_anomaly":
                int(is_anomaly),

            "ml_anomaly_score":
                anomaly_score,

            "temporal_state":
                temporal_state,

            "temporal_streak":
                temporal_streak,

            "temporal_persistence_ratio":
                temporal_persistence_ratio,

            "temporal_confidence":
                temporal_confidence,

            "temporal_persistent":
                int(temporal_persistent),

            "very_strong_persistent":
                int(very_strong_persistent),

            "response_state":
                current_state,

            "response_action":
                response_action,

            "response_mode":
                response_mode,

            "response_effectiveness":
                effectiveness,

            "response_recommendation":
                recommendation
        }

        cursor = self.connection.cursor()

        data.update({
            "application_protocol": features.get("application_protocol"),
            "ip_version": features.get("ip_version"),
            "ml_available": features.get("ml_available"),
        })
        # Column names are fixed above, never supplied by a browser or packet.
        columns = ", ".join(data)
        placeholders = ", ".join(":" + key for key in data)
        cursor.execute(f"INSERT INTO flow_records ({columns}) VALUES ({placeholders})", data)

        self.connection.commit()

    # =========================================================
    # RESPONSE EVENT INSERTION
    # =========================================================

    def insert_response_event(
        self,
        source_ip,
        threat_score,
        state,
        action,
        mode,
        previous_state=None,
        effectiveness=None,
        recommendation=None,
        previous_score=None,
        current_score=None,
        improvement_ratio=None,
        event_type="RESPONSE"
    ):

        cursor = self.connection.cursor()

        cursor.execute("""
            INSERT INTO response_events (

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

                improvement_ratio,

                event_type
            )

            VALUES (

                :timestamp,

                :source_ip,

                :threat_score,

                :threat_state,

                :previous_state,

                :action,

                :mode,

                :effectiveness,

                :recommendation,

                :previous_score,

                :current_score,

                :improvement_ratio,

                :event_type
            )
        """, {

            "timestamp":
                datetime.now().isoformat(),

            "source_ip":
                source_ip,

            "threat_score":
                float(threat_score),

            "threat_state":
                state,

            "previous_state":
                previous_state,

            "action":
                action,

            "mode":
                mode,

            "effectiveness":
                effectiveness,

            "recommendation":
                recommendation,

            "previous_score":
                previous_score,

            "current_score":
                current_score,

            "improvement_ratio":
                improvement_ratio,

            "event_type":
                event_type
        })

        self.connection.commit()

    # =========================================================
    # COUNTS
    # =========================================================

    def get_record_count(self):

        cursor = self.connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM flow_records"
        )

        return cursor.fetchone()[0]

    def get_response_event_count(self):

        cursor = self.connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM response_events"
        )

        return cursor.fetchone()[0]

    # =========================================================
    # CLOSE
    # =========================================================

    def close(self):

        self.connection.close()


if __name__ == "__main__":

    print("=" * 70)

    print(
        "             AEGISNET DATABASE"
    )

    print("=" * 70)

    database = Database()

    print(
        f"Database location : "
        f"{DATABASE_FILE}"
    )

    print(
        "Database connected successfully."
    )

    print(
        f"Flow records      : "
        f"{database.get_record_count()}"
    )

    print(
        f"Response events   : "
        f"{database.get_response_event_count()}"
    )

    database.close()
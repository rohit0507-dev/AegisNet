import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATABASE_FILE = BASE_DIR / "data" / "aegisnet.db"


connection = sqlite3.connect(DATABASE_FILE)
connection.row_factory = sqlite3.Row

cursor = connection.cursor()


cursor.execute("""
    SELECT *
    FROM flow_records
    ORDER BY id DESC
    LIMIT 10
""")

records = cursor.fetchall()


print("=" * 120)
print("                         AEGISNET DATABASE RECORDS")
print("=" * 120)


for record in records:

    print()

    print(f"ID                : {record['id']}")
    print(f"Timestamp         : {record['timestamp']}")
    print(f"Source IP         : {record['source_ip']}")
    print(f"Destination IP    : {record['destination_ip']}")
    print(f"Protocol          : {record['protocol']}")

    print(f"Packets           : {record['packet_count']}")
    print(f"Total Bytes       : {record['total_bytes']}")

    print(
        f"Packets/sec       : "
        f"{record['packets_per_second']:.2f}"
    )

    print(
        f"Bytes/sec         : "
        f"{record['bytes_per_second']:.2f}"
    )

    print(f"SYN Count         : {record['syn_count']}")
    print(f"ACK Count         : {record['ack_count']}")
    print(f"RST Count         : {record['rst_count']}")

    print(f"Threat Score      : {record['threat_score']}")
    print(f"Threat Severity   : {record['threat_severity']}")

    print(f"Alert Count       : {record['alert_count']}")
    print(f"Alert Types       : {record['alert_types']}")

    print(
        f"ML Anomaly        : "
        f"{record['ml_anomaly']}"
    )

    print(
        f"ML Score          : "
        f"{record['ml_anomaly_score']:.6f}"
    )

    print(
        f"Response State    : "
        f"{record['response_state']}"
    )

    print(
        f"Response Action   : "
        f"{record['response_action']}"
    )

    print(
        f"Response Mode     : "
        f"{record['response_mode']}"
    )

    print(
        f"Effectiveness     : "
        f"{record['response_effectiveness']}"
    )

    print(
        f"Recommendation    : "
        f"{record['response_recommendation']}"
    )

    print("-" * 120)


connection.close()


print()
print("=" * 120)
print(
    f"Records displayed : {len(records)}"
)
print("=" * 120)
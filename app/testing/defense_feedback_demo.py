import os
import sqlite3
import time

from app.response.response_controller import ResponseController


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


SOURCE_IP = "192.0.2.100"


def get_database():

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.execute(
        "PRAGMA busy_timeout = 10000"
    )

    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    return connection


def save_response_event(
    result,
    threat_score
):

    state = result.get(
        "current_state",
        result.get(
            "state",
            "NORMAL"
        )
    )

    if isinstance(state, dict):

        state = state.get(
            "current_state",
            state.get(
                "state",
                "NORMAL"
            )
        )

    action = result.get(
        "action",
        "MONITOR"
    )

    mode = result.get(
        "mode",
        "SIMULATION"
    )

    previous_state = result.get(
        "previous_state"
    )

    effectiveness = result.get(
        "effectiveness"
    )

    recommendation = result.get(
        "recommendation"
    )

    previous_score = result.get(
        "previous_score"
    )

    current_score = result.get(
        "current_score",
        threat_score
    )

    improvement_ratio = result.get(
        "improvement_ratio"
    )

    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    connection = get_database()

    try:

        connection.execute(
            """
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                SOURCE_IP,
                threat_score,
                state,
                previous_state,
                action,
                mode,
                effectiveness,
                recommendation,
                previous_score,
                current_score,
                improvement_ratio,
                "SIMULATION"
            )
        )

        connection.commit()

    finally:

        connection.close()


def print_result(
    step,
    threat_score,
    result
):

    print()
    print("=" * 70)

    print(
        f"STEP {step}"
    )

    print("=" * 70)

    print(
        f"Threat Score       : {threat_score}"
    )

    print(
        f"Previous State     : "
        f"{result.get('previous_state')}"
    )

    print(
        f"Current State      : "
        f"{result.get('current_state')}"
    )

    print(
        f"Action             : "
        f"{result.get('action')}"
    )

    print(
        f"Mode               : "
        f"{result.get('mode')}"
    )

    print(
        f"Previous Score     : "
        f"{result.get('previous_score')}"
    )

    print(
        f"Current Score      : "
        f"{result.get('current_score')}"
    )

    print(
        f"Effectiveness      : "
        f"{result.get('effectiveness')}"
    )

    print(
        f"Recommendation     : "
        f"{result.get('recommendation')}"
    )

    improvement = result.get(
        "improvement_ratio"
    )

    if improvement is not None:

        print(
            f"Improvement        : "
            f"{improvement * 100:.2f}%"
        )

    else:

        print(
            "Improvement        : None"
        )


def run_simulation():

    print()
    print("=" * 70)
    print(
        "        AEGISNET DEFENSE FEEDBACK SIMULATION"
    )
    print("=" * 70)

    print(
        f"Simulation Source  : {SOURCE_IP}"
    )

    print(
        "Defense Mode       : SIMULATION"
    )

    print(
        "Real network block : DISABLED"
    )

    print("=" * 70)

    controller = ResponseController(
        simulation_mode=True
    )

    # --------------------------------------------------------
    # STEP 1
    # NORMAL
    # --------------------------------------------------------

    score = 20

    result = controller.process(
        source_ip=SOURCE_IP,
        threat_score=score,
        ml_result={
            "is_anomaly": False,
            "anomaly_score": 0.10,
            "ml_confidence": 0.10
        },
        alerts=[]
    )

    print_result(
        1,
        score,
        result
    )

    save_response_event(
        result,
        score
    )

    time.sleep(1)


    # --------------------------------------------------------
    # STEP 2
    # SUSPICIOUS
    # --------------------------------------------------------

    score = 45

    result = controller.process(
        source_ip=SOURCE_IP,
        threat_score=score,
        ml_result={
            "is_anomaly": True,
            "anomaly_score": 0.45,
            "ml_confidence": 0.45
        },
        alerts=[
            {
                "type": "ANOMALY",
                "severity": "LOW"
            }
        ]
    )

    print_result(
        2,
        score,
        result
    )

    save_response_event(
        result,
        score
    )

    time.sleep(1)


    # --------------------------------------------------------
    # STEP 3
    # HIGH RISK
    # TEMPORARY LIMIT
    # --------------------------------------------------------

    score = 65

    result = controller.process(
        source_ip=SOURCE_IP,
        threat_score=score,
        ml_result={
            "is_anomaly": True,
            "anomaly_score": 0.65,
            "ml_confidence": 0.80
        },
        alerts=[
            {
                "type": "HIGH_PACKET_RATE",
                "severity": "HIGH"
            }
        ]
    )

    print_result(
        3,
        score,
        result
    )

    save_response_event(
        result,
        score
    )

    time.sleep(1)


    # --------------------------------------------------------
    # STEP 4
    # CRITICAL
    # TEMPORARY BLOCK / ESCALATION
    # --------------------------------------------------------

    score = 85

    result = controller.process(
        source_ip=SOURCE_IP,
        threat_score=score,
        ml_result={
            "is_anomaly": True,
            "anomaly_score": 0.85,
            "ml_confidence": 0.95
        },
        alerts=[
            {
                "type": "SYN_FLOOD",
                "severity": "CRITICAL"
            }
        ]
    )

    print_result(
        4,
        score,
        result
    )

    save_response_event(
        result,
        score
    )

    time.sleep(1)


    # --------------------------------------------------------
    # STEP 5
    # THREAT DECREASES
    # EFFECTIVE RESPONSE
    # RESTORE
    # --------------------------------------------------------

    score = 50

    result = controller.process(
        source_ip=SOURCE_IP,
        threat_score=score,
        ml_result={
            "is_anomaly": True,
            "anomaly_score": 0.50,
            "ml_confidence": 0.40
        },
        alerts=[]
    )

    print_result(
        5,
        score,
        result
    )

    save_response_event(
        result,
        score
    )

    time.sleep(1)


    # --------------------------------------------------------
    # STEP 6
    # THREAT RETURNS TO NORMAL
    # --------------------------------------------------------

    score = 25

    result = controller.process(
        source_ip=SOURCE_IP,
        threat_score=score,
        ml_result={
            "is_anomaly": False,
            "anomaly_score": 0.10,
            "ml_confidence": 0.10
        },
        alerts=[]
    )

    print_result(
        6,
        score,
        result
    )

    save_response_event(
        result,
        score
    )


    print()
    print("=" * 70)

    print(
        "DEFENSE FEEDBACK SIMULATION COMPLETED"
    )

    print("=" * 70)

    print()
    print(
        "Open the AegisNet dashboard and inspect:"
    )

    print(
        "  • Current Defense State"
    )

    print(
        "  • Fused Threat Timeline"
    )

    print(
        "  • Defense Feedback & Response History"
    )

    print()
    print(
        "Simulation source:"
    )

    print(
        f"  {SOURCE_IP}"
    )

    print()
    print(
        "No real network blocking was performed."
    )

    print("=" * 70)


if __name__ == "__main__":

    run_simulation()
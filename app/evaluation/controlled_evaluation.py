import os
import json
from datetime import datetime, timedelta

from app.analysis.flow_engine import Flow
from app.detection.rule_engine import RuleEngine
from app.detection.port_scan_detector import PortScanDetector
from app.detection.temporal_detector import TemporalDetector
from app.scoring.threat_fusion import ThreatFusionEngine


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "data",
    "evaluation"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


def set_flow_values(
    flow,
    packet_count,
    total_bytes,
    syn_count=0,
    ack_count=0,
    fin_count=0,
    rst_count=0,
    unique_destination_ports=0,
    duration_seconds=1.0
):
    flow.packet_count = packet_count
    flow.total_bytes = total_bytes

    flow.syn_count = syn_count
    flow.ack_count = ack_count
    flow.fin_count = fin_count
    flow.rst_count = rst_count

    flow.unique_destination_ports = (
        unique_destination_ports
    )

    now = datetime.now()

    flow.start_time = (
        now - timedelta(
            seconds=duration_seconds
        )
    )

    flow.last_time = now

    return flow


def make_normal_flow():

    flow = Flow(
        "192.0.2.10",
        "198.51.100.10",
        50000,
        443,
        "TCP"
    )

    return set_flow_values(
        flow,
        packet_count=40,
        total_bytes=24000,
        syn_count=1,
        ack_count=20,
        fin_count=1,
        rst_count=0,
        unique_destination_ports=1,
        duration_seconds=10.0
    )


def make_syn_flood_flow():

    flow = Flow(
        "192.0.2.20",
        "198.51.100.20",
        40000,
        80,
        "TCP"
    )

    return set_flow_values(
        flow,
        packet_count=150,
        total_bytes=90000,
        syn_count=150,
        ack_count=10,
        fin_count=0,
        rst_count=0,
        unique_destination_ports=1,
        duration_seconds=1.0
    )


def make_high_packet_rate_flow():

    flow = Flow(
        "192.0.2.30",
        "198.51.100.30",
        41000,
        443,
        "TCP"
    )

    return set_flow_values(
        flow,
        packet_count=1200,
        total_bytes=600000,
        syn_count=1,
        ack_count=1000,
        fin_count=1,
        rst_count=0,
        unique_destination_ports=1,
        duration_seconds=0.5
    )


def make_high_bandwidth_flow():

    flow = Flow(
        "192.0.2.40",
        "198.51.100.40",
        42000,
        443,
        "TCP"
    )

    return set_flow_values(
        flow,
        packet_count=1000,
        total_bytes=12000000,
        syn_count=1,
        ack_count=900,
        fin_count=1,
        rst_count=0,
        unique_destination_ports=1,
        duration_seconds=1.0
    )


def make_high_rst_flow():

    flow = Flow(
        "192.0.2.50",
        "198.51.100.50",
        43000,
        443,
        "TCP"
    )

    return set_flow_values(
        flow,
        packet_count=40,
        total_bytes=20000,
        syn_count=1,
        ack_count=5,
        fin_count=0,
        rst_count=30,
        unique_destination_ports=1,
        duration_seconds=10.0
    )


def make_port_scan_flows():

    flows = []

    for port in range(20, 45):

        flow = Flow(
            "192.0.2.60",
            "198.51.100.60",
            44000 + port,
            port,
            "TCP"
        )

        flow = set_flow_values(
            flow,
            packet_count=3,
            total_bytes=180,
            syn_count=2,
            ack_count=0,
            fin_count=0,
            rst_count=1,
            unique_destination_ports=1,
            duration_seconds=1.0
        )

        features = flow.get_features()

        flows.append(
            features
        )

    return flows


def flow_to_features(flow):

    features = flow.get_features()

    features["unique_destination_ports"] = (
        getattr(
            flow,
            "unique_destination_ports",
            0
        )
    )

    return features


def calculate_rule_detection():

    engine = RuleEngine()

    scenarios = [
        (
            "NORMAL",
            make_normal_flow(),
            False
        ),
        (
            "SYN_FLOOD",
            make_syn_flood_flow(),
            True
        ),
        (
            "HIGH_PACKET_RATE",
            make_high_packet_rate_flow(),
            True
        ),
        (
            "HIGH_BANDWIDTH",
            make_high_bandwidth_flow(),
            True
        ),
        (
            "HIGH_RST_RATE",
            make_high_rst_flow(),
            True
        )
    ]

    results = []

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for name, flow, expected_threat in scenarios:

        alerts = engine.detect(
            flow
        )

        detected = len(
            alerts
        ) > 0

        if expected_threat and detected:

            tp += 1

        elif not expected_threat and not detected:

            tn += 1

        elif not expected_threat and detected:

            fp += 1

        elif expected_threat and not detected:

            fn += 1

        results.append({
            "scenario": name,
            "expected_threat": expected_threat,
            "detected": detected,
            "alerts": [
                alert["type"]
                for alert in alerts
            ],
            "packets_per_second": round(
                flow.packets_per_second(),
                2
            ),
            "bytes_per_second": round(
                flow.bytes_per_second(),
                2
            ),
            "rst_rate": round(
                flow.rst_ratio(),
                3
            )
        })

    return (
        results,
        tp,
        tn,
        fp,
        fn
    )


def calculate_port_scan_detection():

    detector = PortScanDetector()

    normal_flow = make_normal_flow()

    normal_features = [
        flow_to_features(
            normal_flow
        )
    ]

    port_scan_features = (
        make_port_scan_flows()
    )

    normal_result = detector.detect(
        normal_features
    )

    scan_result = detector.detect(
        port_scan_features
    )

    return {
        "normal_detected": bool(
            normal_result
        ),
        "port_scan_detected": bool(
            scan_result
        ),
        "port_scan_details": scan_result
    }


def calculate_temporal_detection():

    detector = TemporalDetector()

    source_ip = "192.0.2.70"

    scores = [
        0.90,
        0.92,
        0.88,
        0.91,
        0.87
    ]

    history = []

    for score in scores:

        result = detector.update(
            source_ip,
            score
        )

        history.append(
            result
        )

    final = history[-1]

    return {
        "source_ip": source_ip,
        "scores": scores,
        "consecutive_anomalies": final[
            "consecutive_anomalies"
        ],
        "persistent": final[
            "persistent"
        ],
        "very_strong_persistent": final[
            "very_strong_persistent"
        ],
        "temporal_confidence": final[
            "temporal_confidence"
        ],
        "final_state": final[
            "current_state"
        ],
        "persistence_ratio": final[
            "persistence_ratio"
        ]
    }


def calculate_fusion_tests():

    fusion = ThreatFusionEngine()

    tests = [
        {
            "name": "NORMAL",
            "rule_alerts": [],
            "ml_anomaly": False,
            "ml_confidence": 0.0,
            "anomaly_strength": "NORMAL",
            "baseline_score": 0.05,
            "port_scan_detected": False
        },
        {
            "name": "ML_ANOMALY",
            "rule_alerts": [],
            "ml_anomaly": True,
            "ml_confidence": 0.90,
            "anomaly_strength": "STRONG",
            "baseline_score": 0.20,
            "port_scan_detected": False
        },
        {
            "name": "RULE_PLUS_ML",
            "rule_alerts": [
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message": "Controlled evaluation"
                }
            ],
            "ml_anomaly": True,
            "ml_confidence": 0.90,
            "anomaly_strength": "STRONG",
            "baseline_score": 0.30,
            "port_scan_detected": False
        },
        {
            "name": "PORT_SCAN",
            "rule_alerts": [],
            "ml_anomaly": False,
            "ml_confidence": 0.0,
            "anomaly_strength": "NORMAL",
            "baseline_score": 0.10,
            "port_scan_detected": True
        }
    ]

    results = []

    for test in tests:

        result = fusion.fuse(
            rule_alerts=test[
                "rule_alerts"
            ],
            ml_anomaly=test[
                "ml_anomaly"
            ],
            ml_confidence=test[
                "ml_confidence"
            ],
            anomaly_strength=test[
                "anomaly_strength"
            ],
            baseline_score=test[
                "baseline_score"
            ],
            temporal_result=None,
            port_scan_detected=test[
                "port_scan_detected"
            ],
            source_context=None,
            existing_threat_score=0.0
        )

        results.append({
            "name": test["name"],
            "fusion_score": result.get(
                "fusion_score",
                result.get(
                    "score",
                    0
                )
            ),
            "severity": result.get(
                "severity"
            ),
            "confidence": result.get(
                "confidence"
            ),
            "malicious_evidence_sources":
                result.get(
                    "malicious_evidence_sources",
                    []
                )
        })

    return results


def calculate_classification_metrics(
    tp,
    tn,
    fp,
    fn
):

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0.0
    )

    f1 = (
        2 * precision * recall /
        (precision + recall)
        if precision + recall
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if fp + tn
        else 0.0
    )

    accuracy = (
        (tp + tn) /
        (tp + tn + fp + fn)
        if tp + tn + fp + fn
        else 0.0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "False Positive Rate": false_positive_rate,
        "Accuracy": accuracy
    }


def save_results(
    rule_results,
    metrics,
    port_scan,
    temporal,
    fusion
):

    output = {
        "rule_detection": rule_results,
        "classification_metrics": metrics,
        "port_scan_detection": port_scan,
        "temporal_detection": temporal,
        "threat_fusion": fusion
    }

    path = os.path.join(
        OUTPUT_DIR,
        "controlled_evaluation.json"
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print(
        f"\nCreated: {path}"
    )


def print_rule_results(results):

    print(
        "\n[1] RULE ENGINE CONTROLLED TEST"
    )

    print(
        "-" * 72
    )

    for result in results:

        status = (
            "PASS"
            if result["expected_threat"]
            == result["detected"]
            else "FAIL"
        )

        print(
            f'{result["scenario"]:<22} '
            f'Expected={str(result["expected_threat"]):<5} '
            f'Detected={str(result["detected"]):<5} '
            f'{status}'
        )

        if result["alerts"]:

            print(
                f'  Alerts: '
                f'{", ".join(result["alerts"])}'
            )

        print(
            f'  PPS={result["packets_per_second"]} '
            f'BPS={result["bytes_per_second"]} '
            f'RST={result["rst_rate"]}'
        )


def print_metrics(metrics):

    print(
        "\n[2] CLASSIFICATION METRICS"
    )

    print(
        "-" * 72
    )

    print(
        f'True Positives          : '
        f'{metrics["TP"]}'
    )

    print(
        f'True Negatives          : '
        f'{metrics["TN"]}'
    )

    print(
        f'False Positives         : '
        f'{metrics["FP"]}'
    )

    print(
        f'False Negatives         : '
        f'{metrics["FN"]}'
    )

    print(
        f'Precision               : '
        f'{metrics["Precision"] * 100:.2f}%'
    )

    print(
        f'Recall                  : '
        f'{metrics["Recall"] * 100:.2f}%'
    )

    print(
        f'F1 Score                : '
        f'{metrics["F1"] * 100:.2f}%'
    )

    print(
        f'False Positive Rate     : '
        f'{metrics["False Positive Rate"] * 100:.2f}%'
    )

    print(
        f'Accuracy                : '
        f'{metrics["Accuracy"] * 100:.2f}%'
    )


def print_port_scan_results(result):

    print(
        "\n[3] PORT-SCAN DETECTION TEST"
    )

    print(
        "-" * 72
    )

    print(
        f'Normal traffic detected : '
        f'{result["normal_detected"]}'
    )

    print(
        f'Port scan detected      : '
        f'{result["port_scan_detected"]}'
    )


def print_temporal_results(result):

    print(
        "\n[4] TEMPORAL PERSISTENCE TEST"
    )

    print(
        "-" * 72
    )

    print(
        f'Source                  : '
        f'{result["source_ip"]}'
    )

    print(
        f'Scores                  : '
        f'{result["scores"]}'
    )

    print(
        f'Consecutive anomalies   : '
        f'{result["consecutive_anomalies"]}'
    )

    print(
        f'Persistent              : '
        f'{result["persistent"]}'
    )

    print(
        f'Very-strong persistent  : '
        f'{result["very_strong_persistent"]}'
    )

    print(
        f'Temporal confidence     : '
        f'{result["temporal_confidence"]}'
    )

    print(
        f'Final state             : '
        f'{result["final_state"]}'
    )

    print(
        f'Persistence ratio       : '
        f'{result["persistence_ratio"]:.2f}'
    )


def print_fusion_results(results):

    print(
        "\n[5] THREAT FUSION TEST"
    )

    print(
        "-" * 72
    )

    for result in results:

        evidence = result[
            "malicious_evidence_sources"
        ]

        print(
            f'{result["name"]:<22} '
            f'Score={result["fusion_score"]:.2f} '
            f'Severity={result["severity"]:<9} '
            f'Confidence={result["confidence"]}'
        )

        if evidence:

            print(
                f'  Evidence: '
                f'{", ".join(evidence)}'
            )


def main():

    print("=" * 72)

    print(
        "          AEGISNET CONTROLLED EVALUATION"
    )

    print("=" * 72)

    print(
        "\nAll test traffic is synthetic."
    )

    print(
        "No packets are sent to external systems."
    )

    print(
        "Documentation IP ranges are used."
    )

    (
        rule_results,
        tp,
        tn,
        fp,
        fn
    ) = calculate_rule_detection()

    metrics = calculate_classification_metrics(
        tp,
        tn,
        fp,
        fn
    )

    port_scan = (
        calculate_port_scan_detection()
    )

    temporal = (
        calculate_temporal_detection()
    )

    fusion = (
        calculate_fusion_tests()
    )

    print_rule_results(
        rule_results
    )

    print_metrics(
        metrics
    )

    print_port_scan_results(
        port_scan
    )

    print_temporal_results(
        temporal
    )

    print_fusion_results(
        fusion
    )

    save_results(
        rule_results,
        metrics,
        port_scan,
        temporal,
        fusion
    )

    print(
        "\n" + "=" * 72
    )

    print(
        "Controlled evaluation completed."
    )

    print(
        "=" * 72
    )


if __name__ == "__main__":
    main()
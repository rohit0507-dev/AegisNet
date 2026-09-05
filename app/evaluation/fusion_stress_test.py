from app.scoring.threat_fusion import ThreatFusionEngine


def run_test(engine, name, **kwargs):

    result = engine.fuse(
        **kwargs
    )

    print(
        f"{name:<30} "
        f"Score={result['fusion_score']:>6.2f} "
        f"Severity={result['severity']:<9} "
        f"Confidence={result['confidence']:<10} "
        f"Evidence={result['evidence_count']}"
    )

    if result["malicious_evidence_sources"]:

        print(
            " " * 32 +
            "Evidence: " +
            ", ".join(
                result[
                    "malicious_evidence_sources"
                ]
            )
        )

    return result


def main():

    print("=" * 100)

    print(
        "                 AEGISNET THREAT FUSION STRESS TEST"
    )

    print("=" * 100)

    print()

    engine = ThreatFusionEngine()

    common = {
        "baseline_score": 0.0,
        "temporal_result": None,
        "source_context": None,
        "existing_threat_score": 0.0
    }

    results = []

    results.append(
        run_test(
            engine,
            "NORMAL",
            rule_alerts=[],
            ml_anomaly=False,
            ml_confidence=0.0,
            anomaly_strength="NORMAL",
            port_scan_detected=False,
            **common
        )
    )

    results.append(
        run_test(
            engine,
            "ML ONLY",
            rule_alerts=[],
            ml_anomaly=True,
            ml_confidence=0.95,
            anomaly_strength="VERY_STRONG",
            port_scan_detected=False,
            **common
        )
    )

    results.append(
        run_test(
            engine,
            "PORT SCAN ONLY",
            rule_alerts=[],
            ml_anomaly=False,
            ml_confidence=0.0,
            anomaly_strength="NORMAL",
            port_scan_detected=True,
            **common
        )
    )

    results.append(
        run_test(
            engine,
            "SYN FLOOD ONLY",
            rule_alerts=[
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message": "Controlled SYN flood"
                }
            ],
            ml_anomaly=False,
            ml_confidence=0.0,
            anomaly_strength="NORMAL",
            port_scan_detected=False,
            **common
        )
    )

    results.append(
        run_test(
            engine,
            "ML + PORT SCAN",
            rule_alerts=[],
            ml_anomaly=True,
            ml_confidence=0.95,
            anomaly_strength="VERY_STRONG",
            port_scan_detected=True,
            **common
        )
    )

    results.append(
        run_test(
            engine,
            "RULE + ML",
            rule_alerts=[
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message": "Controlled SYN flood"
                }
            ],
            ml_anomaly=True,
            ml_confidence=0.95,
            anomaly_strength="VERY_STRONG",
            port_scan_detected=False,
            **common
        )
    )

    temporal_3 = {
        "consecutive_anomalies": 3,
        "persistent": True,
        "very_strong_persistent": False
    }

    results.append(
        run_test(
            engine,
            "RULE + TEMPORAL",
            rule_alerts=[
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message": "Controlled SYN flood"
                }
            ],
            ml_anomaly=False,
            ml_confidence=0.0,
            anomaly_strength="NORMAL",
            port_scan_detected=False,
            temporal_result=temporal_3,
            **{
                "baseline_score": 0.0,
                "source_context": None,
                "existing_threat_score": 0.0
            }
        )
    )

    results.append(
        run_test(
            engine,
            "PORT SCAN + TEMPORAL",
            rule_alerts=[],
            ml_anomaly=False,
            ml_confidence=0.0,
            anomaly_strength="NORMAL",
            port_scan_detected=True,
            temporal_result=temporal_3,
            **{
                "baseline_score": 0.0,
                "source_context": None,
                "existing_threat_score": 0.0
            }
        )
    )

    results.append(
        run_test(
            engine,
            "RULE + ML + TEMPORAL",
            rule_alerts=[
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message": "Controlled SYN flood"
                }
            ],
            ml_anomaly=True,
            ml_confidence=0.95,
            anomaly_strength="VERY_STRONG",
            port_scan_detected=False,
            temporal_result=temporal_3,
            **{
                "baseline_score": 0.0,
                "source_context": None,
                "existing_threat_score": 0.0
            }
        )
    )

    results.append(
        run_test(
            engine,
            "ALL FOUR EVIDENCE SOURCES",
            rule_alerts=[
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "message": "Controlled SYN flood"
                }
            ],
            ml_anomaly=True,
            ml_confidence=0.95,
            anomaly_strength="VERY_STRONG",
            port_scan_detected=True,
            temporal_result={
                "consecutive_anomalies": 5,
                "persistent": True,
                "very_strong_persistent": True
            },
            **{
                "baseline_score": 0.0,
                "source_context": None,
                "existing_threat_score": 0.0
            }
        )
    )

    print()

    print("=" * 100)

    print(
        "Fusion stress test completed."
    )

    print("=" * 100)


if __name__ == "__main__":
    main()
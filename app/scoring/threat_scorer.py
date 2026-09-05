class ThreatScorer:

    def calculate(
        self,
        flow,
        alerts,
        ml_result=None
    ):

        score = 0

        reasons = []

        if alerts is None:

            alerts = []

        # =====================================================
        # NETWORK BEHAVIOR
        # =====================================================

        if flow.syn_count >= 100:

            score += 35

            reasons.append(
                "High SYN activity"
            )

        if flow.packet_count > 1000:

            score += 20

            reasons.append(
                "High packet volume"
            )

        if flow.packets_per_second() > 500:

            score += 15

            reasons.append(
                "High packet rate"
            )

        if flow.bytes_per_second() > 5_000_000:

            score += 10

            reasons.append(
                "High bandwidth usage"
            )

        if flow.packet_count >= 20:

            rst_rate = (
                flow.rst_count
                /
                flow.packet_count
            )

            if rst_rate > 0.5:

                score += 15

                reasons.append(
                    "High TCP RST rate"
                )

        # =====================================================
        # RULE ALERTS
        # =====================================================

        for alert in alerts:

            if not isinstance(
                alert,
                dict
            ):

                continue

            severity = alert.get(
                "severity",
                "LOW"
            )

            if severity == "HIGH":

                score += 25

            elif severity == "MEDIUM":

                score += 10

            elif severity == "LOW":

                score += 5

            alert_type = alert.get(
                "type"
            )

            if alert_type:

                reasons.append(
                    str(alert_type)
                )

        # =====================================================
        # ML EVIDENCE
        # =====================================================

        ml_anomaly = False

        ml_confidence = 0.0

        anomaly_strength = "NORMAL"

        anomaly_score = 0.0

        if isinstance(
            ml_result,
            dict
        ):

            ml_anomaly = bool(
                ml_result.get(
                    "is_anomaly",
                    ml_result.get(
                        "anomaly",
                        False
                    )
                )
            )

            # -------------------------------------------------
            # Support both the new and old field names.
            # -------------------------------------------------

            ml_confidence = float(
                ml_result.get(
                    "confidence",
                    ml_result.get(
                        "ml_confidence",
                        0.0
                    )
                )
            )

            anomaly_score = float(
                ml_result.get(
                    "anomaly_score",
                    0.0
                )
            )

            anomaly_strength = ml_result.get(
                "anomaly_strength",
                "NORMAL"
            )

            # -------------------------------------------------
            # Clamp confidence to a valid range.
            # -------------------------------------------------

            ml_confidence = max(
                0.0,
                min(
                    ml_confidence,
                    1.0
                )
            )

            # -------------------------------------------------
            # ML contribution
            # -------------------------------------------------

            if ml_anomaly:

                if anomaly_strength == "VERY_STRONG":

                    ml_points = max(
                        1,
                        round(
                            20
                            *
                            ml_confidence
                        )
                    )

                    score += ml_points

                    reasons.append(
                        "Very strong ML anomaly"
                    )

                elif anomaly_strength == "STRONG":

                    ml_points = max(
                        1,
                        round(
                            15
                            *
                            ml_confidence
                        )
                    )

                    score += ml_points

                    reasons.append(
                        "Strong ML anomaly"
                    )

                elif anomaly_strength == "MODERATE":

                    ml_points = max(
                        1,
                        round(
                            8
                            *
                            ml_confidence
                        )
                    )

                    score += ml_points

                    reasons.append(
                        "Moderate ML anomaly"
                    )

                elif anomaly_strength == "WEAK":

                    ml_points = max(
                        1,
                        round(
                            3
                            *
                            ml_confidence
                        )
                    )

                    score += ml_points

                    reasons.append(
                        "Weak ML anomaly"
                    )

                else:

                    # -------------------------------------------------
                    # Defensive fallback:
                    # If Isolation Forest says anomalous but the
                    # strength label is missing/unknown, the anomaly
                    # must still contribute to the score.
                    # -------------------------------------------------

                    ml_points = max(
                        1,
                        round(
                            10
                            *
                            ml_confidence
                        )
                    )

                    score += ml_points

                    reasons.append(
                        "ML anomaly detected"
                    )

        # =====================================================
        # FINAL SCORE
        # =====================================================

        score = min(
            round(score),
            100
        )

        # =====================================================
        # SEVERITY
        # =====================================================

        if score >= 80:

            severity = "CRITICAL"

        elif score >= 60:

            severity = "HIGH"

        elif score >= 30:

            severity = "MEDIUM"

        else:

            severity = "LOW"

        # =====================================================
        # RESULT
        # =====================================================

        return {

            "score":
                score,

            "severity":
                severity,

            "reasons":
                reasons,

            "ml_anomaly":
                ml_anomaly,

            "ml_confidence":
                ml_confidence,

            "confidence":
                ml_confidence,

            "anomaly_score":
                anomaly_score,

            "anomaly_strength":
                anomaly_strength
        }


if __name__ == "__main__":

    scorer = ThreatScorer()

    print("=" * 70)

    print(
        "       AEGISNET THREAT SCORER"
    )

    print("=" * 70)

    print(
        "Rule + ML threat scoring engine initialized successfully."
    )

    print("=" * 70)